#!/usr/bin/env python
#
# Generate a large number of valid configurations, build them concurrently,
# and report.

import argparse
import itertools
import multiprocessing
import os
import re
import shutil
import subprocess
import sys
import tempfile

def print_fn(*args):
    map(sys.stdout.write, args + tuple('\n'))
    return None

def quote_if_needed(value):
    if not isinstance(value, int) and value != 'y' and value != 'n':
        value = '"' + value + '"'

    return value

def gen_configs_list(options_dict):
    names = options_dict.keys()
    product = itertools.product(*options_dict.itervalues())
    return map(lambda x: dict(zip(names, x)), product)

def gen_configs_values_str(options_dict):
    return map(lambda x: ' '.join(x.values()), gen_configs_list(options_dict))

def gen_cc_options_list(options_dict):
    return map(lambda x: x + ' -Werror', gen_configs_values_str(options_dict))

# Check whether a filter prototype is valid.
#
# A filter prototype is a list of (name, value) pairs used to build a filter.
# Keep in mind that a valid filter must match invalid configurations. As a
# result, a filter prototype is valid if and only if
#  - all options are included in the given list, and
#  - the number of enabled options is not 1
def check_exclusive_boolean_filter(prototype):
    return (len(set(map(lambda x: x[0], prototype))) == len(prototype)
            and len(filter(lambda x: x[1][1] == 'y', prototype)) != 1)

# Generate a list of filters on a list of boolean options.
#
# The resulting filters match configurations that don't have one and only
# one of the given options enabled.
def gen_exclusive_boolean_filters_list(options_list):
    product = itertools.product(options_list, [[True, 'y'], [True, 'n']])
    prototypes = list(itertools.combinations(product, len(options_list)))
    return map(dict, filter(check_exclusive_boolean_filter, prototypes))

# Dictionary of compiler options.
#
# Each entry describes a single compiler option. The key is mostly ignored
# and serves as description, but must be present in order to reuse the
# gen_configs_list() function. The value is a list of all values that may
# be used for this compiler option when building a configuration.
all_cc_options_dict = {
    'O'         : ['-O0', '-O2', '-Os'],
    'LTO'       : ['-flto', '-fno-lto'],
    'SSP'       : ['-fno-stack-protector', '-fstack-protector'],
}

# Dictionaries of options.
#
# Each entry describes a single option. The key matches an option name
# whereas the value is a list of all values that may be used for this
# option when building a configuration.

small_options_dict = {
    'CONFIG_CC_EXE'                 : ['gcc', 'clang'],
    'CONFIG_CC_OPTIONS'             : gen_cc_options_list(all_cc_options_dict),
    'CONFIG_ASSERT'                 : ['y', 'n'],
}

large_options_dict = dict(small_options_dict)
large_options_dict.update({
    'CONFIG_64BITS'                 : ['y', 'n'],
    'CONFIG_X86_PAE'                : ['y', 'n'],
    'CONFIG_MULTIPROCESSOR'         : ['y', 'n'],
    'CONFIG_MAX_CPUS'               : ['1', '128'],
    'CONFIG_MUTEX_ADAPTIVE'         : ['y', 'n'],
    'CONFIG_MUTEX_PI'               : ['y', 'n'],
    'CONFIG_MUTEX_PLAIN'            : ['y', 'n'],
    'CONFIG_SHELL'                  : ['y', 'n'],
    'CONFIG_THREAD_STACK_GUARD'     : ['y', 'n'],
})

# TODO Test modules set of options and filters.

all_options_sets = {
    'small'                         : small_options_dict,
    'large'                         : large_options_dict,
}

# List of filters used to determine valid configurations.
#
# Each entry is a dictionary of options. The key matches an option name
# whereas the value is a [match_flag, string/regular expression] list.
# The match flag is true if the matching expression must match, false
# otherwise.
all_filters_list = [
    # XXX Clang currently cannot build the kernel with LTO.
    {
        'CONFIG_CC_EXE'             :   [True, 'clang'],
        'CONFIG_CC_OPTIONS'         :   [True, re.compile('-flto')],
    },
    {
        'CONFIG_MULTIPROCESSOR'     :   [True, 'n'],
        'CONFIG_MAX_CPUS'           :   [False, re.compile('^0*1$')],
    },
    {
        'CONFIG_64BITS'             :   [True, 'y'],
        'CONFIG_X86_PAE'            :   [True, 'y'],
    },
]
all_filters_list += gen_exclusive_boolean_filters_list([
    'CONFIG_MUTEX_ADAPTIVE',
    'CONFIG_MUTEX_PI',
    'CONFIG_MUTEX_PLAIN'
])

def gen_config_line(name, value):
    return name + '=' + quote_if_needed(value)

def gen_config_content(config_dict):
    lines = []

    for name, value in config_dict.iteritems():
        lines.append(gen_config_line(name, value) + '\n')

    return lines

def test_config_run(command, check, buildlog):
    buildlog.writelines(['$ ' + command + '\n'])
    buildlog.flush()

    if check:
        return subprocess.check_call(command.split(), stdout = buildlog,
                                     stderr = subprocess.STDOUT)
    else:
        return subprocess.call(command.split(), stdout = buildlog,
                               stderr = subprocess.STDOUT)

def test_config(topbuilddir, config_dict):
    srctree = os.path.abspath(os.getcwd())
    buildtree = tempfile.mkdtemp(dir = topbuilddir)
    os.chdir(buildtree)
    buildlog = open('build.log', 'w')
    f = open('.testconfig', 'w')
    f.writelines(gen_config_content(config_dict))
    f.close()

    try:
        test_config_run(srctree + '/tools/kconfig/merge_config.sh -f '
                        + srctree + '/Makefile .testconfig', True, buildlog)
        test_config_run('make -f ' + srctree + '/Makefile olddefconfig',
                        True, buildlog)
        retval = test_config_run('make -f ' + srctree + '/Makefile x15',
                                 False, buildlog)
    except KeyboardInterrupt:
        buildlog.close()
        return
    except:
        retval = 1

    buildlog.close()
    os.chdir(srctree)

    if retval == 0:
        shutil.rmtree(buildtree)

    return [retval, buildtree]

def test_config_star(args):
    return test_config(*args)

def check_filter(config_dict, filter_dict):
    for name, value in filter_dict.iteritems():
        if not name in config_dict:
            return True

        if isinstance(value[1], str):
            if value[0] != (config_dict[name] == value[1]):
                return True
        else:
            if value[0] != bool(value[1].match(config_dict[name])):
                return True

    return False

def check_filters(config_dict, filters_list):
    for filter_dict in filters_list:
        if (not check_filter(config_dict, filter_dict)):
            return False

    return True

def gen_all_configs(options_dict, filters_list):
    configs_list = []

    for config_dict in gen_configs_list(options_dict):
        if (check_filters(config_dict, filters_list)):
            configs_list.append(config_dict)

    return configs_list

def find_options_dict(options_sets, name):
    if name not in options_sets:
        return None

    return options_sets[name]

def print_set(name, options_dict):
    print name
    map(lambda x: print_fn('  ' + x), sorted(iter(options_dict)))

class BuildConfigListSetsAction(argparse.Action):
    def __init__(self, nargs=0, **kwargs):
        if nargs != 0:
            raise ValueError("nargs not allowed")

        super(BuildConfigListSetsAction, self).__init__(nargs=nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        map(print_set, all_options_sets.iterkeys(),
            all_options_sets.itervalues())
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='Configuration builder')
    parser.add_argument('-s', '--set', default='small',
                        help='select a set of options to combine')
    parser.add_argument('-l', '--list-sets', action=BuildConfigListSetsAction,
                        help='print the list of options sets')
    args = parser.parse_args()

    options_dict = find_options_dict(all_options_sets, args.set)

    if not options_dict:
        print 'error: invalid set'
        sys.exit(2);

    print 'set: ' + args.set
    configs_list = gen_all_configs(options_dict, all_filters_list)
    nr_configs = len(configs_list)
    print 'total: ' + str(nr_configs)

    # This tool performs out-of-tree builds and requires a clean source tree
    print 'cleaning source tree...'
    subprocess.check_call(['make', 'distclean'])
    topbuilddir = os.path.abspath(tempfile.mkdtemp(prefix = 'build', dir = '.'))
    print 'top build directory: ' + topbuilddir

    pool = multiprocessing.Pool()
    worker_args = map(lambda config_dict: (topbuilddir, config_dict),
                      configs_list)

    try:
        results = pool.map(test_config_star, worker_args)
    except KeyboardInterrupt:
        pool.terminate()
        pool.join()
        shutil.rmtree(topbuilddir)
        raise

    failures = filter(lambda x: x[0] != 0, results)
    map(lambda buildtree: print_fn('failed: ' + buildtree + '/.config ('
                                   + buildtree + '/build.log)'),
        [buildtree for retval, buildtree in failures])
    print 'passed: ' + str(nr_configs - len(failures))
    print 'failed: ' + str(len(failures))

    try:
        os.rmdir(topbuilddir)
    finally:
        sys.exit(len(failures) != 0)

if __name__ == '__main__':
    main()
