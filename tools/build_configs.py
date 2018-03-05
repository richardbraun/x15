#!/usr/bin/env python3
'''
Configuration builder.

Generate a large number of valid configurations, build them concurrently,
and report.
'''

import argparse
import itertools
import multiprocessing
import os
import re
import shutil
import subprocess
import sys
import tempfile

def quote_if_needed(value):
    if not value.isdigit() and value != 'y' and value != 'n':
        value = '"%s"' % value

    return value

def gen_configs_list(options_dict):
    'Generate a list of all possible combinations of options.'
    names = options_dict.keys()
    product = itertools.product(*options_dict.values())
    return [dict(zip(names, x)) for x in product]

def gen_configs_values_str(options_dict):
    'Generate a list of all possible combinations of options as strings.'
    return [' '.join(x.values()) for x in gen_configs_list(options_dict)]

def gen_cc_options_list(options_dict):
    '''
    Does the same as gen_configs_values_str() but adds the -Werror option
    to all generated strings.
    '''
    return ['{} -Werror'.format(x) for x in gen_configs_values_str(options_dict)]

def gen_exclusive_boolean_filter(args):
    enabled_option, options_list = args
    option_filter = dict()

    for option in options_list:
        if option == enabled_option:
            value = [True, 'y']
        else:
            value = [True, 'n']

        option_filter.update({option: value})

    return option_filter

def gen_exclusive_boolean_filters_list(options_list, all_disabled=False):
    '''
    Generate a list of passing filters on a list of boolean options.

    The resulting filters match configurations that have only one of the given
    options enabled, unless all_disabled is true, in which case an additional
    filter is generated to match configurations where none of the options
    are enabled.
    '''
    option_and_options = [(x, options_list) for x in options_list]

    if all_disabled:
        option_and_options.append((None, options_list))

    return list(map(gen_exclusive_boolean_filter, option_and_options))

# Dictionary of compiler options.
#
# Each entry describes a single compiler option. The key is mostly ignored
# and serves as description, but must be present in order to reuse the
# gen_configs_list() function. The value is a list of all values that may
# be used for this compiler option when building a configuration.
all_cc_options_dict = {
    'O'             : ['-O0', '-O2', '-Os'],
    'LTO'           : ['-flto', '-fno-lto'],
    'SSP'           : ['-fno-stack-protector', '-fstack-protector'],
}

# Dictionaries of options.
#
# Each entry describes a single option. The key matches an option name
# whereas the value is a list of all values that may be used for this
# option when building a configuration.

small_options_dict = {
    'CONFIG_CC_OPTIONS'             : gen_cc_options_list(all_cc_options_dict),
    'CONFIG_SMP'                    : ['y', 'n'],
    'CONFIG_MAX_CPUS'               : ['1', '128'],
    'CONFIG_ASSERT'                 : ['y', 'n'],
}

large_options_dict = dict(small_options_dict)
large_options_dict.update({
    'CONFIG_CC_EXE'                 : ['gcc', 'clang'],
    'CONFIG_64BITS'                 : ['y', 'n'],
    'CONFIG_X86_PAE'                : ['y', 'n'],
    'CONFIG_MUTEX_ADAPTIVE'         : ['y', 'n'],
    'CONFIG_MUTEX_PI'               : ['y', 'n'],
    'CONFIG_MUTEX_PLAIN'            : ['y', 'n'],
    'CONFIG_SHELL'                  : ['y', 'n'],
    'CONFIG_THREAD_STACK_GUARD'     : ['y', 'n'],
})

# TODO Generate this list from test/test_*.c
test_list = [
    'CONFIG_TEST_MODULE_MUTEX',
    'CONFIG_TEST_MODULE_MUTEX_PI',
    'CONFIG_TEST_MODULE_PMAP_UPDATE_MP',
    'CONFIG_TEST_MODULE_RCU_DEFER',
    'CONFIG_TEST_MODULE_SREF_DIRTY_ZEROES',
    'CONFIG_TEST_MODULE_SREF_NOREF',
    'CONFIG_TEST_MODULE_SREF_WEAKREF',
    'CONFIG_TEST_MODULE_VM_PAGE_FILL',
    'CONFIG_TEST_MODULE_XCALL',
]

test_options_dict = dict(small_options_dict)

for test in test_list:
    test_options_dict.update({test: ['y', 'n']})

all_options_sets = {
    'small'     : small_options_dict,
    'large'     : large_options_dict,
    'test'      : test_options_dict,
}

# Filters.
#
# A filter is a list of dictionaries of options. For each dictionary, the
# key matches an option name whereas the value is a
# [match_flag, string/regular expression] list. The match flag is true if
# the matching expression must match, false otherwise.
#
# Passing filters are used to allow configurations that match the filters,
# whereras blocking filters allow configurations that do not match.

passing_filters_list = gen_exclusive_boolean_filters_list([
    'CONFIG_MUTEX_ADAPTIVE',
    'CONFIG_MUTEX_PI',
    'CONFIG_MUTEX_PLAIN',
])
passing_filters_list += gen_exclusive_boolean_filters_list(test_list,
                                                           all_disabled=True)

blocking_filters_list = [
    # XXX Clang currently cannot build the kernel with LTO.
    {
        'CONFIG_CC_EXE'         :   [True, 'clang'],
        'CONFIG_CC_OPTIONS'     :   [True, re.compile('-flto')],
    },
    {
        'CONFIG_SMP'            :   [True, 'y'],
        'CONFIG_MAX_CPUS'       :   [True, '1'],
    },
    {
        'CONFIG_SMP'            :   [True, 'n'],
        'CONFIG_MAX_CPUS'       :   [False, '1'],
    },
    {
        'CONFIG_64BITS'         :   [True, 'y'],
        'CONFIG_X86_PAE'        :   [True, 'y'],
    },
]

def gen_config_line(config_entry):
    name, value = config_entry
    return '%s=%s\n' % (name, quote_if_needed(value))

def gen_config_content(config_dict):
    return map(gen_config_line, config_dict.items())

def test_config_run(command, check, buildlog):
    buildlog.writelines(['$ %s\n' % command])
    buildlog.flush()

    if check:
        return subprocess.check_call(command.split(), stdout=buildlog,
                                     stderr=subprocess.STDOUT)
    else:
        return subprocess.call(command.split(), stdout=buildlog,
                               stderr=subprocess.STDOUT)

def test_config(args):
    'This function is run in multiprocessing.Pool workers.'
    topbuilddir, config_dict = args
    srctree = os.path.abspath(os.getcwd())
    buildtree = tempfile.mkdtemp(dir=topbuilddir)
    os.chdir(buildtree)
    buildlog = open('build.log', 'w')
    config_file = open('.testconfig', 'w')
    config_file.writelines(gen_config_content(config_dict))
    config_file.close()

    try:
        test_config_run('%s/tools/kconfig/merge_config.sh'
                        ' -m -f %s/Makefile .testconfig' % (srctree, srctree),
                        True, buildlog)
        test_config_run('make -f %s/Makefile V=1 olddefconfig' % srctree,
                        True, buildlog)
        retval = test_config_run('make -f %s/Makefile V=1 x15' % srctree,
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

def check_filter(config_dict, filter_dict):
    'Return true if a filter completely matches a configuration.'
    for name, value in filter_dict.items():
        if name not in config_dict:
            return False

        if isinstance(value[1], str):
            if value[0] != (config_dict[name] == value[1]):
                return False
        else:
            if value[0] != bool(value[1].match(config_dict[name])):
                return False

    return True

def check_filter_relevant(config_dict, filter_dict):
    for name in filter_dict.keys():
        if name in config_dict:
            return True

    return False

def check_filters_list_relevant(config_dict, filters_list):
    for filter_dict in filters_list:
        if check_filter_relevant(config_dict, filter_dict):
            return True

    return False

def check_passing_filters(args):
    '''
    If the given filters list is irrelevant, i.e. it applies to none of
    the options in the given configuration, the filters are considered
    to match.

    @return true if a configuration doesn't pass any given filter.
    '''
    config_dict, filters_list = args

    if not check_filters_list_relevant(config_dict, filters_list):
        return True

    for filter_dict in filters_list:
        if check_filter(config_dict, filter_dict):
            return True

    return False

def check_blocking_filters(args):
    'Return true if a configuration passes all the given filters.'
    config_dict, filters_list = args

    for filter_dict in filters_list:
        if check_filter(config_dict, filter_dict):
            return False

    return True

def filter_configs_list(configs_list, passing_filters, blocking_filters):
    configs_and_filters = [(x, passing_filters) for x in configs_list]
    configs_list = [x[0] for x in filter(check_passing_filters,
                                         configs_and_filters)]
    configs_and_filters = [(x, blocking_filters) for x in configs_list]
    configs_list = [x[0] for x in filter(check_blocking_filters,
                                         configs_and_filters)]
    return configs_list

def find_options_dict(options_sets, name):
    if name not in options_sets:
        return None

    return options_sets[name]

class BuildConfigListSetsAction(argparse.Action):
    def __init__(self, nargs=0, **kwargs):
        if nargs != 0:
            raise ValueError("nargs not allowed")

        super(BuildConfigListSetsAction, self).__init__(nargs=nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        for key in sorted(all_options_sets.keys()):
            print(key)

            for option in sorted(all_options_sets[key]):
                print('  ' + option)

        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-s', '--set', default='small',
                        help='select a set of options (default=small)')
    parser.add_argument('-l', '--list-sets', action=BuildConfigListSetsAction,
                        help='print the list of options sets')
    args = parser.parse_args()

    options_dict = find_options_dict(all_options_sets, args.set)

    if not options_dict:
        print('error: invalid set')
        sys.exit(2)

    print('set: {}'.format(args.set))
    configs_list = filter_configs_list(gen_configs_list(options_dict),
                                       passing_filters_list,
                                       blocking_filters_list)
    nr_configs = len(configs_list)
    print('total: {:d}'.format(nr_configs))

    # This tool performs out-of-tree builds and requires a clean source tree
    print('cleaning source tree...')
    subprocess.check_call(['make', 'distclean'])
    topbuilddir = os.path.abspath(tempfile.mkdtemp(prefix='build', dir='.'))
    print('top build directory: {}'.format(topbuilddir))

    pool = multiprocessing.Pool()
    worker_args = [(topbuilddir, x) for x in configs_list]

    try:
        results = pool.map(test_config, worker_args)
    except KeyboardInterrupt:
        pool.terminate()
        pool.join()
        shutil.rmtree(topbuilddir)
        raise

    failures = [x[1] for x in results if x[0] != 0]
    for buildtree in failures:
        print('failed: {0}/.config ({0}/build.log)'.format(buildtree))
    print('passed: {:d}'.format(nr_configs - len(failures)))
    print('failed: {:d}'.format(len(failures)))

    try:
        os.rmdir(topbuilddir)
    finally:
        sys.exit(len(failures) != 0)

if __name__ == '__main__':
    main()
