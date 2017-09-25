#!/usr/bin/env python
#
# Generate a large number of valid configurations, build them concurrently,
# and report.

import itertools
import multiprocessing
import os
import re
import shutil
import subprocess
import tempfile

def quote_if_needed(value):
    if not isinstance(value, int) and value != 'y' and value != 'n':
        value = '"' + value + '"'

    return value

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
        return subprocess.check_call(command.split(), stdout = buildlog, stderr = subprocess.STDOUT)
    else:
        return subprocess.call(command.split(), stdout = buildlog, stderr = subprocess.STDOUT)

def test_config(topbuilddir, config_dict):
    try:
        srctree = os.path.abspath(os.getcwd())
        buildtree = tempfile.mkdtemp(dir = topbuilddir)
        os.chdir(buildtree)
        buildlog = open('build.log', 'w')
        f = open('.testconfig', 'w')
        f.writelines(gen_config_content(config_dict))
        f.close()
        test_config_run(srctree + '/tools/kconfig/merge_config.sh -f ' + srctree + '/Makefile .testconfig', True, buildlog)
        test_config_run('make -f ' + srctree + '/Makefile olddefconfig', True, buildlog)
        result = test_config_run('make -f ' + srctree + '/Makefile x15', False, buildlog)
    except:
        result = -1
    finally:
        buildlog.close()
        os.chdir(srctree)

        if result == 0:
            shutil.rmtree(buildtree)

        return [result, buildtree]

def test_config_star(args):
    return test_config(*args)

def gen_all_configs_recursive(options_dict, config_dict = {}):
    configs_list = []

    if (len(options_dict) == 0):
        return [config_dict]

    options_dict_copy = options_dict.copy()
    name, values = options_dict_copy.popitem()

    for v in values:
        config_dict_copy = config_dict.copy()
        config_dict_copy[name] = v
        configs_list += gen_all_configs_recursive(options_dict_copy, config_dict_copy)

    return configs_list

# TODO Better name.
def check_filter(config_dict, filter_dict):
    for name, value in filter_dict.iteritems():
        if not name in config_dict:
            return True

        if isinstance(value, str):
            if config_dict[name] != value:
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

    for config_dict in gen_all_configs_recursive(options_dict):
        if (check_filters(config_dict, filters_list)):
            configs_list.append(config_dict)

    return configs_list

def gen_all_combinations_str(options_dict):
    return [' '.join([value for value in config_dict.itervalues()])
                     for config_dict in gen_all_configs_recursive(options_dict)]

def gen_boolean_exclusive_filters_list(options_list):
    filters_triplets = []

    # Forge all (name, value) triplet combinations, filter those where a name
    # appears more than once, and then those where there isn't exactly one
    # value 'y'.
    for x in itertools.combinations(itertools.product(options_list, ['y', 'n']), 3):
        if (len(x) == len(set([y[0] for y in x]))
            and len(filter(lambda x: x == 'y', [y[1] for y in x])) != 1):
            filters_triplets.append(x)

    filters_list = []

    for filters_triplet in filters_triplets:
        filters_list.append(dict(filters_triplet))

    return filters_list

# Dictionary of compiler options.
#
# Each entry describes a single compiler option. The key is mostly ignored
# and serves as description, but must be present in order to reuse the
# gen_all_configs_recursive() function. The value is a list of all values
# that may be used for this compiler option when building a configuration.
all_cc_options_dict = {
    'O'         : ['-O0', '-O2', '-Os'],
    'LTO'       : ['-flto', '-fno-lto'],
    'SSP'       : ['-fno-stack-protector', '-fstack-protector'],
}

# Dictionary of options.
#
# Each entry describes a single option. The key matches an option name
# whereas the value is a list of all values that may be used for this
# option when building a configuration.
all_options_dict = {
    'CONFIG_CC_EXE'                 : ['gcc', 'clang'],
    'CONFIG_CC_OPTIONS'             : gen_all_combinations_str(all_cc_options_dict),
    'CONFIG_ASSERT'                 : ['y', 'n'],
    'CONFIG_64BITS'                 : ['y', 'n'],
    'CONFIG_X86_PAE'                : ['y', 'n'],
    'CONFIG_MULTIPROCESSOR'         : ['y', 'n'],
    'CONFIG_MAX_CPUS'               : ['1', '128'],
    'CONFIG_MUTEX_ADAPTIVE'         : ['y', 'n'],
    'CONFIG_MUTEX_PI'               : ['y', 'n'],
    'CONFIG_MUTEX_PLAIN'            : ['y', 'n'],
    'CONFIG_SHELL'                  : ['y', 'n'],
    'CONFIG_THREAD_STACK_GUARD'     : ['y', 'n'],
    # TODO Test modules.
}

# List of filters used to determine valid configurations.
#
# Each entry is a dictionary of options. The key matches an option name
# whereas the value may either be a string for exact matching, or a regular
# expression for more powerful matching.
all_filters_list = [
    # XXX Clang currently cannot build the kernel with LTO.
    {
        'CONFIG_CC_EXE'             :   'clang',
        'CONFIG_CC_OPTIONS'         :   [True, re.compile('-flto')],
    },
    {
        'CONFIG_MULTIPROCESSOR'     :   'n',
        'CONFIG_MAX_CPUS'           :   [False, re.compile('^0*1$')],
    },
    {
        'CONFIG_64BITS'             :   'y',
        'CONFIG_X86_PAE'            :   'y',
    },
]
all_filters_list += gen_boolean_exclusive_filters_list([
    'CONFIG_MUTEX_ADAPTIVE',
    'CONFIG_MUTEX_PI',
    'CONFIG_MUTEX_PLAIN'
])

if __name__ == '__main__':
    # This tool performs out-of-tree builds and requires a clean source tree
    print 'cleaning source tree...'
    subprocess.check_call(['make', 'distclean'])
    topbuilddir = os.path.abspath(tempfile.mkdtemp(prefix = 'build', dir = '.'))
    print 'using ' + topbuilddir

    pool = multiprocessing.Pool()
    configs_list = gen_all_configs(all_options_dict, all_filters_list)
    nr_configs = len(configs_list)
    print 'total: ' + str(nr_configs)
    results = pool.map(test_config_star, [(topbuilddir, config_dict)
                                          for config_dict in configs_list])
    pool.close()
    pool.join()

    for result, buildtree in results:
        if result != 0:
            print 'failed: ' + buildtree + '/.config (' + buildtree + '/build.log)'

    nr_failures = len(filter(None, [result[0] for result in results]))
    nr_successes = nr_configs - nr_failures
    print 'passed: ' + str(nr_successes)
    print 'failed: ' + str(nr_failures)

    try:
        os.rmdir(topbuilddir)
    except:
        pass
