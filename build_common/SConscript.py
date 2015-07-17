#******************************************************************
#
# Copyright 2015 Intel Mobile Communications GmbH All Rights Reserved.
#
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

import os
import platform
import itertools
from sets import Set
from script_helpers import *

# The list of environment variables to import into the SCons environment
import_environment_variables = ['TARGET_OS', 'PATH']

# Get any command-line options
target_os = ARGUMENTS.get('TARGET_OS', platform_host()).lower()
target_arch = ARGUMENTS.get('TARGET_ARCH', platform_arch()).lower()

# Map of host os to supported target os
host_target_map = {
    'linux':    Set(['linux',   'android']),
    'windows':  Set(['windows', 'winrt',  'android']),
    'darwin':   Set(['darwin',  'ios',    'android']),
    }

# Map of target os to supported architectures
os_arch_map = {
        'darwin':   Set(['i386', 'x86_64']),
        'windows':  Set(['x86',  'amd64',  'arm']),
        'winrt':    Set(['x86',  'amd64',  'arm']),
		'linux':    Set(['x86',  'x86_64', 'arm',     'arm64']),
        'ios':      Set(['i386', 'x86_64', 'armv7',   'armv7s',      'arm64']),
		'android':  Set(['x86',  'x86_64', 'armeabi', 'armeabi-v7a', 'armeabi-v7a-hard', 'arm64-v8a']),
		}

# Configure command-line variables
help_vars = Variables()
help_vars.Add(BoolVariable('VERBOSE', 'Show compilation details?', 'no'))
help_vars.Add(BoolVariable('RELEASE', 'Build for release?', 'true')) # set to 'no', 'false' or 0 for debug
help_vars.Add(EnumVariable('TARGET_OS', 'Target platform', platform_host(), host_target_map[platform_host()]))

help_vars.Add(BoolVariable('STROPHE', 'Use libstrophe in place of C++ stream processor', 'no'))
help_vars.Add(BoolVariable('DOWNLOAD_OPENSSL', 'Force download and build of the openSSL library', 'no'))
help_vars.Add(BoolVariable('FUNCTIONAL_TESTS', 'Build the functional test within the unit test modules', 'no'))




# Check that the host build environment is supported
if not host_target_map.has_key(platform_host()):
	print_error("Builds under %s are not currently supported\n" % platform_host())
	Exit(1)


# Verify that default (or passed-in) target_os is supported
target_host_set = host_target_map[platform_host()]
if target_os not in target_host_set:
    print_error("Unsupported target os: %s (Allowed values: %s)" % (target_os, pretty_print(target_host_set)))
    Exit(1)


#for key, value in env.items():
#    print key, '=', value


def _import_environment(vars):
    return dict(map(lambda k: (k, os.getenv(k, "")), vars))


env = Environment(ENV = _import_environment(import_environment_variables))



env.EnsureSConsVersion(2,1)
env.EnsurePythonVersion(2,7)

env.Tool('URLDownload', toolpath=['tools/'])
env.Tool('UnpackAll',   toolpath=['tools/'])
env.Tool('Configure',   toolpath=['tools/'])
env.Tool('Make',        toolpath=['tools/'])

env['HOST'] = platform_host()

print "HOST:", platform_host()
print "PLATFORM:", env['PLATFORM']
print "TARGET_ARCH:", platform_arch()

# Get required meta-build tools that are not always present on the host.
#if platform_host() == 'windows':
#    if not env.WhereIs('7z'):
#        print_warning('7-Zip is required to unpack externally downloaded libraries. Attempting to get 7-zip.')
#
#        if '64' in platform_arch():
#            sevenzip_exe = env.URLDownload('7z920-x64.msi', 'http://www.7-zip.org/a/7z920-x64.msi')
#        else:
#            sevenzip_exe = env.URLDownload('7z920.exe', 'http://www.7-zip.org/a/7z920.exe')
#

# Configure help for command-line options
help_vars.Update(env)



# Add additional helper functions [imported from Iotivity]

# Install header file(s) to <src_dir>/deps/<target_os>/include
def __install_header_file(ienv, file):
    return ienv.Install(os.path.join(env.get('SRC_DIR'), 'deps', target_os, 'include'), file)

# Install library binaries to <src_dir>/deps/<target_os>/lib/<arch>
def __install_library(ienv, lib):
    return ienv.Install(os.path.join(env.get('SRC_DIR'), 'deps', target_os, 'lib', target_arch), lib)

def __append_target(ienv, target):
    env.AppendUnique(TS = [target])

# Set the source directory and build directory
#   Source directory: 'dir'
#   Build directory: 'dir'/out/<target_os>/<target_arch>/<release or debug>/
#
# You can get the directory as following:
#   env.get('SRC_DIR')
#   env.get('BUILD_DIR')

def __set_dir(env, dir):
    if not os.path.exists(dir + '/SConstruct'):
        print '''
*************************************** Error *********************************
* It seems the directory "%s" isn't a source code directory.
* No SConstruct file was found.
*******************************************************************************
''' % dir
        Exit(1)

    build_dir = dir + '/out/' + target_os + '/' + target_arch + ('/release/' if env.get('RELEASE') else '/debug/')
    env.VariantDir(build_dir, dir, duplicate=0)

    if env['VERBOSE']:
        print "BUILD_DIR", build_dir
    env.Replace(BUILD_DIR = build_dir)
    env.Replace(SRC_DIR = dir)



env.AddMethod(__set_dir, 'SetDir')

env.AddMethod(__install_header_file, 'InstallHeaderFile')
env.AddMethod(__install_library, 'InstallLibrary')
env.AddMethod(__append_target, 'AppendTarget')

env.SetDir(env.GetLaunchDir())
env['ROOT_DIR'] = env.GetLaunchDir()+'/..'



Help(help_vars.GenerateHelpText(env))

if not env['VERBOSE']:
    env['CCCOMSTR'] = "Compiling $TARGET"
    env['SHCCCOMSTR'] = "Compiling $TARGET"
    env['ARCOMSTR'] = "Archiving $TARGET"
    env['RANLIBCOMSTR'] = "Ranlib $TARGET"
    env['CXXCOMSTR'] = "Compiling $TARGET"
    env['SHCXXCOMSTR'] = "Compiling $TARGET"
    env['LINKCOMSTR'] = "Linking $TARGET"
    env['SHLINKCOMSTR'] = "Linking $TARGET"

# Export the default environment (without build targets)
Export('env')




conf = Configure(env)

# Check compiler confguration
#if not env.GetOption('clean'):
#    pass


if not conf.CheckCC():
    print_error("C Compiler Configuration Incorrect/Incomplete")
    Exit(0)

if not conf.CheckCXX():
    print_error("C++ Compiler Configuration Incorrect/Incomplete")
    Exit(0)

# Check for openssl
has_ssl = conf.CheckLib('ssl')
has_crypto = conf.CheckLib('crypto')

# OPENSSL is deprecated on 10.7 and later so we use a downloaded version
if target_os in ['darwin']:
    has_ssl = False
    has_crypto = False

conf.env['HAS_OPENSSL'] = has_ssl and has_crypto

# Check for curl [BOSH support]
conf.env['HAS_CURL'] = conf.CheckLib('curl')

## Check for safec
conf.env['HAS_SAFEC'] = 'yes' if conf.CheckLib('safec') else 'no'


def versionSufficient(sourceVer, requiredVer):
    verOkay = True
    for p in itertools.izip_longest(sourceVer.split('.'), requiredVer.split('.'), fillvalue = 0):
        if p[0]<p[1]:
            verOkay = False
            break
        if p[0]>p[1]:
            break
    return verOkay


if 'linux' in env['HOST']:
    # Check g++ version (GCC C-version shouldn't matter as much, but can be checked too
    # here if needed)
    REQUIRED_VER = "4.6"
    # Check gcc version
    if  not versionSufficient(env['CXXVERSION'], REQUIRED_VER):
        print "g++ version is insufficient to compile the client. Required:", REQUIRED_VER, " Found:", env['CXXVERSION']
        Exit(2)

    print "CCVERVSION", env['CCVERSION']
    print "CXXVERVSION", env['CXXVERSION']


env = conf.Finish()


#get packages from brew, etc.
if target_os in ['darwin']:
   env.AppendUnique(
         LIBPATH = [
            '/usr/local/lib'
            ])


