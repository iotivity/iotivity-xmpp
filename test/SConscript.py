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

##
# Program configuration for the ccfxmpp_tests unit test module.
#
##

Import('env')


######################################################################
# Source files and Targets
######################################################################
ccfxmpp_tests_src = [
    Glob('*.cpp'),
    ]



ccfxmpp_tests_env = env.Clone()

target_os = ccfxmpp_tests_env.get('TARGET_OS')


#def __static_lib_full_name(name):
#    return env['LIBPREFIX']+name+env['LIBSUFFIX']

if target_os not in ['windows', 'winrt']:
    # Force the use of the static library so that we don't need to export everything tested
    # from the shared library.
    ccfxmpplib = File(env['BUILD_DIR']+'libccfxmpp.a')

    # We use append rather than appendunique to force certain dynamic libraries to appear
    # after the static libraries. This does result in duplication on the command line.
    ccfxmpp_tests_env.Append(
        LIBS = [ccfxmpplib, 'gmock', 'gtest', 'curl', 'ssl', 'pthread', 'crypto'],
        )
    ccfxmpp_tests_env.AppendUnique(
        LIBPATH = [
            '#src'          # TODO: Improve reference to library and out-directory
            ],
        CPPPATH = [
            '#src/platform/linux/',
            '#src'
            ],
        CXXFLAGS = [
            '-std=c++0x',
            '-Doverride=',
            '-fdata-sections',
            '-ffunction-sections',
            '-flto',
            '-fno-rtti',
            '-DCCF_XMPP_EXPORTS',
            '-DASIO_STANDALONE',
            '-DASIO_NO_TYPEID',
            '-DGTEST_HAS_EXCEPTIONS=1',
            '-Wall',
            '-Werror',
            '-Wno-unknown-pragmas',             # Ignore any windows-specific pragmas (don't warn)
            ])
    if env['STROPHE']==1:
        ccfxmpp_tests_env.AppendUnique(
            CXXFLAGS = [
                '-DENABLE_LIBSTROPHE',
            ],
            LIBS = ['libstrophe'])
    if env['FUNCTIONAL_TESTS']==1:
        ccfxmpp_tests_env.AppendUnique(
            CXXFLAGS = [
                '-DENABLE_FUNCTIONAL_TESTING',
            ])
    if target_os not in ['darwin']:
        ccfxmpp_tests_env.AppendUnique(
            LINKFLAGS = [
            '-Wl,--gc-sections',
            '-Wl,--strip-all',
            ])

    if not env['RELEASE']:
        ccfxmpp_tests_env.AppendUnique(CXXFlags = [
            '-DLOGSTREAM_ENABLE_ALL_LOGGING',
            ])


ccfxmpp_tests = ccfxmpp_tests_env.Program('ccfxmpp_tests', ccfxmpp_tests_src)
ccfxmpp_tests_env.Install(env.get('BUILD_DIR'), ccfxmpp_tests)

# Runner to help with LD_LIBRARY_PATH for running ccfxmpp_tests without installing libraries.
ccfxmpp_tests_env.Install(env.get('BUILD_DIR'), env['SRC_DIR']+'/build_common/run_ccfxmpp_tests.sh')


