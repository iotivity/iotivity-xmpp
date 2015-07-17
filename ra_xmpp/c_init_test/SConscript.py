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
# Program configuration for the ra_xmpp_test program.
#
##

Import('env')


######################################################################
# Source files and Targets
######################################################################
ra_xmpp_test_src = [
    Glob('*.c'),
    ]


ra_xmpp_test_env = env.Clone()

target_os = env.get('TARGET_OS')

if target_os not in ['windows', 'winrt']:
    if env['STROPHE']==1:
        ra_xmpp_test_env.AppendUnique(
            CXXFLAGS = [
                '-DENABLE_LIBSTROPHE',
            ],
            LIBS = ['strophe'])
    ra_xmpp_test_env.Append(
        LIBS = ['ra_xmpp', 'ccfxmpp', 'curl']
        )
    ra_xmpp_test_env.AppendUnique(
        LIBPATH = [
            '#ra_xmpp',
            '#src'
            ],
        CPPPATH = [
            '#ra_xmpp'],
        CFLAGS = [
            '-pthread',
            '-Wall',
            '-Werror',
            '-Wno-unknown-pragmas',             # Ignore any windows-specific pragmas (don't warn)
            ])
    if target_os not in ['darwin','ios']:
        ra_xmpp_test_env.AppendUnique(
                LINKFLAGS = [
            '-Wl,--no-as-needed'
            ])
    else:
        ra_xmpp_test_env.AppendUnique(
            LIBS =['c++'],
            LINKFLAGS = [
            '-stdlib=libc++'
            ])

    if not env['RELEASE']:
        ra_xmpp_test_env.AppendUnique(CFLAGS = [
            '-g'
            ])


init_test = ra_xmpp_test_env.Program('c_init_test', ra_xmpp_test_src)

ra_xmpp_test_env.Install(env.get('BUILD_DIR'), init_test)

