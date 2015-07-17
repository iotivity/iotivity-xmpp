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
# Program configuration for the ccfxmpp library.
#
##

Import('env')


SConscript([
            'test/SConscript.py',
            'c_init_test/SConscript.py'
            ])


######################################################################
# Source files and Targets
######################################################################
ra_xmpp_src = [
    Glob('*.c'),
    Glob('*.cpp')
    ]


ra_xmpp_env = env.Clone()

target_os = env.get('TARGET_OS')

if target_os not in ['windows', 'winrt']:
    if env['STROPHE']==1:
        ra_xmpp_env.AppendUnique(
            CXXFLAGS = [
                '-DENABLE_LIBSTROPHE',
            ],
            LIBS = ['strophe'])
    ra_xmpp_env.Append(
        LIBS = ['ccfxmpp','pthread'],
        LIBPATH = ['#src']
        )

    ra_xmpp_env.AppendUnique(
        CPPPATH = [
            '#src'],
        CXXFLAGS = [
            '-pthread',
            #'-std=c++11',
            '-std=c++0x',
            '-fdata-sections',
            '-ffunction-sections',
            '-flto',
            '-DASIO_STANDALONE',
            '-DXMPP_EXPORTS',
            '-Doverride=',
            '-Os',
            '-Wall',
            '-Werror',
            '-Wno-unknown-pragmas',             # Ignore any windows-specific pragmas (don't warn)
            '-fPIC',
            ])

    if target_os not in ['darwin','ios']:
        ra_xmpp_env.AppendUnique(
            LINKFLAGS = [
                     '-Wl,--no-undefined'
                     ],
            CXXFLAGS = [
                '-Wl,--gc-sections',
                '-Wl,--strip-all',
                ])
    else:
        ra_xmpp_env.AppendUnique(
            LINKFLAGS = [
                     '-Wl,-undefined,error'
                     ])

    if not env['RELEASE']:
        ra_xmpp_env.AppendUnique(CXXFLAGS = [
            '-g'
            ])


ra_xmpp_sh = ra_xmpp_env.SharedLibrary('ra_xmpp', ra_xmpp_src)
ra_xmpp_st = ra_xmpp_env.StaticLibrary('ra_xmpp', ra_xmpp_src)
ra_xmpp_env.Install(env.get('BUILD_DIR'), ra_xmpp_st)

if target_os not in ['darwin','ios']:
    ra_xmpp_sh = ra_xmpp_env.SharedLibrary('ra_xmpp', ra_xmpp_src)
    ra_xmpp_env.Install(env.get('BUILD_DIR'), ra_xmpp_sh)



