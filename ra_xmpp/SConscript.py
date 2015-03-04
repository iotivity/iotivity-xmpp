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
        LIBS = ['ccfxmpp'],
        LIBPATH = ['#src']
        )

    ra_xmpp_env.AppendUnique(
        CPPPATH = [            
            '#src'],
        CXXFLAGS = [
            '-pthread',
            '-std=c++11',
            '-fdata-sections',
            '-ffunction-sections',
            '-flto',
            '-Os',
            '-Wl,--gc-sections',
            '-Wl,--strip-all',
            '-Wall', 
            '-Werror',
            '-Wno-unknown-pragmas',             # Ignore any windows-specific pragmas (don't warn)
            '-fPIC',
            ])
    if not env['RELEASE']:
        ra_xmpp_env.AppendUnique(CXXFLAGS = [
            '-g'
            ])


ra_xmpp_sh = ra_xmpp_env.SharedLibrary('ra_xmpp', ra_xmpp_src)
ra_xmpp_st = ra_xmpp_env.StaticLibrary('ra_xmpp', ra_xmpp_src)

#env.Requires(File('ra_xmpp.c'), env['BUILD_DIR']+'libsafec-1.0.so.1')

ra_xmpp_env.Install(env.get('BUILD_DIR'), ra_xmpp_sh)
ra_xmpp_env.Install(env.get('BUILD_DIR'), ra_xmpp_st)

# The safec dependency is not being picked up automatically; force the issue

