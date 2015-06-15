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


######################################################################
# Source files and Targets
######################################################################
ccfxmpp_src = [
    Glob('common/*.cpp'),
    Glob('connect/*.cpp'),
    Glob('pubsub/*.cpp'),
    Glob('bosh/*.cpp'),
    Glob('xml/*.cpp'),
    Glob('xmpp/*.cpp'),
    ]




ccfxmpp_lib_env = env.Clone()


######################################################################
# Compiler Flags
######################################################################
ccfxmpp_lib_env.AppendUnique(CPPPATH = [
		'include/'
		])


target_os = env.get('TARGET_OS')

ccfxmpp_lib_env.AppendUnique(CPPPATH = ['#external/rapidxml-1.13/'])

if target_os not in ['windows', 'winrt']:
    ccfxmpp_lib_env.AppendUnique(CPPPATH = ['platform/linux/'])
    ccfxmpp_lib_env.AppendUnique(CXXFLAGS = [
        #'-std=c++11',
        '-std=c++0x',
        '-Doverride=',
        '-fdata-sections',
        '-ffunction-sections',
        '-fno-rtti',
        '-DCCF_XMPP_EXPORTS',
        '-DASIO_STANDALONE',
        '-DASIO_NO_TYPEID',
        '-Os',
        '-Wall',
        '-Werror',
        '-Wno-unknown-pragmas',             # Ignore any windows-specific pragmas (don't warn)
        '-fPIC',
        ])
    if target_os not in ['darwin','ios']:
        ccfxmpp_lib_env.AppendUnique(
            CXXFLAGS = [
                '-Wl,--gc-sections',
                '-Wl,--strip-all',
                ])

    if env['STROPHE']:
        ccfxmpp_lib_env.AppendUnique(CXXFLAGS = [
            '-DENABLE_LIBSTROPHE',
            ])
    if not env['RELEASE']:
        # NOTE: We are currently leaving logging disabled in release to decrease code footprint.
        ccfxmpp_lib_env.AppendUnique(CXXFLAGS = [
            '-g',
            '-DLOGSTREAM_ENABLE_ALL_LOGGING',
            ])
elif target_os in ['windows', 'winrt']:
    ccfxmpp_lib_env.AppendUnique(CPPPATH = ['#WinDT/WinDT/'])

elif target_os == 'android':
    ccfxmpp_lib_env.AppendUnique(CXXFLAGS = ['-fno-rtti', '-fexceptions'])
    ccfxmpp_lib_env.AppendUnique(CPPPATH = ['platform/linux/include/'])
#	ccfxmpp_lib_env.AppendUnique(LIBPATH = [env.get('BUILD_DIR')])
#	ccfxmpp_lib_env.AppendUnique(LIBS = ['octbstack', 'oc_logger', 'boost_thread', 'gnustl_static', 'log'])


if target_os in ['darwin', 'ios']:
    ccfxmpp_lib_env.AppendUnique(LIBPATH = [env.get('BUILD_DIR')])
    ccfxmpp_lib_env.AppendUnique(CPPPATH = ['/usr/local/include'])
#	ccfxmpp_lib_env.AppendUnique(LIBS = ['octbstack', 'oc_logger'])


libccfxmpp_st = ccfxmpp_lib_env.StaticLibrary('ccfxmpp', ccfxmpp_src)
ccfxmpp_lib_env.Install(env.get('BUILD_DIR'), libccfxmpp_st)


ccfxmpp_shared_lib_env = ccfxmpp_lib_env.Clone()
ccfxmpp_shared_lib_env.AppendUnique(CXXFLAGS = ['-fvisibility=hidden'])

if target_os not in ['darwin', 'ios']:
    libccfxmpp_sh = ccfxmpp_shared_lib_env.SharedLibrary('ccfxmpp', ccfxmpp_src)
    ccfxmpp_shared_lib_env.Install(env.get('BUILD_DIR'), libccfxmpp_sh)


if env['RELEASE']:
    pass
    # TODO: Run strip against the shared object library (to remove symbols)


