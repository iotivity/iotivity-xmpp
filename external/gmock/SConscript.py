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


def dir_offset_from_current(subdir):
    return os.path.join('#'+Dir('.').path, subdir)


Import('env')

gmock_env = env.Clone()

target_os = gmock_env.get('TARGET_OS')

src_dir= 'gmock-1.7.0/'
tar_file = 'gmock-1.7.0.zip'
tar_url = 'https://googlemock.googlecode.com/files/gmock-1.7.0.zip'

if not os.path.exists(tar_file):
    target_zip = gmock_env.URLDownload(tar_file, tar_url)

if not os.path.exists(src_dir):
    target_dir = gmock_env.UnpackAll(src_dir+'configure', tar_file)


if target_os in ['windows', 'winrt']:
    # Build gmock as a third-party solution    
    #env.BuildSolution(target = "", source = src_dir+'/msvc/2010/gmock.sln')
    pass
else:
    libs_dir = src_dir+"lib/.libs/"

    make_file = gmock_env.Configure(target = src_dir+'Makefile', source = src_dir+'configure')

    # Run make dependent on whether one of the targets was created (not all). We mark this
    # target precious because it was not created by scons and should not be deleted by it when
    # the next build is run.
    
    if target_os in ['darwin']:
        gmock_env.Precious(gmock_env.Make(target = libs_dir+'libgmock.dylib', source = make_file))
    else:
        gmock_env.Precious(gmock_env.Make(target = libs_dir+'libgmock.so', source = make_file))

    if target_os in ['darwin']:
        gmock_env.Depends(src_dir+'gtest/lib/.libs/libgtest.dylib', libs_dir+'libgmock.dylib')
        gmock_env.Depends(src_dir+'gtest/lib/.libs/libgtest.0.dylib', libs_dir+'libgmock.dylib')
    else:
        gmock_env.Depends(src_dir+'gtest/lib/.libs/libgtest.so', libs_dir+'libgmock.so')
        gmock_env.Depends(src_dir+'gtest/lib/.libs/libgtest.so.0', libs_dir+'libgmock.so')
        

    # For running ccfxmpp_tests
    if target_os not in ['darwin']:
        gmock_env.Install(env['BUILD_DIR'], src_dir+'gtest/lib/.libs/libgtest.so')
        gmock_env.Install(env['BUILD_DIR'], src_dir+'gtest/lib/.libs/libgtest.so.0')
    else:
        gmock_env.Install(env['BUILD_DIR'], src_dir+'gtest/lib/.libs/libgtest.dylib')
        gmock_env.Install(env['BUILD_DIR'], src_dir+'gtest/lib/.libs/libgtest.0.dylib')
        gmock_env.Install(env['BUILD_DIR'], src_dir+'lib/.libs/libgmock.dylib')
        gmock_env.Install(env['BUILD_DIR'], src_dir+'lib/.libs/libgmock.0.dylib')

    # Append the path to asio to the original environment
    env.AppendUnique(CPPPATH = [dir_offset_from_current(src_dir+'include/'),
                                dir_offset_from_current(src_dir+'gtest/include/')],
                     LIBPATH = [dir_offset_from_current(libs_dir),
                                dir_offset_from_current(src_dir+'gtest/lib/.libs/')])
    
