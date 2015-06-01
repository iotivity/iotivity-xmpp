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
target_os = env.get('TARGET_OS')

safec_env = env.Clone()

src_dir = 'libsafec-10052013/'
libs_dir = src_dir+'src/.libs/'

safec_library_file = 'libsafec-10052013.tar.gz'

if target_os not in ['darwin']:
    if not os.path.exists(src_dir):
        safec_zip = safec_env.URLDownload(safec_library_file, 'http://sourceforge.net/projects/safeclib/files/libsafec-10052013.tar.gz/download')
        safec_dir = safec_env.UnpackAll(src_dir+'configure', safec_zip)

    make_file = safec_env.Configure(src_dir+'Makefile', src_dir+'configure')
    
    # Run make dependent on whether one of the targets was created (not all). We mark this
    # target precious because it was not created by scons and should not be deleted by it when
    # the next build is run.
    safec_env.Precious(safec_env.Make(libs_dir+'libsafec-1.0.so', make_file))
    
    safec_env.Depends(libs_dir+'libsafec-1.0.so.1', libs_dir+'libsafec-1.0.so')
    safec_env.Install(env['BUILD_DIR'], libs_dir+'libsafec-1.0.so.1')
    
    
    
    # Append the path to safec to the original environment
    env.AppendUnique(CPPPATH = [dir_offset_from_current(src_dir+'include/')],
                     LIBPATH = [dir_offset_from_current(src_dir+'src/.libs/')])

else:
       # Append the path to safec to the original environment
    env.AppendUnique(CPPPATH = [dir_offset_from_current('/usr/local/include/libsafec')])
 
#env.Repository(src_dir+'include')



