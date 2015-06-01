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

# Current openssl library name
ssl_download_version = 'openssl-1.0.2a'
ssl_download_name = ssl_download_version+'.tar.gz'



def dir_offset_from_current(subdir):
    return os.path.join('#'+Dir('.').path, subdir)

Import('env')

print 'HAS_OPENSSL', env['HAS_OPENSSL']

if not env['HAS_OPENSSL'] or env['DOWNLOAD_OPENSSL']:
    ssl_env = env.Clone()

    src_dir = ssl_download_version+'/'
    libs_dir = src_dir

    if not os.path.exists(ssl_download_name):
        ssl_zip = ssl_env.URLDownload(ssl_download_name, 'https://www.openssl.org/source/'+ssl_download_name)

    if not os.path.exists(src_dir):
        ssl_dir = ssl_env.UnpackAll(src_dir+'Configure', ssl_download_name)


    if env['PLATFORM'] in ['win','64']:
        pass
 
    #configure_file = ssl_env.Command(src_dir+'configure', src_dir+'bootstrap.sh')
                                         #'bash -c "pushd external/openssl/libssl-master;./bootstrap.sh;popd"')
    #make_file = ssl_env.Configure(src_dir+'Makefile', src_dir+'config')

    # Run make dependent on whether one of the targets was created (not all). We mark this
    # target precious because it was not created by scons and should not be deleted by it when
    # the next build is run.
    #ssl_env.Precious(ssl_env.Make(libs_dir+'libssl.so', make_file))

    # Append the path to safec to the original environment
    env.AppendUnique(CPPPATH = [dir_offset_from_current(src_dir+'/include')],
                     LIBPATH = [dir_offset_from_current(libs_dir)])

    #ssl_env.Install(env['BUILD_DIR'], 'libssl.so')

    #conf = env.Configure()
    #env = conf.Environment()

