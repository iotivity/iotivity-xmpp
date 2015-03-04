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

strophe_env = env.Clone()

src_dir = 'libstrophe-master/'
libs_dir = src_dir+'.libs/'

strophe_library_file = 'master.zip'

if not os.path.exists(src_dir):
    strophe_zip = strophe_env.URLDownload(strophe_library_file, 'https://github.com/strophe/libstrophe/archive/master.zip')
    strophe_dir = strophe_env.UnpackAll(src_dir+'bootstrap.sh', strophe_zip)

configure_file = strophe_env.Command(src_dir+'configure', src_dir+'bootstrap.sh', 
                                     'bash -c "pushd external/libstrophe/libstrophe-master;./bootstrap.sh;popd"')
make_file = strophe_env.Configure(src_dir+'Makefile', configure_file)

# Run make dependent on whether one of the targets was created (not all). We mark this
# target precious because it was not created by scons and should not be deleted by it when
# the next build is run.
strophe_env.Precious(strophe_env.Make(libs_dir+'libstrophe.so', make_file))

# Append the path to safec to the original environment
env.AppendUnique(CPPPATH = [dir_offset_from_current(src_dir)],
                 LIBPATH = [dir_offset_from_current(libs_dir)])

#env.Repository(src_dir+'include')

strophe_env.Install(env['BUILD_DIR'], libs_dir+'libstrophe.so.0')




