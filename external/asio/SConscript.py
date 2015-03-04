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

asio_env = env.Clone()

src_dir = 'asio-master/'
libs_dir = src_dir+'src/.libs/'

asio_library_file = 'master.zip'

if not os.path.exists(src_dir):
    asio_zip = asio_env.URLDownload(asio_library_file, 'https://github.com/chriskohlhoff/asio/archive/master.zip')
    asio_dir = asio_env.UnpackAll(src_dir+'asio/autogen.sh', asio_zip)

# NOTE: We are using asio in a header-only configuration. If there is a conmponent added that
#       requires a build, please add autogen.sh, ./configure and make to this target.
#make_file = asio_env.Configure(src_dir+'Makefile', src_dir+'asio/autogen.sh')

# Append the path to asio to the original environment
env.AppendUnique(CPPPATH = [dir_offset_from_current(src_dir+'asio/include')])

#lib = asio_env.InstallLibrary(libasio)



