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

Import('env')

# Windows does not require safec, as the functions used are present in its C standard library
# if env['PLATFORM'] not in ['win']:
#     SConscript([
#                'safec/SConscript.py',
#                ], duplicate = 0)

SConscript([
           'asio/SConscript.py',
           'gmock/SConscript.py',
           'rapidxml-1.13/SConscript.py',
           'openssl/SConscript.py',
           'libcurl/SConscript.py'
           ], duplicate = 0)


if env['STROPHE']==1 and env['PLATFORM'] not in ['darwin']:
    SConscript(['libstrophe/SConscript.py'])

