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
# The main build script for ccfxmpp
#
##

import os
import sys


# Add build_common to package search path (for common utilities)
sys.path.append(os.path.join(os.path.dirname('__file__'), "build_common"))


# Load common build config. Edit this file to change the targets supported by the build.
# NOTE: We use SConscript.py rather than the convential SConscript name so that Python will properly 
#       precompile all the build scripts.
SConscript('build_common/SConscript.py')

Import('env')


# Ensure the build scripts are accessible from the build environment (those that aren't extensions)
sys.path.append('build_common')


# Load and prepare external modules
SConscript('external/SConscript.py')

# Load extra options
#SConscript('extra_options.scons')


# Configure the primary build targets
SConscript([
           'src/SConscript.py',
           'ra_xmpp/SConscript.py',
           'test/SConscript.py',
           ])
    


# By default, src_dir is current dir, the build_dir is:
#     ./out/<target_os>/<target_arch>/<release or debug>/
#
# The build_dir is a variant directory of the source directory(You can
# consider build_dir as a soft link to src_dir, for detail please refer to:
#     http://www.scons.org/doc/production/HTML/scons-user.html#f-VariantDir
#
# Any way, to make the output is in build_dir, when load scripts, the path should
# be relative to build_dir.
build_dir = env.get('BUILD_DIR')

# Append targets information to the help information, to see help info, execute command line:
#     $ scons [options] -h
#env.PrintTargets()




