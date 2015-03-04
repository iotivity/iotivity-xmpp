# *********************************************************************
#
# Copyright 2015 Intel Mobile Communications GmbH All Rights Reserved.
#
# *********************************************************************
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *********************************************************************

# This builder executes UNIX-style Make files to build external components with
# their own build environment.


import os, subprocess
import SCons.Builder, SCons.Node, SCons.Errors

def __message( s, target, source, env ):
    print "Making [%s] ..." % (source[0])

def __no_action(target, source, env):
    pass

# @brief Action to run the make command (with default parameters) on a given Makefile
def __action(target, source, env):
    cmd = 'make -f '+os.path.basename(source[0].path)

    # We need to be in the source's directory
    cwd = os.path.dirname(os.path.realpath(source[0].path))
    handle  = subprocess.Popen( cmd, shell=True, cwd=cwd)

    if handle.wait() <> 0:
        raise SCons.Errors.BuildError("[%s] on the source [%s]" % (cmd, source[0]))


def __emitter(target, source, env):
    return target, source


# Fake emitter that actually cleans up the targets for a Makefile.
# If/when scons supports custom clean actions, this should be replaced with a more
# logical design.
def __clean_emitter(target, source, env):
    try:
        cmd = 'make -f '+os.path.basename(source[0].path)+" clean"

        cwd = os.path.dirname(os.path.join(env.Dir('#.').abspath, source[0].path))
        subprocess.Popen(cmd, shell=True, cwd=cwd).wait()

    except:
        print "Unable to clean", source[0].path

    return "", source



def generate(env):
    if not env.GetOption('clean'):
        env["BUILDERS"]["Make"] = SCons.Builder.Builder(action = __action,  
                                                        emitter = __emitter,  
                                                        target_factory = SCons.Node.FS.File,  
                                                        source_factory = SCons.Node.FS.File,  
                                                        single_source = True,  
                                                        PRINT_CMD_LINE_FUNC = __message)
    else:
        # For some reason there is no way to run actions during a clean, but an emitter
        # still runs, so we're making do. This emitter also cleans up the Makefile artifacts.
        # This may not always be desirable. TODO: Make this step optional with a flag.
        env["BUILDERS"]["Make"] = SCons.Builder.Builder(action = __no_action,
                                                        emitter = __clean_emitter,  
                                                        target_factory = SCons.Node.FS.File,  
                                                        source_factory = SCons.Node.FS.File,  
                                                        single_source = True,  
                                                        PRINT_CMD_LINE_FUNC = __message)


def exists(env):
    return 1
