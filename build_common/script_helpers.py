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
import sys
import platform
from collections import defaultdict
from functools import reduce


def platform_host():
    return platform.system().lower()

def platform_arch():
    return platform.machine().lower()


def pretty_print(a_set):
    return reduce((lambda i,j: i+", "+j), a_set)



color_root_table = [('error',   '\x1b[31;1m'), ('red',    '\x1b[31m'), 
                    ('warning', '\x1b[33;1m'), ('yellow', '\x1b[33m'),
                    ('okay',    '\x1b[32;1m'), ('green',  '\x1b[32m'),
                    ('blue',    '\x1b[34m'),   ('cyan',   '\x1b[36m'), 
                    ('magenta', '\x1b[35m'),   ('white',  '\x1b[37m')]
color_table = defaultdict(lambda: "", color_root_table)
reset_color = '\x1b[39;49m'

def print_in_color(color, text):
    # We do not attempt to do color management for windows here. See the project colorama
    # for a more portable option, if required.
    if sys.stdout.isatty() and platform_host()!='windows':
        print color_table[color], text, reset_color
    else:
        print text


def print_error(text):
    print_in_color('error', "\nError: %s\n" % text)


def print_warning(text):
    print_in_color('warning', "\nWarning: %s\n" % text)



