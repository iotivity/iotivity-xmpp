#!/bin/bash

# Temporarily include '.' as a library path for running the test suite.
# On linux 'ld-linux.??.so.2 --library-path . ./ra_xmpp_tests' may
# also be used, but is less portable.

if [ "$(uname)" == "Darwin" ]; then
	export DYLD_LIBRARY_PATH=.
else
	export LD_LIBRARY_PATH=.
fi

./ra_xmpp_test
