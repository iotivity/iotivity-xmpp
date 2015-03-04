# Temporarily include '.' as a library path for running the test suite.
# On linux 'ld-linux.??.so.2 --library-path . ./ra_xmpp_tests' may
# also be used, but is less portable.

export LD_LIBRARY_PATH=.
./ra_xmpp_test
