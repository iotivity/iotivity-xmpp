# Temporarily include '.' as a library path for running the test suite.
# On linux 'ld-linux.??.so.2 --library-path . ./ccfxmpp_tests' may
# also be used, but is less portable.

export LD_LIBRARY_PATH=.
./ccfxmpp_tests
