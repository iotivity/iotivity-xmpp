cmake_minimum_required(VERSION 2.8.4)
project(ccf-xmpp)
include(ExternalProject)
#### EXTERNALS ####

#safec
ExternalProject_Add(
    libsafec
    BUILD_IN_SOURCE 1
    URL http://sourceforge.net/projects/safeclib/files/libsafec-10052013.tar.gz/download
    PATCH_COMMAND ""
    CONFIGURE_COMMAND ./configure
    BUILD_COMMAND make
    INSTALL_COMMAND ""
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
)


ExternalProject_Get_Property(libsafec source_dir)
include_directories(
    ${source_dir}/include
)
add_library(safec UNKNOWN IMPORTED)
set_property(TARGET safec PROPERTY IMPORTED_LOCATION ${source_dir}/src/.libs/libsafec-1.0.so)
add_dependencies(safec libsafec)

#rapidxml
ExternalProject_Add(
    rapidxml
    URL https://github.com/dwarburt/RapidXML/archive/v0.1.tar.gz
    PATCH_COMMAND patch < ${CMAKE_SOURCE_DIR}/patches/rapidxml-no-ending.patch && patch < ${CMAKE_SOURCE_DIR}/patches/rapidxml-partial-parse.patch && patch < ${CMAKE_SOURCE_DIR}/patches/rapidxml-non-template-flags.patch
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    LOG_DOWNLOAD ON
)
ExternalProject_Get_Property(rapidxml source_dir)
include_directories(
    ${source_dir}
)

#googlemock
ExternalProject_Add(
    googlemock
    URL http://googlemock.googlecode.com/files/gmock-1.7.0.zip
    INSTALL_COMMAND ""
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
)
ExternalProject_Get_Property(googlemock source_dir)
include_directories(
    ${source_dir}/include
    ${source_dir}/gtest/include
)
ExternalProject_Get_Property(googlemock binary_dir)
add_library(gmock UNKNOWN IMPORTED)
set_property(TARGET gmock PROPERTY IMPORTED_LOCATION ${binary_dir}/${CMAKE_FIND_LIBRARY_PREFIXES}gmock.a)
add_dependencies(gmock googlemock)


#openssl
#find_package(OpenSSL REQUIRED)
#include_directories(${OpenSSL_INCLUDE_DIRS})


#asio
ExternalProject_Add(
    asio_cpp
    URL https://github.com/chriskohlhoff/asio/archive/master.zip
    PATCH_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
)
ExternalProject_Get_Property(asio_cpp source_dir)
include_directories(
    ${source_dir}/asio/include
)
ExternalProject_Get_Property(asio_cpp binary_dir)


#libstrophe
ExternalProject_Add(
    libstrophe
    # In the orignal build environment where this was tested master.zip had symbolic links that
    # would not process. Using URL is fine where this is not an issue.
    #URL https://github.com/strophe/libstrophe/archive/master.zip
    DOWNLOAD_COMMAND wget https://github.com/strophe/libstrophe/archive/master.zip COMMAND unzip master.zip -x libstrophe-master/README
    PATCH_COMMAND ""
    SOURCE_DIR libstrophe-prefix/src/libstrophe-master
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND pwd COMMAND ./bootstrap.sh COMMAND ./configure
    BUILD_COMMAND make
    INSTALL_COMMAND ""
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
)
ExternalProject_Get_Property(libstrophe source_dir)
include_directories(
    ${source_dir}/
)
ExternalProject_Get_Property(libstrophe binary_dir)
add_library(strophe UNKNOWN IMPORTED)
set_property(TARGET strophe PROPERTY IMPORTED_LOCATION ${binary_dir}/.libs/${CMAKE_FIND_LIBRARY_PREFIXES}strophe.so)
add_dependencies(strophe libstrophe)



set(CMAKE_EXE_LINKER_FLAGS  "-flto")


#### XMPP ####

#add_subdirectory(src/xmpp)
set(ccfxmpp_sources
    src/common/bufferencrypt.cpp  
    src/common/buffers.cpp  
    src/common/compatibility.cpp  
    src/common/errorabstraction.cpp
    src/common/rand_helper.cpp
    src/common/str_helpers.cpp
    src/common/logstream.cpp
    src/xml/portabledom.cpp
    src/connect/proxy.cpp
    src/connect/connecterror.cpp
    src/connect/curlconnect.cpp
    src/connect/tcpclient.cpp
    src/bosh/httpclient.cpp
    src/bosh/boshclient.cpp
    src/xmpp/jabberid.cpp
    src/xmpp/sasl.cpp
    src/xmpp/xmppclient.cpp
    src/xmpp/xmppstrophe.cpp
    src/xmpp/xmppconfig.cpp
    src/xmpp/xmppextension.cpp
    src/xmpp/xmppregister.cpp
    src/xmpp/xmppstream.cpp
    src/xmpp/xmppping.cpp
    src/xmpp/xmpppubsub.cpp
    src/xmpp/xmppservicedisc.cpp
)

add_definitions(-D_GNU_SOURCE
    -std=c++11
    -fdata-sections
    -ffunction-sections
    -flto
    -fno-rtti
    -DENABLE_LIBSTROPHE
    -DLOGSTREAM_ENABLE_ALL_LOGGING
    #-fvisibility=hidden
    -DCCF_XMPP_EXPORTS
    -Os
    -Wl,--gc-sections
    -Wl,--strip-all
    -Wall
    -Wno-unknown-pragmas
    -Werror)

include_directories(src src/platform/linux)
add_library(ccfxmpp SHARED ${ccfxmpp_sources})
add_dependencies(ccfxmpp safec rapidxml)
target_link_libraries(ccfxmpp
    safec
    strophe
)



# XMPP Tests


set(ccfxmpp_test_sources
    test/unittest_base.cpp
    test/common_tests.cpp
    test/curl_tests.cpp
    test/bosh_tests.cpp
    test/xmpp_tests.cpp
    test/xmpp_dummy_server.cpp
    test/xmpp_compliance_tests.cpp
    test/tcp_tests.cpp
    test/ping_tests.cpp
    test/pubsub_tests.cpp
    test/register_tests.cpp
    test/servicedisc_tests.cpp
    test/portabledom_tests.cpp
)
include_directories(src src/platform/linux)
add_executable(ccfxmpp_tests ${ccfxmpp_test_sources})
add_dependencies(ccfxmpp_tests ccfxmpp rapidxml safec gmock)
target_link_libraries(ccfxmpp_tests 
    ccfxmpp
    strophe
    gmock
    curl
    ssl
    pthread
    crypto
    safec
)

#add_custom_command(TARGET ccfxmpp POST_BUILD
#    COMMAND strip $<TARGET_FILE:ccfxmpp>
#)


