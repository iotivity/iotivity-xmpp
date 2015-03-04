///////////////////////////////////////////////////////////////////////////////
//
// Copyright 2015 Intel Mobile Communications GmbH All Rights Reserved.
//
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
//
//
///////////////////////////////////////////////////////////////////////////////

/// @file xmpp_tests.cpp

#include <gtest/gtest.h>

#define XMPP_LIB_(x) xmpp_##x
#include <ra_xmpp.h>

#include <string>

using namespace std;


// NOTE: We are testing the C functions in a C++ context here.

TEST(ra_xmpp, xmpp_context)
{
    xmpp_context_t context;
    memset(&context, 1, sizeof(context));

    xmpp_context_init(&context);
    EXPECT_EQ(context.cb, sizeof(context));
    EXPECT_EQ(context.log_callback, nullptr);
    xmpp_context_destroy(&context);

    EXPECT_TRUE(xmpp_global_shutdown_okay() == 1);
}

TEST(ra_xmpp, xmpp_host)
{
    xmpp_host_t host;
    memset(&host, 1, sizeof(host));

    ASSERT_NE(host.protocol, XMPP_PROTOCOL_XMPP);
    xmpp_host_init(&host, "TEST_HOST", 5222, XMPP_PROTOCOL_XMPP);

    EXPECT_EQ(host.cb, sizeof(host));

    ASSERT_NE(host.host, nullptr);
    EXPECT_EQ(string(host.host), "TEST_HOST");
    EXPECT_EQ(host.port, 5222);
    EXPECT_EQ(host.protocol, XMPP_PROTOCOL_XMPP);
    xmpp_host_destroy(&host);

    EXPECT_EQ(host.host, nullptr);

    EXPECT_TRUE(xmpp_global_shutdown_okay() == 1);
}

TEST(ra_xmpp, xmpp_identity)
{
    xmpp_identity_t identity;
    memset(&identity, 1, sizeof(identity));

    ASSERT_NE(identity.inband_registration, XMPP_NO_IN_BAND_REGISTER);

    xmpp_identity_init(&identity, "TEST_NAME", "TEST_PASS", "TEST_NAME@TEST_HOST/TEST_RESOURCE",
                       XMPP_NO_IN_BAND_REGISTER);

    EXPECT_EQ(identity.cb, sizeof(identity));
    ASSERT_NE(identity.user_name, nullptr);
    EXPECT_EQ(string(identity.user_name), "TEST_NAME");
    ASSERT_NE(identity.password, nullptr);
    EXPECT_EQ(string(identity.password), "TEST_PASS");
    ASSERT_NE(identity.user_jid, nullptr);
    EXPECT_EQ(string(identity.user_jid), "TEST_NAME@TEST_HOST/TEST_RESOURCE");
    EXPECT_EQ(identity.inband_registration, XMPP_NO_IN_BAND_REGISTER);
    xmpp_identity_destroy(&identity);
    EXPECT_EQ(identity.user_name, nullptr);
    EXPECT_EQ(identity.password, nullptr);
    EXPECT_EQ(identity.user_jid, nullptr);

    EXPECT_TRUE(xmpp_global_shutdown_okay() == 1);
}

TEST(ra_xmpp, xmpp_proxy)
{
    xmpp_proxy_t proxy;
    memset(&proxy, 1, sizeof(proxy));

    ASSERT_NE(proxy.proxy_type, XMPP_PROXY_DIRECT_CONNECT);

    xmpp_proxy_init(&proxy, "TEST_HOST", 1080, XMPP_PROXY_DIRECT_CONNECT);

    EXPECT_EQ(proxy.cb, sizeof(proxy));
    EXPECT_EQ(proxy.proxy_type, XMPP_PROXY_DIRECT_CONNECT);
    ASSERT_NE(proxy.proxy_host, nullptr);
    EXPECT_EQ(string(proxy.proxy_host), "TEST_HOST");
    EXPECT_EQ(proxy.proxy_port, 1080);

    xmpp_proxy_destroy(&proxy);
    EXPECT_EQ(proxy.proxy_host, nullptr);

    EXPECT_TRUE(xmpp_global_shutdown_okay() == 1);
}

TEST(ra_xmpp, xmpp_startup_shutdown)
{
    xmpp_context_t context;
    xmpp_context_init(&context);
    xmpp_handle_t handle = xmpp_startup(&context);
    EXPECT_NE(handle, nullptr);

    xmpp_shutdown(handle);
    xmpp_context_destroy(&context);

    EXPECT_TRUE(xmpp_global_shutdown_okay() == 1);
}