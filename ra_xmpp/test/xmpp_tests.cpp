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

// Required by ra_xmpp.h for the Windows target builds.
#ifdef _WIN32
#include <SDKDDKVer.h>
#endif

#include <gtest/gtest.h>

#define XMPP_LIB_(x) xmpp_##x
#include <ra_xmpp.h>

#include <string>
#include <thread>
#include <future>

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
    xmpp_host_init(&host, "TEST_HOST", 5222, "TEST_DOMAIN", XMPP_PROTOCOL_XMPP);

    EXPECT_EQ(host.cb, sizeof(host));

    ASSERT_NE(host.host, nullptr);
    EXPECT_EQ(string(host.host), "TEST_HOST");
    EXPECT_EQ(host.port, 5222);
    ASSERT_NE(host.xmpp_domain, nullptr);
    EXPECT_EQ(string(host.xmpp_domain), "TEST_DOMAIN");
    EXPECT_EQ(host.protocol, XMPP_PROTOCOL_XMPP);
    xmpp_host_destroy(&host);

    EXPECT_EQ(host.host, nullptr);
    EXPECT_EQ(host.xmpp_domain, nullptr);

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
    EXPECT_NE(handle.abstract_handle, nullptr);

    xmpp_shutdown(handle);
    xmpp_context_destroy(&context);

    EXPECT_TRUE(xmpp_global_shutdown_okay() == 1);
}


const char *TEST_PROXY_HOST = "proxy-us.intel.com";
const uint16_t TEST_PROXY_PORT = 1080;

const char *JABBERDAEMON_TEST_HOST = "xmpp-dev-lb.api.intel.com";
const char *JABBERDAEMON_TEST_DOMAIN =  "xmpp-dev";
const uint16_t JABBERDAEMON_TEST_PORT = 5222;

const char *JABBERDAEMON_INTERNAL_TEST_HOST = "strophe-test.amr.corp.intel.com";
const char *JABBERDAEMON_INTERNAL_TEST_PORT = "5222";

//const std::string JABBERDAEMON_TEST_URL = "xmpp-dev-lb.api.intel.com/http-bind";
//const Iotivity::Xmpp::JabberID MY_JID{"unittest"};


struct ConnectCallbackTest
{

        ConnectCallbackTest(XMPP_LIB_(error_code_t) expect_connect,
                            XMPP_LIB_(error_code_t) expect_disconnect):
            m_onConnectErr(expect_connect), m_onDisconnectErr(expect_disconnect), m_connection( {0}) {}

        static void connected(void *const param, XMPP_LIB_(error_code_t) result,
                              XMPP_LIB_(connection_handle_t) connection)
        {
            EXPECT_NE(param, nullptr);
            ConnectCallbackTest *self = reinterpret_cast<ConnectCallbackTest *>(param);
            EXPECT_EQ(result, self->m_onConnectErr);
            self->m_connection = connection;
            cout << "Connected Callback: " << result << endl;

            self->m_connectedRanPromise.set_value();
        }

        XMPP_LIB_(connection_handle_t) getConnection()
        {
            return m_connection;
        }

        static void disconnected(void *const param, XMPP_LIB_(error_code_t) result,
                                 XMPP_LIB_(connection_handle_t) connection)
        {
            EXPECT_NE(param, nullptr);
            ConnectCallbackTest *self = reinterpret_cast<ConnectCallbackTest *>(param);
            EXPECT_EQ(result, self->m_onDisconnectErr);
            EXPECT_EQ(connection.abstract_connection, self->m_connection.abstract_connection);

            cout << "Disconnected Callback: " << result << endl;

            self->m_disconnectedRanPromise.set_value();
        }

        future<void> connectedRan() { return m_connectedRanPromise.get_future(); }
        future<void> disconnectedRan() { return m_disconnectedRanPromise.get_future(); }

    private:
        XMPP_LIB_(error_code_t) m_onConnectErr;
        XMPP_LIB_(error_code_t) m_onDisconnectErr;
        promise<void> m_connectedRanPromise;
        promise<void> m_disconnectedRanPromise;
        XMPP_LIB_(connection_handle_t) m_connection;
};


TEST(ra_xmpp, xmpp_remote_connect)
{
    xmpp_context_t context;
    xmpp_context_init(&context);

    xmpp_handle_t handle = xmpp_startup(&context);

    xmpp_host_t host;
    xmpp_host_init(&host, JABBERDAEMON_TEST_HOST, JABBERDAEMON_TEST_PORT, JABBERDAEMON_TEST_DOMAIN,
                   XMPP_PROTOCOL_XMPP);

    xmpp_identity_t identity;
    xmpp_identity_init(&identity, "unittest", "unitTestPassword", "", XMPP_NO_IN_BAND_REGISTER);

    xmpp_proxy_t proxy;
    xmpp_proxy_init(&proxy, TEST_PROXY_HOST, TEST_PROXY_PORT, XMPP_PROXY_SOCKS5);


    ConnectCallbackTest connect_callback_wrapper(XMPP_ERR_OK, XMPP_ERR_OK);

    xmpp_connection_callback_t callback = {};
    callback.on_connected = &ConnectCallbackTest::connected;
    callback.on_disconnected = &ConnectCallbackTest::disconnected;
    callback.param = &connect_callback_wrapper;

    EXPECT_EQ(xmpp_connect_with_proxy(handle, &host, &identity, &proxy, callback), XMPP_ERR_OK);

    // Wait for the connect callback.
    EXPECT_NO_THROW(connect_callback_wrapper.connectedRan().get());

    // Close.
    EXPECT_EQ(xmpp_close(connect_callback_wrapper.getConnection()), XMPP_ERR_OK);

    // Wait for the close callback.
    EXPECT_NO_THROW(connect_callback_wrapper.disconnectedRan().get());


    xmpp_proxy_destroy(&proxy);
    xmpp_identity_destroy(&identity);
    xmpp_host_destroy(&host);

    xmpp_shutdown(handle);
    xmpp_context_destroy(&context);

    EXPECT_TRUE(xmpp_global_shutdown_okay() == 1);
}