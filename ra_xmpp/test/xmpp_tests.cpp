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

#include <ra_xmpp.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <string>
#include <thread>
#include <future>
#include <random>

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
    EXPECT_TRUE(xmpp_global_shutdown_okay() == 1);
    xmpp_context_t context;
    xmpp_context_init(&context);
    xmpp_handle_t handle = xmpp_startup(&context);
    EXPECT_NE(handle.abstract_handle, nullptr);

    xmpp_shutdown_xmpp(handle);
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

/*

ID  8
APP GUID    7e14b5f9-914c-4911-8fbf-af58de8825fb
ISV Intel
NAME    ra_xmpp_test
CREATED AT  May 27, 2015 17:28
UPDATED AT  May 27, 2015 17:28
USER LIMIT  100
CLIENTID    7E14B5F9-914C-4911-8FBF-AF58DE8825FB
CLIENT SECRET   RA XMPP CLIENT SECRET MAY BE REVOKED AT ANY TIME
TURNUSER LT EMPTY*/




struct ConnectCallbackTest
{

        ConnectCallbackTest(xmpp_error_code_t expect_connect,
                            xmpp_error_code_t expect_disconnect):
            m_onConnectErr(expect_connect), m_onDisconnectErr(expect_disconnect), m_connection( {0}) {}

        static void connected(void *const param, xmpp_error_code_t result,
                              xmpp_connection_handle_t connection)
        {
            EXPECT_NE(param, nullptr);
            ConnectCallbackTest *self = reinterpret_cast<ConnectCallbackTest *>(param);
            EXPECT_EQ(result, self->m_onConnectErr);
            self->m_connection = connection;
            cout << "Connected Callback: " << result << endl;

            self->m_connectedRanPromise.set_value();
        }

        xmpp_connection_handle_t getConnection()
        {
            return m_connection;
        }

        static void disconnected(void *const param, xmpp_error_code_t result,
                                 xmpp_connection_handle_t connection)
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
        xmpp_error_code_t m_onConnectErr;
        xmpp_error_code_t m_onDisconnectErr;
        promise<void> m_connectedRanPromise;
        promise<void> m_disconnectedRanPromise;
        xmpp_connection_handle_t m_connection;
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

    cout << "BEFORE CONNECTED CALLBACK" << endl;
    // Wait for the connect callback.
    EXPECT_NO_THROW(connect_callback_wrapper.connectedRan().get());

    cout << "AFTER CONNECTED CALLBACK" << endl;
    // Close.
    EXPECT_EQ(xmpp_close(connect_callback_wrapper.getConnection()), XMPP_ERR_OK);

    cout << "AFTER XMPP CLOSE" << endl;

    // Wait for the close callback.
    EXPECT_NO_THROW(connect_callback_wrapper.disconnectedRan().get());

    cout << "AFTER DISCONNECTED CALLBACK" << endl;

    xmpp_proxy_destroy(&proxy);
    xmpp_identity_destroy(&identity);
    xmpp_host_destroy(&host);

    xmpp_shutdown_xmpp(handle);
    xmpp_context_destroy(&context);

    EXPECT_TRUE(xmpp_global_shutdown_okay() == 1);
}


const char *TEST_SESSION_GUID = "F1AED571-A1E4-4DB7-BF1C-41865C44E689";
const char *TEST_APP_GUID = "7e14b5f9-914c-4911-8fbf-af58de8825fb";
const char TEST_APP_KEY[] = "RA XMPP CLIENT SECRET MAY BE REVOKED AT ANY TIME";

template <typename _T> _T BASE64_ENCODE_RESERVE(_T size) { return (size + 2) / 3 * 4; }

string base64Encode(const void *buf, size_t size)
{
    if (!buf || size == 0)
    {
        return "";
    }
    // 32 as EVP_EncodeBlock adds garbage past the expected end of the buffer.
    size_t bufLen = BASE64_ENCODE_RESERVE(size) + 32;

    auto *tempBuf = new uint8_t[bufLen] {};
    try
    {
        EVP_EncodeBlock(tempBuf, (const uint8_t *)buf, (int)size);
        tempBuf[bufLen - 1] = 0;
        return (const char *)tempBuf;
    }
    catch (...)
    {
        delete tempBuf;
        throw;
    }
    delete tempBuf;
}

void constructTestUserAuth(const string &userPart1, const string &userPart2,
                           string &userName, string &password)
{
    static mt19937 rng;


#ifdef USE_REAL_RAND_BUF
    // NOTE: If you do switch to using a real random buf, you will need to update the
    // TEST_SESSION_GUID each time too. This is present for manual executions of the canonical
    // registration, not for normal test scenarios.
    uint8_t randBuf[64] = {0};
    uniform_int_distribution<int> rngSelector(0, 255);

    for (size_t i = 0; i < sizeof(randBuf) / sizeof(randBuf[0]); ++i)
    {
        randBuf[i] = static_cast<uint8_t>(rngSelector(rng));
    }
#else
    // Use a block of non-random random data so multiple users do not get registered for the
    // connectional functional tests.
    uint8_t randBuf[64] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                           0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                           0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
                           0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                           0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
                           0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                           0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40
                          };
#endif

    uint8_t hmac[SHA256_DIGEST_LENGTH] = {0};
    unsigned int digestLength = SHA256_DIGEST_LENGTH;

    HMAC(EVP_sha256(), TEST_APP_KEY, sizeof(TEST_APP_KEY) / sizeof(TEST_APP_KEY[0]) - 1,
         randBuf, sizeof(randBuf) / sizeof(randBuf[0]), &hmac[0], &digestLength);

    userName = userPart1 + "_" + userPart2;
    password = base64Encode(randBuf, sizeof(randBuf) / sizeof(randBuf[0])) + ":" +
               base64Encode(hmac, sizeof(hmac) / sizeof(hmac[0]));
}

TEST(ra_xmpp, xmpp_remote_register_connect)
{
    xmpp_context_t context;
    xmpp_context_init(&context);

    xmpp_handle_t handle = xmpp_startup(&context);

    xmpp_host_t host;
    xmpp_host_init(&host, JABBERDAEMON_TEST_HOST, JABBERDAEMON_TEST_PORT, JABBERDAEMON_TEST_DOMAIN,
                   XMPP_PROTOCOL_XMPP);


    string userName;
    string password;
    constructTestUserAuth(TEST_SESSION_GUID, TEST_APP_GUID, userName, password);

    xmpp_identity_t identity;
    xmpp_identity_init(&identity, userName.c_str(), password.c_str(), "",
                       XMPP_TRY_IN_BAND_REGISTER);

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

    xmpp_shutdown_xmpp(handle);
    xmpp_context_destroy(&context);

    EXPECT_TRUE(xmpp_global_shutdown_okay() == 1);
}
