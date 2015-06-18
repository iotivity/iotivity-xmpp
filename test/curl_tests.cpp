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

/// @file curl_tests.cpp

#include "stdafx.h"
#include <gtest/gtest.h>

#include "bosh/httpclient.h"
#include "connect/proxy.h"

#include <curl/curl.h>
#include <iostream>

using namespace std;



#ifndef DISABLE_SUPPORT_BOSH

TEST(Curl, Curl_Global_Init)
{
    CURLcode init1Result = curl_global_init(CURL_GLOBAL_DEFAULT);
    EXPECT_EQ(init1Result, CURLE_OK);

    curl_global_cleanup();
}


using namespace Iotivity;
using namespace Iotivity::Xmpp;



// connect_error
TEST(connect_error, ConnectError_Coverage_Test)
{
    EXPECT_GT(connect_error::etConnectError(), LocalError::etMaxInternalErrorType);

    connect_error tempError;
    EXPECT_EQ(tempError, LocalError());

    LocalError tempLocal(LocalError::ecInvalidParameter);
    connect_error tempMatchError(tempLocal);
    EXPECT_EQ(tempMatchError, tempLocal);

    //connect_error connectError(connect_error::ecNotAuthorized, connect_error::etConnectError());
    //EXPECT_EQ(connect_error.errorCode(), connect_error::ecNotAuthorized);
    //EXPECT_EQ(connect_error.errorType(), connect_error::etConnectError());
    //connect_error ConnectErrorMatch(connect_error);
    //EXPECT_EQ(connect_error, ConnectErrorMatch);

    //connect_error ConnectError2(connect_error::ecNotAuthorized);
    //EXPECT_EQ(ConnectError2.errorCode(), connect_error::ecNotAuthorized);
    //EXPECT_EQ(ConnectError2.errorType(), connect_error::etConnectError());

    connect_error success1 = connect_error::SUCCESS;
    EXPECT_TRUE(success1.succeeded());

    connect_error success2 = connect_error::ecSuccess;
    EXPECT_TRUE(success2.succeeded());

#ifdef _WIN32
    connect_error success3 = S_OK;
    EXPECT_TRUE(success3.succeeded());

    connect_error success4(ERROR_SUCCESS, connect_error::etWindowsError);
    EXPECT_TRUE(success4.succeeded());
#endif

    //EXPECT_FALSE(connect_error.succeeded());

    //connect_error errorCodeAssign;
    //errorCodeAssign = connect_error::ecNotAuthorized;
    //EXPECT_EQ(errorCodeAssign.errorCode(), connect_error::ecNotAuthorized);
    //EXPECT_EQ(errorCodeAssign.errorType(), connect_error::etConnectError());

    //connect_error errorCodeHRESULT;
    //errorCodeHRESULT = E_NOT_SET;
    //EXPECT_EQ(errorCodeHRESULT.errorCode(), E_NOT_SET);
    //EXPECT_EQ(errorCodeHRESULT.errorType(), LocalError::etHRESULT);

#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
    asio::error_code defError;
    connect_error errorCodeDefaultASIOError(defError);
    EXPECT_TRUE(errorCodeDefaultASIOError.succeeded());
    EXPECT_EQ(errorCodeDefaultASIOError.errorCode(), 0);
    EXPECT_EQ(errorCodeDefaultASIOError.errorType(), connect_error::etASIOError());

    EXPECT_EQ(connect_error().ASIOError(), defError);

    static struct dummyCategory: public asio::error_category
    {
        virtual const char *name() const throw() { return "dummyCategory"; }

        /// Returns a string describing the error denoted by @c value.
        virtual std::string message(int value) const { return "dummyError" + to_string(value); }
    } s_dummyCategory;

    asio::error_code dummyError(1, s_dummyCategory);
    connect_error errorCodeASIOError(dummyError);
    EXPECT_FALSE(errorCodeASIOError.succeeded());
    EXPECT_EQ(errorCodeASIOError.errorCode(), 1);
    EXPECT_EQ(errorCodeASIOError.errorType(), connect_error::etASIOError());

    EXPECT_EQ(errorCodeASIOError.ASIOError(), dummyError);

#endif
}


TEST(CurlConnection, Curl_SList)
{
    curl_slist *testListStart = nullptr;
    CurlConnection connection;

    {
        SList testList(connection);
        EXPECT_FALSE(testList.isValid());
        EXPECT_EQ(testList.getSList(), nullptr);

        list<string> testStrings;
        testStrings.push_back("TEST1");
        testStrings.push_back("TEST2");

        testList.push_back(testStrings);
        EXPECT_TRUE(testList.isValid());
        EXPECT_NE(testList.getSList(), nullptr);

        testListStart = testList;

        ASSERT_NE(testListStart, nullptr);
        EXPECT_NE(testListStart->data[0], '\0');
    }

    EXPECT_NE(testListStart->data[0], '\0');
}

TEST(HttpConnection, Http_Proxy)
{
    ProxyConfig emptyConfig;
    EXPECT_EQ(emptyConfig.url(), "");
    EXPECT_EQ(emptyConfig.type(), ProxyConfig::ProxyType::ProxyUndefined);

    ProxyConfig simpleConfig("myurl.com:911");
    EXPECT_EQ(simpleConfig.url(), "myurl.com:911");
    EXPECT_EQ(simpleConfig.type(), ProxyConfig::ProxyType::ProxyHTTP);

    ProxyConfig assignConfig;
    assignConfig = simpleConfig;
    EXPECT_EQ(assignConfig.url(), "myurl.com:911");
    EXPECT_EQ(assignConfig.type(), ProxyConfig::ProxyType::ProxyHTTP);

    ProxyConfig moveConfig = std::move(simpleConfig);
    EXPECT_EQ(moveConfig.url(), "myurl.com:911");
    EXPECT_EQ(moveConfig.type(), ProxyConfig::ProxyType::ProxyHTTP);
}

TEST(HttpConnection, Http_HostName)
{
    // TODO:
}

#ifdef ENABLE_FUNCTIONAL_TESTING
TEST(HttpConnection, Http_Simple_Connect)
#else
TEST(HttpConnection, DISABLED_Http_Simple_Connect)
#endif
{
    HttpCurlConnection connection;
    ASSERT_TRUE(connection.isValid());

    connection.setRequestTimeout(chrono::milliseconds(10000));
    connection.setUrl("http://google.com");

    connection.setProxy(ProxyConfig::queryProxy());
    try
    {
        connection.performSynchronousConnect();
    }
    catch (const connect_error &ec)
    {
        if (ec.errorType() == connect_error::etHttpError())
        {
            EXPECT_LT(ec.errorCode(), 400);
        }
        else
        {
            EXPECT_NO_THROW(throw ec);
        }
    }
}

#ifdef ENABLE_FUNCTIONAL_TESTING
TEST(HttpConnection, DISABLED_Https_Connect)
#else
TEST(HttpConnection, DISABLED_Https_Connect)
#endif
{
    HttpCurlConnection connection;
    ASSERT_TRUE(connection.isValid());

    connection.setRequestTimeout(chrono::milliseconds(10000));
    connection.setUrl("https://google.com");

    connection.setProxy(ProxyConfig::queryProxy());

    // TODO: Fix TLS negotiation
    EXPECT_NO_THROW(connection.performSynchronousConnect());
}


#endif // DISABLE_SUPPORT_BOSH