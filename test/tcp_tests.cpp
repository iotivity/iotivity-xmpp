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

/// @file tcp_tests.cpp

#include "stdafx.h"
#include <gtest/gtest.h>

#include <connect/tcpclient.h>
#include <connect/proxy.h>
#include <common/buffers.h>
#include <common/logstream.h>

#include <iostream>

#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT

static const std::string JABBERDAEMON_TEST_HOST = "xmpp-dev.iotivity.intel.com";
static const std::string JABBERDAEMON_TEST_PORT = "5222";

using namespace std;
using namespace Iotivity;
using namespace Iotivity::Xmpp;

TEST(TcpConnection, XmppConnect)
{
    ProxyConfig proxy("proxy-us.intel.com", "1080", ProxyConfig::ProxyType::ProxySOCKS5);
    TcpConnection testConnection(JABBERDAEMON_TEST_HOST, JABBERDAEMON_TEST_PORT, proxy);

#ifdef DISABLE_SUPPORT_SOCKS5
    EXPECT_THROW(testConnection.connect(), connect_error);
#else
    EXPECT_NO_THROW(testConnection.connect());
#endif


}


TEST(TcpConnection, SynchronousReadWrite)
{
    ProxyConfig proxy("proxy-us.intel.com", "1080", ProxyConfig::ProxyType::ProxySOCKS5);
    TcpConnection testConnection(JABBERDAEMON_TEST_HOST, JABBERDAEMON_TEST_PORT, proxy);

    ASSERT_NO_THROW(testConnection.connect());

    // TODO:
}


TEST(TcpConnection, AsynchronousReadWrite)
{
    ProxyConfig proxy("proxy-us.intel.com", "1080", ProxyConfig::ProxyType::ProxySOCKS5);
    TcpConnection testConnection(JABBERDAEMON_TEST_HOST, JABBERDAEMON_TEST_PORT, proxy);

    ASSERT_NO_THROW(testConnection.connect());

    // TODO:
}

#endif // DISABLE_SUPPORT_NATIVE_XMPP_CLIENT