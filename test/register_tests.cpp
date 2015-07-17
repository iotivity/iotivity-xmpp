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

/// @file register_tests.cpp

#include "stdafx.h"
#include <gtest/gtest.h>

#include <xmpp/xmppclient.h>
#include <xmpp/xmppconfig.h>
#include <xmpp/xmppregister.h>
#include <connect/tcpclient.h>
#include "xmpp_test_config.h"
#include "xmpp_connect_config.h"

extern "C"
{
#if !defined(_WIN32)
#ifdef WITH_SAFE
#include <safe_mem_lib.h>
#include <safe_str_lib.h>
#endif
#endif
}


using namespace std;
using namespace Iotivity;
using namespace Iotivity::Xmpp;


#ifndef DISABLE_SUPPORT_XEP0077

#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT

#ifdef ENABLE_FUNCTIONAL_TESTING
TEST(InBandRegistration, XEP0077_Register_Remove)
#else
TEST(InBandRegistration, DISABLED_XEP0077_Register_Remove)
#endif
{
    if (!xmpp_connect_config::hasConfig())
    {
        cout << "XEP0077_Register_Remove skipped. No DEFAULT XMPP config." << endl;
        return;
    }

    const Iotivity::Xmpp::ProxyConfig proxy(xmpp_connect_config::proxyHost(),
                                            xmpp_connect_config::proxyPort(),
                                            Iotivity::Xmpp::ProxyConfig::ProxyType::ProxySOCKS5);
    auto remoteTcp = make_shared<TcpConnection>(xmpp_connect_config::host(),
                     xmpp_connect_config::port(), proxy);

    auto xmlConnection = make_shared<XmppConnection>(
                             static_pointer_cast<IStreamConnection>(remoteTcp));

    auto streamPromise = make_shared<promise<shared_ptr<IXmppStream>>>();
    auto streamFuture = streamPromise->get_future();

    XmppConfig config(JabberID(""), xmpp_connect_config::xmppDomain());
    config.requireTLSNegotiation();
    config.requestInBandRegistration();

    auto registrationParams = InBandRegistration::Params::create();
    registrationParams->setRegistrationParam("username", "unitTestUserName1");
    registrationParams->setRegistrationParam("password", "unitTestUserName1Password");
    // TODO: Secure password?

    config.setExtensionConfig(InBandRegistration::extensionName(), registrationParams);

    auto client = XmppClient::create();
    ASSERT_NO_THROW(client->initiateXMPP(config, xmlConnection, streamPromise));

    shared_ptr<IXmppStream> xmppStream;
    EXPECT_NO_THROW(xmppStream = streamFuture.get());
    ASSERT_NE(xmppStream, nullptr);

    xmppStream->whenNegotiated().wait_for(chrono::seconds(5));

}

#endif

#endif
