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

/// @file xmpp_connect_establish.cpp

#include "stdafx.h"
#include "xmpp_connect_establish.h"
#ifdef ENABLE_LIBSTROPHE
#include <xmpp/xmppstrophe.h>
#else
#include <xmpp/xmppclient.h>
#endif
#include <connect/tcpclient.h>
#include <connect/proxy.h>
#include <common/bufferencrypt.h>
#include <xmpp/sasl.h>
#include <xmpp/xmppconfig.h>
#include <xmpp/xmppregister.h>
#include "xmpp_connect_config.h"

#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <iostream>

using namespace std;
using namespace Iotivity;
using namespace Iotivity::Xmpp;



const char *TEST_SESSION_GUID = "F1AED571-A1E4-4DB7-BF1C-41865C44E691";
const char *TEST_APP_GUID = "7e14b5f9-914c-4911-8fbf-af58de8825fb";
const char TEST_APP_KEY[] = "RA XMPP CLIENT SECRET MAY BE REVOKED AT ANY TIME";


string base64Encode(const void *buf, size_t size)
{
    if (!buf || size == 0)
    {
        return "";
    }

    ByteBuffer outBuffer;
    ByteBuffer::base64Encode(ByteBuffer((void *)buf, size, false), outBuffer);

    return string((const char *)outBuffer.get(), outBuffer.size());
}

void constructTestUserAuth(const string &userPart1, const string &userPart2,
                           string &userName, string &password)
{
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

    uint8_t hmac[SHA256_DIGEST_LENGTH] = {0};
    unsigned int digestLength = SHA256_DIGEST_LENGTH;

    HMAC(EVP_sha256(), TEST_APP_KEY, sizeof(TEST_APP_KEY) / sizeof(TEST_APP_KEY[0]) - 1,
         randBuf, sizeof(randBuf) / sizeof(randBuf[0]), &hmac[0], &digestLength);

    userName = userPart1 + "_" + userPart2;
    password = base64Encode(randBuf, sizeof(randBuf) / sizeof(randBuf[0])) + ":" +
               base64Encode(hmac, sizeof(hmac) / sizeof(hmac[0]));
}


void xmpp_test_default_connect_client(shared_ptr<IXmppStream> &stream,
                                      shared_ptr<IXmppClient> &client)
{
#ifdef ENABLE_LIBSTROPHE
    if (!xmpp_connect_config::hasConfig("NO_PROXY"))
#else
    if (!xmpp_connect_config::hasConfig())
#endif
    {
        return;
    }

#ifdef ENABLE_LIBSTROPHE
    auto xmlConnection = make_shared<XmppStropheConnection>(xmpp_connect_config::host("NO_PROXY"),
                         xmpp_connect_config::port("NO_PROXY"));
#else
    const ProxyConfig proxy(xmpp_connect_config::proxyHost(),
                            xmpp_connect_config::proxyPort(),
                            Iotivity::Xmpp::ProxyConfig::ProxyType::ProxySOCKS5);
    auto remoteTcp = make_shared<TcpConnection>(xmpp_connect_config::host(),
                     xmpp_connect_config::port(), proxy);

    auto xmlConnection = make_shared<XmppConnection>(
                             static_pointer_cast<IStreamConnection>(remoteTcp));
#endif

    auto streamPromise = make_shared<promise<shared_ptr<IXmppStream>>>();
    auto streamFuture = streamPromise->get_future();

    string userName = xmpp_connect_config::userName();
    string passwordStr = xmpp_connect_config::password();
    string userJID = xmpp_connect_config::userJID();

    // No user-name in config. Fall back on default registration (CCF)
    if (userName.size() == 0)
    {
        constructTestUserAuth(TEST_SESSION_GUID, TEST_APP_GUID, userName, passwordStr);
        userJID = userName + "@" + xmpp_connect_config::xmppDomain();
    }

    SecureBuffer password;
    password.write(passwordStr);
    auto scramConfig = SaslScramSha1::Params::create(userName, password);
    auto plainConfig = SaslPlain::Params::create(userName, password);

#ifdef ENABLE_LIBSTROPHE
    XmppConfig config(JabberID(xmpp_connect_config::userJID("NO_PROXY")),
                      xmpp_connect_config::xmppDomain("NO_PROXY"));
#else
    XmppConfig config(JabberID(xmpp_connect_config::userJID()),
                      xmpp_connect_config::xmppDomain());
#endif

    config.requireTLSNegotiation();
    config.setSaslConfig("SCRAM-SHA-1", scramConfig);
    config.setSaslConfig("PLAIN", plainConfig);

#ifndef DISABLE_SUPPORT_XEP0077
    config.requestInBandRegistration();
    auto registrationParams = InBandRegistration::Params::create();
    registrationParams->setRegistrationParam("username", userName);
    registrationParams->setRegistrationParam("password",
            string((const char *)password.get(), password.size()));
    config.setExtensionConfig(InBandRegistration::extensionName(), registrationParams);
#endif

    client = XmppClient::create();
    client->initiateXMPP(config, xmlConnection, streamPromise);

    shared_ptr<IXmppStream> xmppStream;
    try
    {
        xmppStream = streamFuture.get();
        if (xmppStream)
        {
#if __cplusplus>=201103L || defined(_WIN32)
            future_status status = xmppStream->whenNegotiated().wait_for(chrono::seconds(10));
            if (status == future_status::ready)
#else
            bool status = xmppStream->whenNegotiated().wait_for(chrono::seconds(10));
            if (status)
#endif
            {
                try
                {
                    xmppStream->whenNegotiated().get();
                    stream = xmppStream;
                }
                catch (...)
                {}
            }
        }
    }
    catch (...)
    {}

    return;
}

