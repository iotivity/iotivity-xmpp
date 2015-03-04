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

/// @file ra_xmpp_over_ccfxmpp.cpp

#ifdef _WIN32
#include <SDKDDKVer.h>
#endif


#include <string>
#include <iostream>


#ifdef ENABLE_LIBSTROPHE
#include <xmpp/xmppstrophe.h>
#else
#include <connect/tcpclient.h>
#include <xmpp/xmppclient.h>
#endif

#include <connect/proxy.h>

#include "ra_xmpp.h"

using namespace std;


struct static_init_test
{
        static_init_test()
        {
            m_init_has_run[0] = 'R'; m_init_has_run[1] = 'U';
            m_init_has_run[2] = 'N'; m_init_has_run[3] = '\0';
        }

        // Test for C++ static init. This is intended to fail gracefully even if the static
        // initialization did not run.
        bool has_initalized() const
        {
            return m_init_has_run[0] == 'R' && m_init_has_run[1] == 'U' &&
                   m_init_has_run[2] == 'N';
        }
    private:
        volatile char m_init_has_run[4];
};

static static_init_test s_init_test;


using namespace Iotivity::Xmpp;

struct UserIdentity
{

};

struct ContextWrapper
{
        ContextWrapper()
        {

            /*

            SecureBuffer password;
            password.write("unitTestPassword");
            auto scramConfig = SaslScramSha1::Params::create("unitTestUserName1", password);
            auto plainConfig = SaslPlain::Params::create("unittest", password);

            #ifdef ENABLE_LIBSTROPHE
            XmppConfig config(JabberID("unittest@xmpp.local"), "xmpp.local");
            #else
            XmppConfig config(JabberID(""), "xmpp-dev");
            #endif
            config.requireTLSNegotiation();
            config.setSaslConfig("SCRAM-SHA-1", scramConfig);
            config.setSaslConfig("PLAIN", plainConfig);

            auto client = XmppClient::create();
            ASSERT_NO_THROW(client->initiateXMPP(config, xmlConnection, streamPromise));

            shared_ptr<IXmppStream> xmppStream;
            EXPECT_NO_THROW(xmppStream = streamFuture.get());
            EXPECT_NE(xmppStream, nullptr);
            if (xmppStream)
            {
                cout<< "GOT STREAM FUTURE"<< endl;
                ASSERT_TRUE(xmppStream->whenNegotiated().valid());

                auto status = xmppStream->whenNegotiated().wait_for(chrono::seconds(10));
                EXPECT_EQ(status, future_status::ready);
                if (status==future_status::ready)
                {
                    try
                    {
                        xmppStream->whenNegotiated().get();
                        auto doc = XMLDocument::createEmptyDocument();
                        auto message = doc->createElement("iq");
                        message->setAttribute("type", "get");
                        message->setAttribute("id", xmppStream->getNextID());
                        message->setAttribute("to", "xmpp-dev");

                        auto query = doc->createElement("query");
                        query->setAttribute("xmlns", "http://jabber.org/protocol/disco#info");

                        message->appendChild(query);
                        doc->appendChild(message);

                        promise<void> ready;
                        future<void> readyFuture = ready.get_future();
                        xmppStream->sendQuery(move(message),
                            [&ready](const connect_error &, XMLElement::Ptr)
                            {
                                promise<void> localReady = move(ready);
                                localReady.set_value();
                            });
                        readyFuture.wait_for(chrono::seconds(2));
                    }
                    catch (...)
                    {
                        EXPECT_NO_THROW(throw);
                    }
                }
            }
            */
        }
        ~ContextWrapper()
        {
        }

        void connect(const std::string &host, const std::string &port, const ProxyConfig &proxy)
        {
#ifdef ENABLE_LIBSTROPHE
            auto xmlConnection = make_shared<XmppStropheConnection>(host, port);
#else
            auto remoteTcp = make_shared<TcpConnection>(host, port, proxy);

            auto xmlConnection = make_shared<XmppConnection>(
                                     static_pointer_cast<IStreamConnection>(remoteTcp));
#endif // ENABLE_LIBSTROPHE

            auto streamPromise = make_shared<promise<shared_ptr<IXmppStream>>>();
            auto streamFuture = streamPromise->get_future();

            auto client = XmppClient::create();
            //ASSERT_NO_THROW(client->initiateXMPP(config, xmlConnection, streamPromise));

            shared_ptr<IXmppStream> xmppStream;
            //EXPECT_NO_THROW(xmppStream = streamFuture.get());

        }
    private:
};

extern "C"
{
///////////////////////////////////////////////////////////////////////////////////////////////////
// C Abstraction Interface
///////////////////////////////////////////////////////////////////////////////////////////////////
    void *const xmpp_wrapper_create_wrapper(void)
    {
        // If static-init did not run, we cannot continue. We also can't safely use
        // iostream, so we'll avoid logging the failure here. This might happen if we are executed from
        // within a C-only exe that never executes C++ static init. That is not supported. Note
        // that if you decide to support a log message here, please do not use printf; this library
        // has avoided the overhead of adding printf.
        if (!s_init_test.has_initalized())
        {
            return nullptr;
        }
        try
        {
            ContextWrapper *wrapper = new ContextWrapper;
            return wrapper;
        }
        catch (...) {}
        return nullptr;
    }

    void xmpp_wrapper_destroy_wrapper(void *const handle)
    {
        try
        {
            if (handle)
            {
                // TODO: Test for valid wrapper?
                ContextWrapper *wrapper = reinterpret_cast<ContextWrapper *>(handle);
                delete wrapper;
            }
        }
        catch (...) {}
    }

    XMPP_LIB_(error_code_t) xmpp_wrapper_connect(void *const handle,
            const XMPP_LIB_(host_t) * const host,
            const XMPP_LIB_(identity_t) * const identity,
            const XMPP_LIB_(proxy_t) * const proxy,
            XMPP_LIB_(connection_callback_t) callback)
    {
        if (!handle)
        {
            return XMPP_ERR_INVALID_HANDLE;
        }
        if (!host || !identity)
        {
            return XMPP_ERR_INVALID_PARAMETER;
        }
        try
        {
            // TODO: Test for valid wrapper?
            ContextWrapper *wrapper = reinterpret_cast<ContextWrapper *>(handle);

            auto portStr = to_string(host->port);
            if (proxy)
            {
                auto proxyType = ProxyConfig::ProxyType::ProxyUndefined;
                switch (proxy->proxy_type)
                {
                    case XMPP_PROXY_DIRECT_CONNECT:
                        proxyType = ProxyConfig::ProxyType::ProxyUndefined;
                        break;
                    case XMPP_PROXY_SOCKS5:
                        proxyType = ProxyConfig::ProxyType::ProxySOCKS5;
                        break;
                }
                ProxyConfig proxyConfig(proxy->proxy_host, to_string(proxy->proxy_port), proxyType);
                wrapper->connect(host->host, portStr, proxyConfig);
            }
            else
            {
                ProxyConfig emptyProxy;
                wrapper->connect(host->host, portStr, emptyProxy);
            }
            return XMPP_ERR_OK;
        }
        catch (...) {}
        return XMPP_ERR_INTERNAL_ERROR;
    }

} // extern "C"


