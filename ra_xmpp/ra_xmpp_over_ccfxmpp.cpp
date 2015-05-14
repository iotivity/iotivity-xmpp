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

#include <xmpp/xmppconfig.h>
#include <xmpp/sasl.h>

#include <connect/proxy.h>

#include "ra_xmpp.h"

using namespace std;
using namespace Iotivity;


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


struct XmppWrappers
{
        static void addWrapper(const void *const wrapper)
        {
            std::lock_guard<std::recursive_mutex> lock(mutex());
            s_wrappers.insert(wrapper);
        }

        static bool isValidWrapper(const void *const wrapper)
        {
            std::lock_guard<std::recursive_mutex> lock(mutex());
            return s_wrappers.find(wrapper) != s_wrappers.end();
        }

        static void removeWrapper(const void *const wrapper)
        {
            std::lock_guard<std::recursive_mutex> lock(mutex());
            s_wrappers.erase(wrapper);
        }

    private:
        static std::recursive_mutex &mutex()
        {
            static std::recursive_mutex s_mutex;
            return s_mutex;
        }
        static std::set<const void *> s_wrappers;
};

std::set<const void *> XmppWrappers::s_wrappers;


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

        void connect(void *const handle, const std::string &host, const std::string &port,
                     const ProxyConfig &proxy, const std::string &userName,
                     const SecureBuffer &password,  InBandRegister inbandRegistrationAction,
                     XMPP_LIB_(connection_callback_t) callback)
        {
#ifdef ENABLE_LIBSTROPHE
            auto xmlConnection = make_shared<XmppStropheConnection>(host, port);
#else
            auto remoteTcp = make_shared<TcpConnection>(host, port, proxy);

            auto xmlConnection = make_shared<XmppConnection>(
                                     static_pointer_cast<IStreamConnection>(remoteTcp));
#endif // ENABLE_LIBSTROPHE

            XmppConfig config;
            config.requireTLSNegotiation();

            config.setSaslConfig("SCRAM-SHA-1", SaslScramSha1::Params::create(userName, password));
            config.setSaslConfig("PLAIN", SaslPlain::Params::create(userName, password));


            auto client = XmppClient::create();

            auto createdFunc =
                [handle, callback](XmppStreamCreatedEvent & e)
            {
                if (e.result().succeeded())
                {
                    //e.stream()->onConnected() += streamConnectedCallback;
                    //e.stream()->onClosed() += streamClosedCallback;
                }
                else
                {
                    XMPP_LIB_(error_code_t) errorCode = translateError(e.result());
                    if (callback.on_connected && XmppWrappers::isValidWrapper(handle))
                    {
                        callback.on_connected(callback.param, errorCode, handle);
                    }
                }
            };

            using StreamCreatedFunc = NotifySyncFunc<XmppStreamCreatedEvent, decltype(createdFunc)>;
            client->onStreamCreated() += make_shared<StreamCreatedFunc>(createdFunc);

            client->initiateXMPP(config, xmlConnection);
        }

        static XMPP_LIB_(error_code_t) translateError(const connect_error &ce)
        {
            XMPP_LIB_(error_code_t) errorCode = XMPP_ERR_FAIL;
            if (ce.errorType() == connect_error::etConnectError())
            {
                switch (ce.errorCode())
                {
                    case connect_error::ecSuccess:
                        errorCode = XMPP_ERR_OK;
                        break;
                    case connect_error::ecTLSNegotiationInProgress:
                    case connect_error::ecStreamResourceNotBound:
                        errorCode = XMPP_ERR_STREAM_NOT_NEGOTIATED;
                        break;
                    case connect_error::ecServerClosedStream:
                    case connect_error::ecSocketClosed:
                        errorCode = XMPP_ERR_SERVER_DISCONNECTED;
                        break;
                    case connect_error::ecNotSupported:
                        errorCode =  XMPP_ERR_FEATURE_NOT_SUPPORTED;
                        break;
                    case connect_error::ecXMLParserError:
                    case connect_error::ecUnknownSID:
                    case connect_error::ecSIDReused:
                    case connect_error::ecQueryIDAlreadySubmitted:
                    case connect_error::ecAttemptToRestartBoundStream:
                        errorCode = XMPP_ERR_INTERNAL_ERROR;
                        break;
                    case connect_error::ecWaitMissing:
                    case connect_error::ecRequestsMissing:
                        errorCode = XMPP_ERR_BOSH_ERROR;
                        break;
                    case connect_error::ecUnableToStartSession:
                    case connect_error::ecInvalidStream:
                    case connect_error::ecUnableToBindUser:
                        errorCode = XMPP_ERR_STREAM_NOT_NEGOTIATED;
                        break;
                    case connect_error::ecInvalidPort:
                        errorCode = XMPP_ERR_HOST_CONNECTION_FAILED;
                        break;
                    case connect_error::ecHostNameTooLongForSOCKS5:
                    case connect_error::ecUnknownSOCKS5AddressType:
                    case connect_error::ecUserNameTooLongForSOCKS5:
                    case connect_error::ecPasswordTooLongForSOCKS5:
                    case connect_error::ecSOCKS5InvalidUserNameOrPassword:
                    case connect_error::ecProxyTypeNotSupported:
                        errorCode = XMPP_ERR_PROXY_CONNECT_ERROR;
                        break;
                    case connect_error::ecTlsNegotationFailure:
                        errorCode = XMPP_ERR_TLS_NEGOTIATION_FAILED;
                        break;
                    case connect_error::ecSaslNegotationFailure:
                    case connect_error::ecSaslNegotationAborted:
                    case connect_error::ecNoSaslMechanism:
                    case connect_error::ecInsecureSaslOverInsecureStream:
                    case connect_error::ecErrorEncodingNonce:
                        errorCode = XMPP_ERR_SASL_NEGOTIATION_FAILED;
                        break;
                    case connect_error::ecRegistrationAlreadyRunning:
                    case connect_error::ecInvalidRegistration:
                        errorCode = XMPP_ERR_INBAND_REGISTRATION_FAILURE;
                        break;
                    case connect_error::ecRequestFailed:
                        errorCode = XMPP_ERR_REQUEST_ERROR_RESPONSE;
                        break;
                    case connect_error::ecExtensionInShutdown:
                        errorCode = XMPP_ERR_STREAM_CLOSING_NOT_AVAILABLE;
                        break;
                    case connect_error::ecSocketConnectError:
                        errorCode = XMPP_ERR_CONNECT_ERROR;
                        break;
                    case connect_error::ecStanzaTranslationError:
                    case connect_error::ecStanzaTooLong:
                        errorCode = XMPP_ERR_INVALID_SERVER_STANZA;
                        break;
                    case connect_error::ecStreamInShutdown:
                    default:
                        break;
                }
            }
            else if (ce.errorType() == connect_error::etCurlError())
            {
                errorCode = XMPP_ERR_BOSH_ERROR;
            }
            else if (ce.errorType() == connect_error::etHttpError())
            {
                errorCode = XMPP_ERR_BOSH_ERROR;
            }
            else if (ce.errorType() == connect_error::etSOCKS5Error())
            {
                errorCode = XMPP_ERR_PROXY_CONNECT_ERROR;
            }
            else if (ce.errorType() == connect_error::etASIOError())
            {
                // Fold any ASIO errors (c++ client only) into a generic connect error.
                errorCode = XMPP_ERR_CONNECT_ERROR;
            }
            return errorCode;
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
            XmppWrappers::addWrapper(wrapper);
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
                ContextWrapper *wrapper = reinterpret_cast<ContextWrapper *>(handle);
                if (XmppWrappers::isValidWrapper(wrapper))
                {
                    XmppWrappers::removeWrapper(wrapper);
                    delete wrapper;
                }
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
            ContextWrapper *wrapper = reinterpret_cast<ContextWrapper *>(handle);

            if (!XmppWrappers::isValidWrapper(wrapper))
            {
                return XMPP_ERR_INVALID_HANDLE;
            }

            string userName;
            if (identity->user_name)
            {
                userName = identity->user_name;
            }

            SecureBuffer password;
            if (identity->password)
            {
                string passStr = identity->password;
                password.setBuffer(passStr.c_str(), passStr.size());
            }

            auto portStr = to_string(host->port);
            auto proxyType = ProxyConfig::ProxyType::ProxyUndefined;
            if (proxy)
            {
                switch (proxy->proxy_type)
                {
                    case XMPP_PROXY_DIRECT_CONNECT:
                        proxyType = ProxyConfig::ProxyType::ProxyUndefined;
                        break;
                    case XMPP_PROXY_SOCKS5:
                        proxyType = ProxyConfig::ProxyType::ProxySOCKS5;
                        break;
                }
            }
            auto &&proxyConfig = proxy ? ProxyConfig(proxy->proxy_host, to_string(proxy->proxy_port),
                                 proxyType) :
                                 ProxyConfig();

            wrapper->connect(handle, host->host, portStr, proxyConfig, userName, password,
                             identity->inband_registration, callback);

            return XMPP_ERR_OK;
        }
        catch (...) {}
        return XMPP_ERR_INTERNAL_ERROR;
    }

} // extern "C"


