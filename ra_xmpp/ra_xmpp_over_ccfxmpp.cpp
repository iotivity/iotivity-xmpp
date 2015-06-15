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
#include <map>


#ifdef ENABLE_LIBSTROPHE
#include <xmpp/xmppstrophe.h>
#else
#include <connect/tcpclient.h>
#include <xmpp/xmppclient.h>
#endif

#include <xmpp/xmppconfig.h>
#include <xmpp/sasl.h>
#include <xmpp/xmppregister.h>

#include <connect/proxy.h>

#include "ra_xmpp.h"


/// @cond HIDDEN_SYMBOLS
#ifndef _NOEXCEPT
#ifndef _MSC_VER
#define _NOEXCEPT noexcept
#else
#define _NOEXCEPT
#endif
#endif
/// #endcond


using namespace std;
using namespace Iotivity;
using namespace Iotivity::XML;

/// @cond HIDDEN_SYMBOLS

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
        {}

        ~ContextWrapper()
        {}

        void connect(void *const handle, const string &host, const string &port,
                     const ProxyConfig &proxy, const string &userName,
                     const SecureBuffer &password, const string &userJID,
                     const string &xmppDomain, InBandRegister inbandRegistrationAction,
                     xmpp_connection_callback_t callback)
        {
            (void)inbandRegistrationAction;

#ifdef ENABLE_LIBSTROPHE
            auto xmlConnection = make_shared<XmppStropheConnection>(host, port);
#else
            auto remoteTcp = make_shared<TcpConnection>(host, port, proxy);

            auto xmlConnection = make_shared<XmppConnection>(
                                     static_pointer_cast<IStreamConnection>(remoteTcp));
#endif // ENABLE_LIBSTROPHE

            XmppConfig config(JabberID(userJID), xmppDomain);
            config.requireTLSNegotiation();

            config.setSaslConfig("SCRAM-SHA-1", SaslScramSha1::Params::create(userName, password));
            config.setSaslConfig("PLAIN", SaslPlain::Params::create(userName, password));

#ifndef DISABLE_SUPPORT_XEP0077
            if (inbandRegistrationAction != XMPP_NO_IN_BAND_REGISTER)
            {
                config.requestInBandRegistration();
                auto registrationParams = InBandRegistration::Params::create();
                registrationParams->setRegistrationParam("username", userName);
                string passwordStr((const char *)password.get(), password.size());
                registrationParams->setRegistrationParam("password", passwordStr);
                config.setExtensionConfig(InBandRegistration::extensionName(), registrationParams);
            }
#endif
            {
                lock_guard<recursive_mutex> lock(ContextWrapper::mutex());
                ContextWrapper::s_connectionParams[xmlConnection] = {handle, callback};
            }
            {
                lock_guard<recursive_mutex> lock(m_mutex);
                if (!m_client)
                {
                    m_client = XmppClient::create();

                    auto createdFunc =
                        // Note: We don't really need reference capturing, but there is a bug in C++
                        //       4.6 where static functions still require capturing this.
                        [&](XmppStreamCreatedEvent & e)
                    {
                        ConnectionParams params{};
                        {
                            lock_guard<recursive_mutex> lock(ContextWrapper::mutex());
                            auto f = ContextWrapper::s_connectionParams.find(e.remoteServer());
                            if (f == ContextWrapper::s_connectionParams.end())
                            {
                                return;
                            }
                            params = f->second;
                        }

                        auto stream = e.stream();
                        if (e.result().succeeded() && stream)
                        {
                            const void *streamHandle = stream.get();
                            {
                                lock_guard<recursive_mutex> lock(ContextWrapper::mutex());
                                ContextWrapper::s_streamsByHandle[streamHandle] = stream;
                            }

                            auto callback = params.m_callback;
                            auto streamConnectedFunc =
                                // Note: We don't really need reference capturing, but there is a
                                //       bug in C++ 4.6 where static functions still require
                                //       capturing this.
                                [&, stream, streamHandle, callback](XmppConnectedEvent & e)
                            {
                                // Send first presence message
                                postPresence(stream);

                                if (callback.on_connected)
                                {
                                    xmpp_connection_handle_t connectionHandle = {streamHandle};
                                    callback.on_connected(callback.param,
                                                          translateError(e.result()),
                                                          e.boundJID().c_str(),
                                                          connectionHandle);
                                }
                            };
                            typedef NotifySyncFunc<XmppConnectedEvent,
                                  decltype(streamConnectedFunc)> StreamConnectedFunc;
                            stream->onConnected() += make_shared<StreamConnectedFunc>(
                                                         streamConnectedFunc);

                            auto streamClosedFunc =
                                // Note: We don't really need reference capturing, but there is a
                                //       bug in C++ 4.6 where static functions still require
                                //       capturing this.
                                [&, streamHandle, callback](XmppClosedEvent & e)
                            {
                                if (callback.on_disconnected)
                                {
                                    xmpp_connection_handle_t connectionHandle = {streamHandle};
                                    callback.on_disconnected(callback.param,
                                                             translateError(e.result()),
                                                             connectionHandle);
                                }

                                {
                                    lock_guard<recursive_mutex> lock(ContextWrapper::mutex());
                                    ContextWrapper::s_streamsByHandle.erase(streamHandle);
                                }
                            };
                            typedef NotifySyncFunc<XmppClosedEvent,
                                  decltype(streamClosedFunc)> StreamClosedFunc;
                            stream->onClosed() += make_shared<StreamClosedFunc>(streamClosedFunc);
                        }
                        else
                        {
                            xmpp_error_code_t errorCode = translateError(e.result());
                            if (params.m_callback.on_connected && isValidWrapper(params.m_handle))
                            {
                                xmpp_connection_handle_t connectionHandle = {params.m_handle};
                                params.m_callback.on_connected(params.m_callback.param, errorCode,
                                                               nullptr, connectionHandle);
                            }
                        }


                        {
                            lock_guard<recursive_mutex> lock(mutex());
                            ContextWrapper::s_connectionParams.erase(e.remoteServer());
                        }

                    };

                    typedef NotifySyncFunc<XmppStreamCreatedEvent,
                          decltype(createdFunc)> StreamCreatedFunc;
                    m_client->onStreamCreated() += make_shared<StreamCreatedFunc>(createdFunc);
                }
            }

            m_client->initiateXMPP(config, xmlConnection);
        }

        static shared_ptr<IXmppStream> streamByHandle(xmpp_connection_handle_t connection)
        {
            lock_guard<recursive_mutex> lock(mutex());
            auto f = s_streamsByHandle.find(connection.abstract_connection);
            return f != s_streamsByHandle.end() ? f->second.lock() : shared_ptr<IXmppStream>();
        }

        static xmpp_error_code_t translateError(const connect_error &ce) _NOEXCEPT
        {
            xmpp_error_code_t errorCode = XMPP_ERR_FAIL;
            if (ce.succeeded())
            {
                errorCode = XMPP_ERR_OK;
            }
            else if (ce.errorType() == connect_error::etConnectError())
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

        static void *registerMessageCallback(xmpp_connection_handle_t connection,
                                             xmpp_message_callback_t callback)
        {
            shared_ptr<IXmppStream> stream = streamByHandle(connection);
            if (!stream)
            {
                return nullptr;
            }

            // NOTE: We are not attempting to protect against the same connection getting
            //       multiple callbacks registered. If multiple callbacks should be called
            //       on the same connection, the caller has the option of setting them up.
            auto messageCallback = make_shared<MessageHandler>(stream, callback);


            auto streamMessageFunc =
                [callback](XmppMessageEvent & e)
            {
                if (callback.on_received)
                {
                    xmpp_error_code_t errorCode = translateError(e.result());

                    string sender;
                    ByteBuffer messageBuffer;
                    if (e.message() && e.message()->name() == "message")
                    {
                        e.message()->getAttribute("from", sender);

                        // TODO: Sender is ourselves. Handle error code properly.

                        errorCode = XMPP_ERR_INVALID_MESSAGE_FORMAT;
                        for (const auto &child : e.message()->elements())
                        {
                            if (child->name() == "body")
                            {
                                string val = child->value();
                                ByteBuffer encodedBuffer(val.c_str(), val.size());
                                if (ByteBuffer::base64Decode(encodedBuffer, messageBuffer))
                                {
                                    errorCode = XMPP_ERR_OK;
                                    break;
                                }
                            }
                        }

                        callback.on_received(callback.param, errorCode,
                                             sender.size() > 0 ? sender.c_str() : nullptr,
                                             messageBuffer, messageBuffer.size());
                    }
                }
            };
            typedef NotifySyncFunc<XmppMessageEvent,
                  decltype(streamMessageFunc)> StreamMessageFunc;
            stream->onMessage() += make_shared<StreamMessageFunc>(streamMessageFunc);


            {
                lock_guard<recursive_mutex> lock(mutex());
                s_messageHandlers[messageCallback.get()] = messageCallback;
            }
            return messageCallback.get();
        }

        static void unregisterMessageCallback(void *handle)
        {
            lock_guard<recursive_mutex> lock(mutex());
            s_messageHandlers.erase(handle);
        }

        static xmpp_error_code_t sendMessage(void *handle, const std::string &recipient,
                                             const ByteBuffer &tempBuffer,
                                             const void *const originalMessagePtr,
                                             xmpp_transmission_options_t options)
        {
            shared_ptr<MessageHandler> handler;
            {
                lock_guard<recursive_mutex> lock(mutex());
                auto f = s_messageHandlers.find(handle);
                if (f != s_messageHandlers.end())
                {
                    handler = f->second;
                }
            }

            // TODO: Move to IBB implementation?
            if (!handler)
            {
                return XMPP_ERR_INVALID_HANDLE;
            }

            shared_ptr<IXmppStream> stream = handler->m_stream.lock();
            if (!stream)
            {
                return XMPP_ERR_STREAM_ALREADY_CLOSED;
            }

            auto doc = XMLDocument::createEmptyDocument();
            auto message = doc->createElement("message");
            message->setAttribute("type", "chat");
            message->setAttribute("id", stream->getNextID());
            message->setAttribute("to", recipient);

            auto active = doc->createElement("active");
            active->setAttribute("xmlns", "http://jabber.org/protocol/chatstates");

            auto body = doc->createElement("body");
            ByteBuffer encodedBuffer;
            if (ByteBuffer::base64Encode(tempBuffer, encodedBuffer))
            {
                body->setValue(string((const char *)&encodedBuffer[0], encodedBuffer.size()));
            }
            message->appendChild(active);
            message->appendChild(body);
            doc->appendChild(message);

            try
            {
                stream->sendMessage(move(message));
                if (handler->m_callback.on_sent)
                {
                    handler->m_callback.on_sent(handler->m_callback.param, XMPP_ERR_OK,
                                                recipient.c_str(), originalMessagePtr,
                                                tempBuffer.size());
                }
                return XMPP_ERR_OK;
            }
            catch (const connect_error &ce)
            {
                xmpp_error_code_t errorCode = translateError(ce);
                if (handler->m_callback.on_sent)
                {
                    handler->m_callback.on_sent(handler->m_callback.param, errorCode, nullptr,
                                                nullptr, 0);
                }
                return errorCode;
            }
            catch (...)
            {}
            if (handler->m_callback.on_sent)
            {
                handler->m_callback.on_sent(handler->m_callback.param, XMPP_ERR_FAIL, nullptr,
                                            nullptr, 0);
            }

            return XMPP_ERR_FAIL;
        }

        static void addWrapper(const void *const wrapper)
        {
            lock_guard<recursive_mutex> lock(mutex());
            s_wrappers.insert(wrapper);
        }

        static bool isValidWrapper(const void *const wrapper)
        {
            lock_guard<recursive_mutex> lock(mutex());
            return s_wrappers.find(wrapper) != s_wrappers.end();
        }

        static void removeWrapper(const void *const wrapper)
        {
            lock_guard<recursive_mutex> lock(mutex());
            s_wrappers.erase(wrapper);
        }

    protected:
        static recursive_mutex &mutex()
        {
            static recursive_mutex s_mutex;
            return s_mutex;
        }

        static void postPresence(shared_ptr<IXmppStream> stream)
        {
            auto doc = XMLDocument::createEmptyDocument();
            auto presence = doc->createElement("presence");

            auto show = doc->createElement("show");
            show->setValue("chat");

            auto priority = doc->createElement("priority");
            priority->setValue("1");

            presence->appendChild(show);
            presence->appendChild(priority);
            doc->appendChild(presence);

            stream->sendMessage(move(presence));
        }

    private:
        recursive_mutex m_mutex;
        shared_ptr<XmppClient> m_client;

        static set<const void *> s_wrappers;
        typedef map<const void *, weak_ptr<IXmppStream>> StreamHandleMap;
        static StreamHandleMap s_streamsByHandle;

        struct MessageHandler
        {
            MessageHandler(shared_ptr<IXmppStream> stream, xmpp_message_callback_t callback):
                m_stream(stream), m_callback(callback) {}

            weak_ptr<IXmppStream> m_stream;
            xmpp_message_callback_t m_callback;
        };
        typedef map<const void *, shared_ptr<MessageHandler>> MessageHandlerMap;
        static MessageHandlerMap s_messageHandlers;
        struct ConnectionParams
        {
            void *m_handle;
            xmpp_connection_callback_t m_callback;
        };
        typedef map<shared_ptr<IXmppConnection>, ConnectionParams> ConnectParamMap;
        static ConnectParamMap s_connectionParams;

};

set<const void *> ContextWrapper::s_wrappers;
ContextWrapper::StreamHandleMap ContextWrapper::s_streamsByHandle;
ContextWrapper::MessageHandlerMap ContextWrapper::s_messageHandlers;
ContextWrapper::ConnectParamMap ContextWrapper::s_connectionParams;


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
            ContextWrapper::addWrapper(wrapper);
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
                if (ContextWrapper::isValidWrapper(wrapper))
                {
                    ContextWrapper::removeWrapper(wrapper);
                    delete wrapper;
                }
            }
        }
        catch (...) {}
    }

    xmpp_error_code_t xmpp_wrapper_connect(void *const handle,
                                           const xmpp_host_t *const host,
                                           const xmpp_identity_t *const identity,
                                           const xmpp_proxy_t *const proxy,
                                           xmpp_connection_callback_t callback)
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

            if (!ContextWrapper::isValidWrapper(wrapper))
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

            string userJID;
            if (identity->user_jid)
            {
                userJID = identity->user_jid;
            }

            string hostStr;
            if (host->host)
            {
                hostStr = host->host;
            }

            string xmppDomain;
            if (host->xmpp_domain)
            {
                xmppDomain = host->xmpp_domain;
            }
            else
            {
                xmppDomain = hostStr;
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
                    case XMPP_PROXY_HTTP:
                        proxyType = ProxyConfig::ProxyType::ProxyHTTP;
                        break;
                }
            }
            auto &&proxyConfig = proxy ? ProxyConfig(proxy->proxy_host, to_string(proxy->proxy_port),
                                 proxyType) :
                                 ProxyConfig();

            wrapper->connect(handle, hostStr, portStr, proxyConfig, userName, password,
                             userJID, xmppDomain, identity->inband_registration, callback);

            return XMPP_ERR_OK;
        }
        catch (const connect_error &ce)
        {
            return ContextWrapper::translateError(ce);
        }
        catch (...) {}
        return XMPP_ERR_INTERNAL_ERROR;
    }


    xmpp_error_code_t xmpp_wrapper_disconnect(xmpp_connection_handle_t connection)
    {
        if (!connection.abstract_connection)
        {
            return XMPP_ERR_INVALID_HANDLE;
        }
        try
        {
            shared_ptr<IXmppStream> stream = ContextWrapper::streamByHandle(connection);
            if (!stream)
            {
                return XMPP_ERR_INVALID_HANDLE;
            }
            stream->close();
            return XMPP_ERR_OK;
        }
        catch (const connect_error &ce)
        {
            return ContextWrapper::translateError(ce);
        }
        catch (...) {}

        return XMPP_ERR_INTERNAL_ERROR;
    }

    void *xmpp_wrapper_register_message_callback(xmpp_connection_handle_t connection,
            xmpp_message_callback_t callback)
    {
        try
        {
            return ContextWrapper::registerMessageCallback(connection, callback);
        }
        catch (...) {}
        return NULL;
    }

    void xmpp_wrapper_unregister_message_callback(void *handle)
    {
        if (!handle)
        {
            return;
        }
        try
        {
            ContextWrapper::unregisterMessageCallback(handle);
        }
        catch (...) {}
    }

    xmpp_error_code_t xmpp_wrapper_send_message(void *handle,
            const char *const recipient,
            const void *const message,
            const size_t sizeInOctets,
            xmpp_transmission_options_t options)
    {
        if (!handle)
        {
            return XMPP_ERR_INVALID_HANDLE;
        }
        if (!recipient || (!message && sizeInOctets > 0))
        {
            return XMPP_ERR_INVALID_PARAMETER;
        }
        try
        {
            string recipientStr;
            if (recipient)
            {
                recipientStr = recipient;
            }

            // A copy of the buffer is made here to avoid having the next layer up retain the
            // data buffer past the call. If optimization is desired (and messages are large),
            // consider having this layer provide the buffers to use on demand instead of relying
            // on the lifespan of the buffer at the next layer up.
            ByteBuffer tempBuffer(message, sizeInOctets);

            return ContextWrapper::sendMessage(handle, recipientStr, tempBuffer, message, options);
        }
        catch (const connect_error &ce)
        {
            return ContextWrapper::translateError(ce);
        }
        catch (...) {}
        return XMPP_ERR_INTERNAL_ERROR;
    }


} // extern "C"

/// @endcond

