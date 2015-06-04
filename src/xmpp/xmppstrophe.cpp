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

/// @file xmppstrohe.cpp

#include "stdafx.h"

#include "xmppstrophe.h"

#ifndef DISABLE_SUPPORT_LIBSTROPHE

#include "../xmpp/xmppconfig.h"
#include "../xmpp/xmppstream.h"
#include "../common/logstream.h"
#include "../connect/connecterror.h"
#include "../xmpp/jabberid.h"
#include "../common//bufferencrypt.h"

#include "strophe.h"

#include <set>
#include <thread>

using namespace std;
using namespace Iotivity::XML;

// Declare missing features from the strophe.h file.
extern "C"
{
    extern int xmpp_stanza_get_attribute_count(xmpp_stanza_t *const stanza);
    extern int xmpp_stanza_get_attributes(xmpp_stanza_t *const stanza, const char **attr,
                                          int attrlen);

}

namespace Iotivity
{
    namespace Xmpp
    {
        static XMLElement::Ptr convertStanzaToXml(XML::XMLDocument::Ptr &document,
                _xmpp_stanza_t *const stanza)
        {
            XMLElement::Ptr element;
            if (document && stanza && xmpp_stanza_is_tag(stanza))
            {
                element = document->createElement(xmpp_stanza_get_name(stanza));
                if (element)
                {
                    int attributeCount = xmpp_stanza_get_attribute_count(stanza);
                    if (attributeCount > 0)
                    {
                        const char **attrArray = new const char *[2 * attributeCount];
                        for (int i = 0; i < 2 * attributeCount; ++i)
                        {
                            attrArray[i] = nullptr;
                        }
                        xmpp_stanza_get_attributes(stanza, attrArray, 2 * attributeCount);
                        for (int i = 0; i < 2 * attributeCount; i += 2)
                        {
                            const char *name = attrArray[i];
                            const char *val = attrArray[i + 1];
                            if (name && val)
                            {
                                element->setAttribute(name, val);
                            }
                        }

                        delete attrArray;
                    }

                    _xmpp_stanza_t *next = xmpp_stanza_get_children(stanza);
                    while (next)
                    {
                        if (xmpp_stanza_is_text(next))
                        {
                            element->setValue(xmpp_stanza_get_text(next));
                        }
                        else if (xmpp_stanza_is_tag(next))
                        {
                            XMLElement::Ptr childElement = convertStanzaToXml(document, next);
                            if (childElement)
                            {
                                element->appendChild(childElement);
                            }
                        }

                        next = xmpp_stanza_get_next(next);
                    }
                }
            }
            return element;
        }

        struct StanzaDeleter
        {
            void operator()(_xmpp_stanza_t *stanza) { xmpp_stanza_release(stanza); }
        };
        typedef std::unique_ptr<_xmpp_stanza_t, StanzaDeleter> StanzaPtr;

        static StanzaPtr convertXmlToStanza(const XML::XMLElement::Ptr &element, _xmpp_ctx_t *ctx)
        {
            // NOTE: We are ignoring namespace features here for simplicitly. If they turn out to
            //       be needed, add them.
            if (element && ctx)
            {
                _xmpp_stanza_t *stanzaPtr = xmpp_stanza_new(ctx);
                if (stanzaPtr)
                {
                    StanzaPtr stanza(stanzaPtr);

                    string val = element->value();
                    if (val.size() > 0)
                    {
                        _xmpp_stanza_t *textStanza = xmpp_stanza_new(ctx);
                        if (textStanza)
                        {
                            if (xmpp_stanza_set_text_with_size(textStanza, val.c_str(),
                                                               val.size()) != XMPP_EOK)
                            {
                                return StanzaPtr();
                            }

                            if (xmpp_stanza_add_child(stanza.get(), textStanza) != XMPP_EOK)
                            {
                                xmpp_stanza_release(textStanza);
                                return StanzaPtr();
                            }
                            xmpp_stanza_release(textStanza);
                        }
                        else
                        {
                            return StanzaPtr();
                        }
                    }

                    if (xmpp_stanza_set_name(stanza.get(), element->name().c_str()) != XMPP_EOK)
                    {
                        return StanzaPtr();
                    }

                    for (const auto &attr : element->attributes())
                    {
                        if (xmpp_stanza_set_attribute(stanza.get(), attr->name().c_str(),
                                                      attr->value().c_str()) != XMPP_EOK)
                        {
                            return StanzaPtr();
                        }
                    }
                    for (const auto &subElement : element->elements())
                    {
                        StanzaPtr subStanza = convertXmlToStanza(subElement, ctx);
                        if (subStanza)
                        {
                            // get() not release(), xmpp_stanza_add_child makes a copy.
                            if (xmpp_stanza_add_child(stanza.get(), subStanza.get()) != XMPP_EOK)
                            {
                                return StanzaPtr();
                            }
                        }
                        else
                        {
                            return StanzaPtr();
                        }
                    }
                    return stanza;
                }
            }
            return StanzaPtr();
        }


        class XmppStropheStream: public XmppStreamBase
        {
            public:
                XmppStropheStream(const XmppConfig &config,
                                  shared_ptr<XmppStropheConnection> remoteServer,
                                  XmppStropheClient::XmppStreamPromise xmppConnection):
                    m_negotiatedPromise(), m_negotiated(m_negotiatedPromise.get_future()),
                    m_boundPromise(), m_bound(m_boundPromise.get_future()),
                    m_config(config), m_remoteConnection(remoteServer)
                {
                    if (!m_remoteConnection)
                    {
                        throw new connect_error(LocalError(LocalError::ecInvalidParameter));
                    }
                }


                virtual ~XmppStropheStream() _NOEXCEPT
                {
                    try
                    {
                        close();
                    }
                    catch (...) {}
                }

                void client_connected(const JabberID &boundID)
                {
                    m_negotiatedPromise.set_value();
                    if (boundID.full().size() > 0)
                    {
                        m_boundPromise.set_value(boundID);
                    }
                }

                virtual void close()
                {
                    m_remoteConnection->close();
                }

                virtual void handleXML(XMLElement::Ptr payload)
                {
                    if (payload)
                    {
                        WITH_LOG_INFO( dout << "INCOMING XML: " << payload->xml() << endl; )
                        XmppStreamBase::handleMessage(move(payload));
                    }
                }

                virtual shared_future<void> &whenNegotiated() override { return m_negotiated; }

                virtual shared_future<JabberID> &whenBound() override { return m_bound; }

                virtual void sendStanza(XMLDocument::Ptr stanza) override
                {
                    if (stanza && m_remoteConnection)
                    {
                        m_remoteConnection->async_send(stanza, IXmlConnection::SendCallback());
                    }
                }

                virtual JabberID boundResource() const override
                {
                    if (m_remoteConnection)
                    {
                        return m_remoteConnection->getBoundJID();
                    }
                    else
                    {
                        return JabberID();
                    }
                }

            private:
                promise<void> m_negotiatedPromise;
                shared_future<void> m_negotiated;

                promise<JabberID> m_boundPromise;
                shared_future<JabberID> m_bound;

                XmppConfig m_config;
                shared_ptr<XmppStropheConnection> m_remoteConnection;
        };


        //////////
        XmppStropheConnection::XmppStropheConnection(const string &host, const string &port):
            m_owner(), m_mutex(), m_ctx(nullptr), m_conn(nullptr), m_host(host), m_port(0),
            m_stream(), m_sendMutex()
        {
            m_port = static_cast<unsigned short>(strtoull(port.c_str(), nullptr, 10));
        }

        XmppStropheConnection::~XmppStropheConnection()
        {
            close();
        }


        void XmppStropheConnection::handleStanza(_xmpp_stanza_t *const stanza) const
        {
            if (stanza)
            {
                XMLDocument::Ptr doc = XMLDocument::createEmptyDocument();
                XMLElement::Ptr element = convertStanzaToXml(doc, stanza);
                if (element && m_stream)
                {
                    m_stream->handleXML(move(element));
                }
                else
                {
                    // TODO: LOG
                }
            }
        }

        void XmppStropheConnection::connect()
        {
            int result = -1;
            if (m_conn)
            {

                struct call_context
                {
                    call_context(XmppStropheConnection *const self): m_self(self) {}

                    promise<void> m_connectPromise;
                    XmppStropheConnection *const m_self;
                } *context = new call_context(this);

                auto connected = context->m_connectPromise.get_future();

                result = xmpp_connect_client(m_conn, m_host.c_str(), m_port,
                                             [](xmpp_conn_t *const conn, const xmpp_conn_event_t event, const int error,
                                                xmpp_stream_error_t *const stream_error, void *const userdata)
                {
                    if (!userdata)
                    {
                        return;
                    }
                    auto *context = reinterpret_cast<call_context *>(userdata);

                    if (!context->m_self || !context->m_self->m_stream)
                    {
                        return;
                    }

                    shared_ptr<IXmppStream> stream = context->m_self->m_stream;

                    switch (event)
                    {
                        case XMPP_CONN_CONNECT:
                            try
                            {
                                WITH_LOG_INFO
                                (
                                    dout << "CONNECT: EVENT: " << event <<
                                    " ERROR: " << error << endl;
                                )

                                if (error != XMPP_EOK)
                                {
                                    // TODO: Improve connect error management here
                                    connect_error errorCode = connect_error::ecInvalidStream;
                                    stream->onConnected().fire(XmppConnectedEvent(
                                                                   connect_error::ecInvalidStream));
                                    throw errorCode;
                                }

                                xmpp_handler_add(conn,
                                                 [](xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
                                                    void *const userdata) -> int
                                {
                                    (void)conn;
                                    (void)stanza;
                                    if (conn && stanza && userdata)
                                    {
                                        try
                                        {
                                            XmppStropheConnection *const self =
                                            reinterpret_cast<XmppStropheConnection *>(
                                                userdata);

                                            self->handleStanza(stanza);
                                        }
                                        catch (...)
                                        {
                                            // C routine. No exception may leave
                                            // this callback.
                                        }
                                    }
                                    // TODO: destructor synchronization

                                    return 1;
                                }, nullptr, nullptr, nullptr, context->m_self);

                                stream->onConnected().fire(XmppConnectedEvent(
                                                               connect_error::SUCCESS,
                                                               getBoundJID()
                                                           ));
                                context->m_connectPromise.set_value();
                            }
                            catch (...)
                            {
                                // C call-chain. Catch all exceptions.
                                if (context)
                                {
                                    try
                                    {
                                        stream->onConnected().fire(XmppConnectedEvent(
                                                                       connect_error::ecInvalidStream));
                                        context->m_connectPromise.set_exception(
                                            current_exception());
                                    }
                                    catch (...) {}
                                }
                            }
                            break;
                        case XMPP_CONN_DISCONNECT:
                            try
                            {
                                WITH_LOG_INFO
                                (
                                    dout << "DISCONNECT: EVENT: " << event <<
                                    " ERROR: " << error << endl;
                                )

                                stream->onClosed().fire(XmppClosedEvent(
                                                            connect_error::SUCCESS));
                            }
                            catch (...) {}
                            break;
                        case XMPP_CONN_FAIL:
                            try
                            {
                                // This does not appear to be sent by any existing libstrophe
                                // component, so it is not clear what it is meant to do. We
                                // will log receipt but ignore it.
                                WITH_LOG_WARNINGS
                                (
                                    dout << "XMPP_CONN_FAIL Received. Unexpected. [IGNORED]" << endl;
                                )
                            }
                            catch (...) {}
                            break;
                    }

                    try
                    {
                        // We do not expect an exception from this delete, but let's
                        // not take chances.
                        delete context;
                    }
                    catch (...) {}
                }, context);

                if (result != XMPP_EOK)
                {
                    delete context;
                }

                // Let any exception filter up.
                connected.get();
            }
            if (result != XMPP_EOK)
            {
                throw connect_error(connect_error::ecSocketConnectError);
            }
        }

        void XmppStropheConnection::close()
        {
            if (m_conn)
            {
                xmpp_disconnect(m_conn);

                // TODO: Wait for disconnect to stream.

                if (m_stream)
                {
                    m_stream->onClosed().fire(XmppClosedEvent(connect_error::SUCCESS));
                }

                lock_guard<recursive_mutex> lock(m_mutex);
                xmpp_conn_release(m_conn);
                m_conn = nullptr;
            }
        }

        void XmppStropheConnection::send(XML::XMLDocument::Ptr payload)
        {
            promise<connect_error> promiseResult;
            auto future = promiseResult.get_future();
            async_send(payload,
                       [&promiseResult](connect_error ec)
            {
                promise<connect_error> localPromiseResult = move(promiseResult);
                localPromiseResult.set_value(ec);
            });

            connect_error result = future.get();
            if (!result.succeeded())
            {
                throw result;
            }
        }

        void XmppStropheConnection::receive(XML::XMLElement::Ptr &payload)
        {
            (void)payload;
            if (m_conn)
            {
            }
            // TODO: throw not supported
        }

        void XmppStropheConnection::async_receive(ReceiveCallback receiveComplete)
        {
            (void)receiveComplete;
            // TODO: throw not supported
        }

        void XmppStropheConnection::async_send(XML::XMLDocument::Ptr payload,
                                               SendCallback sendCallback)
        {
            if (m_conn)
            {
                auto stanza = convertXmlToStanza(payload->documentElement(), m_ctx);
                if (stanza)
                {
                    lock_guard<recursive_mutex> lock(m_sendMutex);
                    xmpp_send(m_conn, stanza.get());
                }
                else
                {
                    if (sendCallback) sendCallback(connect_error::ecStanzaTranslationError);
                }
            }
            else
            {
                if (sendCallback) sendCallback(connect_error::ecInvalidStream);
            }
        }

        void XmppStropheConnection::negotiateTLS(TLSCallback callback)
        {
            // NO-OP libstrophe handles this internally.
            if (callback) callback(connect_error::SUCCESS);
        }

        void XmppStropheConnection::restartStream()
        {
            // NO-OP libstrophe handles this internally.
        }

        void XmppStropheConnection::useContext(shared_ptr<IXmppClient> owner, xmpp_ctx_t *context,
                                               const XmppConfig &config,
                                               shared_ptr<IXmppStream> stream)
        {
            lock_guard<recursive_mutex> lock(m_mutex);
            m_owner = owner;
            m_stream = stream;
            if (context != m_ctx)
            {
                m_ctx = context;
                if (m_ctx && !m_conn)
                {
                    m_conn = xmpp_conn_new(m_ctx);
                    if (m_conn)
                    {
                        JabberID initiator = config.initiator();

                        // Grab the userName/password from the SASL config if available
                        auto saslParam = config.saslConfig("PLAIN");
                        if (!saslParam)
                        {
                            saslParam = config.saslConfig("SCRAM-SHA-1");
                        }

                        SecureBuffer password;
                        if (saslParam)
                        {
                            if (initiator.full().size() == 0)
                            {
                                // TODO: Update JID class to help with this...
                                initiator = saslParam->authenticationIdentity() + "@" + config.host();
                            }
                            password = saslParam->password();
                        }

                        xmpp_conn_set_jid(m_conn, initiator.full().c_str());
                        if (password.size() > 0)
                        {
                            password.write("", 1);
                            xmpp_conn_set_pass(m_conn, (const char *)&password[0]);
                        }
                    }
                }
                else if (!m_ctx && m_conn)
                {
                    close();
                }
            }
        }

        JabberID XmppStropheConnection::getBoundJID() const
        {
            lock_guard<recursive_mutex> lock(m_mutex);
            if (m_conn)
            {
                return JabberID(xmpp_conn_get_bound_jid(m_conn));
            }
            return JabberID("");
        }


        //////////

        /// @cond HIDDEN_SYMBOLS
        // Private implementation details for the XmppClient class to avoid DLL export issues.
        struct XmppClientPimpl
        {
            XmppClientPimpl():
                m_mutex(), m_ctx(nullptr), m_streams(), m_runStopPromise(),
                m_runStopped(m_runStopPromise.get_future()),
                m_streamCreated(m_mutex)
            {}

            recursive_mutex m_mutex;
            xmpp_ctx_t *m_ctx;
            set<shared_ptr<IXmppStream>> m_streams;
            promise<void> m_runStopPromise;
            future<void> m_runStopped;
            SyncEvent<XmppStreamCreatedEvent> m_streamCreated;
        };
        /// @endcond

        void XmppClientPimplDelete::operator()(XmppClientPimpl *p) { delete p; }



        //////////
        void logstream_redirect(void *const userdata, const xmpp_log_level_t level,
                                const char *const area, const char *const msg)
        {
            if (!area || !msg) return;

            switch (level)
            {
                case XMPP_LEVEL_DEBUG:
                    WITH_LOG_ENTRYEXIT
                    (
                        dout << area << ": " << msg << endl;
                    )
                    break;
                case XMPP_LEVEL_INFO:
                    WITH_LOG_INFO
                    (
                        dout << area << ": " << msg << endl;
                    )
                    break;
                case XMPP_LEVEL_WARN:
                    WITH_LOG_WARNINGS
                    (
                        dout << area << ": " << msg << endl;
                    )
                    break;
                case XMPP_LEVEL_ERROR:
                    WITH_LOG_ERRORS
                    (
                        dout << area << ": " << msg << endl;
                    )
                    break;
                default:
                    WITH_LOG_CRITICALS
                    (
                        dout << area << ": " << msg << endl;
                    )
                    break;
            }
        }

        shared_ptr<XmppStropheClient> XmppStropheClient::create()
        {
            return shared_ptr<XmppStropheClient>(new XmppStropheClient);
        }

        XmppStropheClient::XmppStropheClient():
            p_(new XmppClientPimpl)
        {
            xmpp_initialize();

            static const _xmpp_log_t logstream_log{&logstream_redirect, nullptr};

            // Select default memory handler and redirect to logstream logger.
            p_->m_ctx = xmpp_ctx_new(nullptr, &logstream_log);

            thread([this]()
            {
                xmpp_run(p_->m_ctx);
                try
                {
                    p_->m_runStopPromise.set_value();
                }
                catch (...) {}
            }).detach();

        }

        XmppStropheClient::~XmppStropheClient()
        {
            for (auto i : p_->m_streams)
            {
                try
                {
                    i->close();
                }
                catch (...)
                {}
            }

            xmpp_stop(p_->m_ctx);

            p_->m_runStopped.get();
            xmpp_ctx_free(p_->m_ctx);
            xmpp_shutdown();
        }

        SyncEvent<XmppStreamCreatedEvent> &XmppStropheClient::onStreamCreated()
        {
            return p_->m_streamCreated;
        }

        void XmppStropheClient::initiateXMPP(const XmppConfig &config,
                                             shared_ptr<XmppStropheConnection> remoteServer,
                                             XmppStreamPromise xmppConnection)
        {
            try
            {
                (void)config;
                if (remoteServer)
                {

                    auto stream = make_shared<XmppStropheStream>(config, remoteServer,
                                  xmppConnection);
                    {
                        lock_guard<recursive_mutex> lock(p_->m_mutex);
                        p_->m_streams.insert(stream);
                    }

                    onStreamCreated().fire(XmppStreamCreatedEvent(stream, remoteServer));

                    remoteServer->useContext(shared_from_this(), p_->m_ctx, config, stream);

                    auto runConnect = async(launch::async,
                                            [remoteServer, xmppConnection, stream]()
                    {
                        try
                        {
                            remoteServer->connect();
                            if (xmppConnection)
                            {
                                xmppConnection->set_value(stream);
                            }

                            stream->client_connected(remoteServer->getBoundJID());
                        }
                        catch (...)
                        {
                            // TODO: 'this' is not captured as we don't have a strong
                            //       lifespan guarantee here. We will 'leak' a stream
                            //       instance into p_->m_streams if we make it to this
                            //       location.
                            if (xmppConnection)
                            {
                                xmppConnection->set_exception(current_exception());
                            }
                        }
                    });

                }
                else
                {
                    throw connect_error(LocalError(LocalError::ecInvalidParameter));
                }
            }
            catch (...)
            {
                if (xmppConnection)
                {
                    xmppConnection->set_exception(current_exception());
                }
            }
        }
    }
}

#endif // DISABLE_SUPPORT_LIBSTROPHE


