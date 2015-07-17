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

/// @file xmppclient.cpp

#include "stdafx.h"

#include "xmppclient.h"

#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT

#include "sasl.h"
#include "../xml/portabledom.h"
#include "../common/str_helpers.h"
#include "../common/buffers.h"
#include "../common/logstream.h"
#include "../xmpp/xmppstream.h"
#include "../xmpp/xmppregister.h"
#include "../xmpp/xmppconfig.h"
#include "../xmpp/jabberid.h"


// TOOD: Move interface when refactoring for BOSH 'streams'
#include "../connect/tcpclient.h"

#include <iostream>




/// @mainpage Iotivity XMPP Client
///
/// @section intro Introduction
///
/// The Iotivity XMPP Client is a basic C++ XMPP client implementation written to provide
/// cross-platform support for XMPP for Iotivity and the CCF project.
///
/// @section XMPP Support
///
/// <ul>
///     <li>RFC 6120 (XMPP Core)</li>
///     <li>SASL
///         <ul>
///             <li>RFC 4616 (PLAIN)</li>
///         </ul>
///     </li>
///     <li>XMPP Extensions
///         <ul>
///             <li>XEP-0077 (In-Band Registration)</li>
///             <li>XEP-0030 (Service-Discovery) [Basic queries only]</li>
///             <li>XEP-0199 (XMPP Ping) [Timer-based ping/pong still a WIP]</li>
///        </ul>
///     </li>
/// </ul>



/// @addtogroup XMPP
/// @{
/// Create and start an XMPP client:
/// @code
///
/// #include <xmpp/xmppclient.h>
/// #include <xmpp/sasl.h>
/// #include <connect/tcpclient.h>
/// #include <connect/proxy.h>
///
/// using namespace Iotivity;
/// using namespace Iotivity::Xmpp;
///
/// ProxyConfig proxy(PROXY_HOST, PROXY_PORT, PROXY_TYPE);
///
/// auto remoteTcp = make_shared<TcpConnection>(XMPP_HOST_NAME, XMPP_HOST_PORT, proxy);
///
/// // Set up XMPP configuration
/// XmppConfig config(FROM_JABBERID, TO_HOST);
///
/// // TLS is required for PLAIN SASL support (if the server does not require TLS).
/// config.requireTLSNegotiation();
///
/// // Set up parameters to Sasl (PLAIN)
/// SecureBuffer password;
/// password.write("UserPassword");
/// auto plainConfig = SaslPlain::Params::create("UserName", password);
///
/// config.setSaslConfig("PLAIN", plainConfig);
///
/// try
/// {
///     // Wrap the stream connection into an XmppConnection (XmppConnection can also use a BOSH connection)
///     auto xmlConnection = make_shared<XmppConnection>(static_pointer_cast<IStreamConnection>(remoteTcp));
///
///     auto client = XmppClient::create();
///
///     // Pass in a promise get the IXmppStream when it is ready.
///     auto streamPromise = make_shared<promise<shared_ptr<IXmppStream>>>();
///
///     client->initiateXMPP(config, xmlConnection, streamPromise);
///
///     // get() will throw on connect error
///     auto xmppStream = streamPromise->get_future().get();
///
///     // get() will throw on stream-negotiation error
///     auto status = xmppStream->whenNegotiated().get();
/// }
/// catch (const connect_error &)
/// {
///     // Handle connection errors here.
/// }
/// catch (...)
/// {}
///
/// @endcode
/// @}



using namespace std;
using namespace Iotivity;
using namespace Iotivity::XML;

namespace Iotivity
{
    namespace Xmpp
    {
#ifdef USE_ID_HEADER
        static const string ID_HEADER = "IoT";
#endif
        static const size_t DEFAULT_TEMP_BUFFER_SIZE = 4096;
        static const size_t DEFAULT_ABSOLUTE_MAX_STANZA_SIZE = (0x1 << 22) - 4096; // ~ 4MB
        static const string XMPP_STREAMS_NAMESPACE = "urn:ietf:params:xml:ns:xmpp-streams";
        static const string XMPP_TLS_NAMESPACE = "urn:ietf:params:xml:ns:xmpp-tls";
        static const string XMPP_SASL_NAMESPACE = "urn:ietf:params:xml:ns:xmpp-sasl";
        static const string XMPP_BIND_NAMESPACE = "urn:ietf:params:xml:ns:xmpp-bind";
        static const string XMPP_SESSION_NAMESPACE = "urn:ietf:params:xml:ns:xmpp-session";
        static const string XMPP_REGISTER_NAMESPACE = "http://jabber.org/features/iq-register";

        //////////
        XmppConnection::XmppConnection(shared_ptr<IStreamConnection> streamConnection):
            m_mutex(), m_closed(false), m_streamConnection(streamConnection),
            m_restartPending(true), m_workingBuffer(make_shared<StreamBuffer>())
        {}

        XmppConnection::~XmppConnection() _NOEXCEPT
        {
            try
            {
                close();
            }
            catch (...) {}
        }

        void XmppConnection::connect()
        {
            if (m_streamConnection)
            {
                m_streamConnection->connect();
            }
            else
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
        }

        void XmppConnection::close()
        {
            if (m_streamConnection)
            {
                bool closed;
                {
                    lock_guard<recursive_mutex> lock(m_mutex);
                    closed = m_closed;
                    m_closed = true;
                }
                if (!closed)
                {
                    WITH_LOG_INFO
                    (
                        dout << "CLOSING" << endl;
                    )
                    try
                    {
                        string payloadStr = "</stream:stream>";

                        WITH_LOG_WRITES
                        (
                            dout << payloadStr << endl;
                        )

                        m_streamConnection->send(ByteBuffer(&payloadStr[0], payloadStr.size()));
                    }
                    catch (...) {}
                    try
                    {
                        m_streamConnection->close();
                    }
                    catch (...) {}
                }
            }
            else
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
        }

        void XmppConnection::send(XMLDocument::Ptr payload)
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

        //  const static size_t DEFAULT_BUFFER_SIZE = 4096;

        void XmppConnection::receive(XMLElement::Ptr &payload)
        {
            promise<connect_error> promiseResult;
            auto future = promiseResult.get_future();
            async_receive(
                [&promiseResult, &payload](connect_error ec, XMLElement::Ptr resultPayload)
            {
                promise<connect_error> localPromiseResult = move(promiseResult);
                if (ec.succeeded())
                {
                    payload = move(resultPayload);
                }
                localPromiseResult.set_value(ec);
            });

            connect_error result = future.get();
            if (!result.succeeded())
            {
                throw result;
            }
        }

        size_t parseStreamOpen(const ByteBuffer &buf, size_t at, size_t bytes,
                               XMLElement::Ptr &element)
        {
            size_t bytesRead = 0;
            if (at < buf.size())
            {
                string tempStr(&((const char *)buf.get())[at], bytes);

                XMLDocument::Ptr tempDoc = XMLDocument::createEmptyDocument();
                if (tempDoc)
                {
                    // We are assuming here that a stream does not start with a CDATA
                    // block so that we can safely count '<' and '>'. We only need
                    // to this for the stream start since the stanzas are well-formed
                    // in the context of the stream 'document'.

                    size_t index = 0, depth = 0;
                    for (const auto c : tempStr)
                    {
                        ++index;
                        if (c == '<')
                        {
                            ++depth;
                            continue;
                        }
                        if (c == '>')
                        {
                            if (depth > 0)
                            {
                                --depth;
                            }
                            if (depth == 0)
                            {
                                try
                                {
                                    static const string tempEnding = "</stream:stream>";

                                    std::string testStr = tempStr.substr(0, index) + tempEnding;
                                    tempDoc->parse(testStr, XMLDocument::EndingTest::IgnoreEnding);

                                    element = tempDoc->documentElement();
                                    bytesRead = index;
                                    break;
                                }
                                catch (const rapidxml::parse_error &)
                                {
                                    // If parsing failed we may have recieved a partial read,
                                    // continue reading.
                                }
                            }
                        }
                    }
                }
            }
            return bytesRead;
        }

        size_t parseStreamNode(const ByteBuffer &buf, size_t at, size_t bytes,
                               XMLElement::Ptr &element)
        {
            size_t bytesRead = 0;
            // TODO: Cache document? How many elements before a new document should
            //       be generated.
            XMLDocument::Ptr tempDoc = XMLDocument::createEmptyDocument();
            if (tempDoc && at < buf.size())
            {
                try
                {
                    XMLNode::Ptr tempNode;
                    bytesRead = tempDoc->parsePartial(buf.slice(at, bytes), tempNode);

                    element.reset(static_cast<XMLElement *>(tempNode.release()));
                }
                catch (const rapidxml::parse_error &)
                {
                    // If parsing failed we may have recieved a partial read, continue
                    // reading.

                    // TODO: bad-format after how much has been read?
                }
            }
            return bytesRead;
        }

        size_t XmppConnection::parseStanza(const ByteBuffer &buffer, size_t at, size_t forBytes,
                                           XML::XMLElement::Ptr &streamElement)
        {
            size_t consumed = 0;
            const auto *buf = (const unsigned char *)buffer;
            if (m_restartPending || (buf[0] == '<' && buf[1] == '?'))
            {
                consumed = parseStreamOpen(buffer, at, forBytes, streamElement);

                if (consumed > 0)
                {
                    // Restart is not complete here, but it is no longer pending
                    m_restartPending = false;
                }
            }
            else
            {
                consumed = parseStreamNode(buffer, at, forBytes, streamElement);
            }
            return consumed;
        }

        void XmppConnection::async_receive(ReceiveCallback receiveComplete)
        {
            if (m_streamConnection)
            {
                auto tempBuffer = make_shared<ByteBuffer>(DEFAULT_TEMP_BUFFER_SIZE);
                auto streamReceivedData =
                    [this, tempBuffer, receiveComplete]
                    (const connect_error & ec, size_t bytesRead)
                {
                    if (ec.succeeded())
                    {
                        if (m_workingBuffer->size() + bytesRead > DEFAULT_ABSOLUTE_MAX_STANZA_SIZE)
                        {
                            WITH_LOG_CRITICALS
                            (
                                // Unexpected error condition
                                dout << "Stanza Exceeded Absolute Max Size" << endl;
                            )
                            close();
                            throw connect_error(connect_error::ecStanzaTooLong);
                        }
                        m_workingBuffer->write(tempBuffer->get(), bytesRead);

                        XMLElement::Ptr streamElement;
                        size_t consumed;

                        bool receiveCompleteCalled = false;
                        do
                        {
                            consumed = parseStanza(*m_workingBuffer, 0,
                                                   m_workingBuffer->size(), streamElement);

                            if (consumed > 0)
                            {
                                m_workingBuffer->shiftTowardsOrigin(consumed);
                                m_workingBuffer->reserve(m_workingBuffer->size() - consumed);
                                if (receiveComplete)
                                {
                                    // Don't move this call into the call to receiveComplete;
                                    // the code may execute move(streamElement) first.
                                    connect_error okay = streamElement ?
                                                         connect_error::SUCCESS :
                                                         LocalError(LocalError::ecOutOfMemory);
                                    receiveComplete(okay, move(streamElement));
                                    receiveCompleteCalled = true;
                                }
                            }
                        }
                        while (consumed > 0 && m_workingBuffer->size() > 0);

                        if (!receiveCompleteCalled)
                        {
                            std::function<void(const connect_error &ec, size_t bytesRead)>
                            continueRead =
                                [this, tempBuffer, receiveComplete]
                                (const connect_error & ec, size_t bytesRead)
                            {
                                bool receiveCompleteCalled = false;
                                if (ec.succeeded())
                                {
                                    m_workingBuffer->write(tempBuffer->get(), bytesRead);

                                    XMLElement::Ptr streamElement;
                                    size_t consumed;

                                    do
                                    {
                                        consumed = parseStanza(*m_workingBuffer, 0,
                                                               m_workingBuffer->size(),
                                                               streamElement);
                                        if (consumed > 0)
                                        {
                                            m_workingBuffer->shiftTowardsOrigin(consumed);
                                            m_workingBuffer->reserve(
                                                m_workingBuffer->size() - consumed);
                                            if (receiveComplete)
                                            {
                                                // Don't move this call into the call
                                                // to receiveComplete; the code may
                                                // execute move(streamElement) first.
                                                connect_error okay = streamElement ?
                                                                     connect_error::SUCCESS :
                                                                     LocalError(LocalError::ecOutOfMemory);

                                                receiveComplete(okay, move(streamElement));
                                            }
                                            receiveCompleteCalled = true;
                                        }
                                    }
                                    while (consumed > 0 && m_workingBuffer->size() > 0);
                                }
                                else
                                {
                                    if (receiveComplete)
                                    {
                                        receiveComplete(ec, XMLElement::Ptr());
                                    }
                                    receiveCompleteCalled = true;
                                }
                                if (!receiveCompleteCalled)
                                {
                                    this->async_receive(receiveComplete);
                                }
                            };

                            m_streamConnection->async_receive(tempBuffer, continueRead);
                        }
                    }
                    else if (ec == connect_error::ecTLSNegotiationInProgress)
                    {
                        // TODO: Hold for negotiation?
                        WITH_LOG_INFO
                        (
                            dout << "XmppConnection read while TLS negotation in progress" <<
                            endl;
                        )
                    }
                    else
                    {
                        if (receiveComplete) receiveComplete(ec, XMLElement::Ptr());
                    }
                };

                m_streamConnection->async_receive(tempBuffer, streamReceivedData);
            }
            else
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
        }

        void XmppConnection::async_send(XMLDocument::Ptr payload, SendCallback sendComplete)
        {
            if (payload && m_streamConnection)
            {
                XMLElement::Ptr element = payload->documentElement();

                if (!element)
                {
                    throw connect_error(connect_error::ecInvalidMessage);
                }
                string &&payloadStr = element->name() == "stream:stream" ?
                                      payload->unterminatedXml() :
                                      payload->xml();

                WITH_LOG_WRITES
                (
                    dout << payloadStr << endl;
                )

                if (payloadStr.size() > 0)
                {
                    m_streamConnection->async_send(make_shared<ByteBuffer>(&payloadStr[0],
                                                   payloadStr.size()),
                                                   [sendComplete](const connect_error & ce, size_t)
                    {
                        if (sendComplete) sendComplete(ce);
                    });
                }
                else
                {
                    if (sendComplete) sendComplete(connect_error::SUCCESS);
                }
            }
            else
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
        }

        void XmppConnection::negotiateTLS(TLSCallback callback)
        {
            if (m_streamConnection)
            {
                m_restartPending = true;
                m_streamConnection->negotiateTLS([this, callback](const connect_error & ce)
                {
                    if (!ce.succeeded())
                    {
                        m_restartPending = false;
                    }
                    if (callback) callback(ce);
                });
            }
            else
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
        }

        void XmppConnection::restartStream()
        {
            // Place into restart-pending mode. The parser is now
            // looking for an unterminated <stream:stream> tag.
            m_restartPending = true;
        }



        //////////
        // Version 1.0 as defined in RFC6120
        static const int STREAM_MAJOR_VERSION = 1;
        static const int STREAM_MINOR_VERSION = 0;
        static const string STREAM_NAMESPACE = "http://etherx.jabber.org/streams";

        // MUST
        static const auto DEFAULT_SERVER_VERSION = make_pair(0, 9);

        // @cond HIDDEN_SYMBOLS
        // Xmpp Stream Implementation
        class XmppStream: public XmppStreamBase, public enable_shared_from_this<XmppStream>,
            public IXmppStreamTest
        {
            public:
                XmppStream(const XmppConfig &config, shared_ptr<IXmppConnection> connection):
                    m_currentPhase(NegotiationPhase::StreamEstablishment),
                    m_config(config), m_connection(connection),
                    m_version(DEFAULT_SERVER_VERSION), m_streamID(),
                    m_from(), m_serverSASLMechanisms(), m_tlsNegotiated(false),
                    m_saslNegotiated(false), m_mechanism(),
                    m_negotiatedPromise(), m_negotiated(m_negotiatedPromise.get_future()),
                    m_boundPromise(), m_bound(m_boundPromise.get_future()),
                    m_runInBandRegistration(false), m_boundJabberId(), m_extensions()
                {
                    if (!m_connection)
                    {
                        throw connect_error(connect_error::ecInvalidStream);
                    }
                }

                ~XmppStream() _NOEXCEPT
                {
                    try
                    {
                        close();
                    }
                    catch (...) {}
                }

                void close()
                {
                    try
                    {
                        m_connection->close();
                    }
                    catch (...)
                    {
                        WITH_LOG_ERRORS
                        (
                            dout << "Exception closing stream" << endl;
                        )
                    }
                    if (!m_saslNegotiated || (m_config.isRequiringTLS() && !m_tlsNegotiated))
                    {
                        try
                        {
                            onConnected().fire(XmppConnectedEvent(
                                                   connect_error::ecUnableToStartSession));
                            m_negotiatedPromise.set_exception(make_exception_ptr(
                                                                  connect_error(connect_error::ecUnableToStartSession)));
                        }
                        catch (...)
                        {
                            // The promise may have already been set (if there was a failure during
                            // TLS or SASL negotation.
                        }
                    }
                    if (m_boundJabberId.full().size() == 0)
                    {
                        try
                        {
                            onConnected().fire(XmppConnectedEvent(
                                                   connect_error::ecUnableToBindUser));
                            m_boundPromise.set_exception(make_exception_ptr(
                                                             connect_error(connect_error::ecUnableToBindUser)));
                        }
                        catch (...)
                        {}
                    }

                    onClosed().fire(XmppClosedEvent(connect_error::SUCCESS));
                }

                virtual shared_future<void> &whenNegotiated() override { return m_negotiated; }
                virtual shared_future<JabberID> &whenBound() override { return m_bound; }

                // This is the post-bind send. Do not use it for sending any stream negotiation
                // stanzas.
                virtual void sendStanza(XMLDocument::Ptr stanza) override
                {
                    if (stanza && m_connection)
                    {
                        m_connection->async_send(stanza, IXmlConnection::SendCallback());
                    }
                }

                void addExtension(shared_ptr<IXmppExtension> extension)
                {
                    if (extension)
                    {
                        lock_guard<recursive_mutex> lock(mutex());
                        string name = extension->getExtensionName();
                        m_extensions.insert(Extensions::value_type(name, extension));
                        extension->assignConfiguration(m_config.extensionConfig(name));
                    }
                }

                XMLElement::Ptr createOpenStreamRequest(XMLDocument::Ptr doc, const string &from,
                                                        const string &to)
                {
                    XMLElement::Ptr element;
                    if (doc)
                    {
                        element = doc->createElement("stream:stream");
// NOTE: It is not required that 'from' (i.e. the initiator) be provided before authentication
//       so this may change to suppress the initiator on intial connection..
                        // SHOULD
                        if (from.size() > 0 && (m_tlsNegotiated || m_saslNegotiated))
                        {
                            element->setAttribute("from", from);
                        }
                        // MUST
                        element->setAttribute("to", to);
                        // MUST (for versions 1.0 and higher)
                        element->setAttribute("version", to_string(STREAM_MAJOR_VERSION) + "." +
                                              to_string(STREAM_MINOR_VERSION));
                        // SHOULD
                        element->setAttribute("xml:lang", m_config.language());
                        // CLIENT ('from' is optional)
                        element->setAttribute("xmlns", "jabber:client");
                        // MUST
                        element->setAttribute("xmlns:stream", STREAM_NAMESPACE);
                    }
                    return element;
                }

                virtual void handleXML(XMLElement::Ptr payload) override
                {
                    static const auto s_currentHandlerTable = constructDefaultHandlerTable("stream");
                    if (payload)
                    {
                        const auto f = s_currentHandlerTable.find(payload->name());
                        if (f != s_currentHandlerTable.end())
                        {
                            (this->*(f->second))(move(payload));
                        }
                        else if (m_streamID.size() == 0)
                        {
                            handleStreamOpen(move(payload));
                        }
                        else
                        {
                            // TODO: Plug-in handlers. Implement as extension-registered filter?
                        }
                    }
                    else
                    {
                        throw connect_error(LocalError(LocalError::ecInvalidParameter));
                    }
                }

                virtual JabberID boundResource() const override { return m_boundJabberId; }

                virtual shared_ptr<IXmppStreamTest> getTestInterface() override
                {
                    return static_pointer_cast<IXmppStreamTest>(shared_from_this());
                }

                // IXmppStreamTest interface
            protected:
                virtual void forceRestartStreamNow() override
                {
                    restartStream();
                }

            protected:
                enum class NegotiationPhase
                {
                    StreamEstablishment,
                    StartTLS,
                    TLSNegotation,
                    StreamOverTLS,
                    SaslNegotiation,
                    StreamReestablishment,
                };

                typedef void (XmppStream::*XMLHandlerFunc)(XMLElement::Ptr);
                typedef map<string, XMLHandlerFunc> HandlerMap;
                static HandlerMap constructDefaultHandlerTable(const string &streamNamespace)
                {
                    map<string, XMLHandlerFunc> table;
                    table[streamNamespace + ":stream"] = &XmppStream::handleStreamOpen;
                    table[streamNamespace + ":error"] = &XmppStream::handleStreamError;
                    table[streamNamespace + ":features"] = &XmppStream::handleStreamFeatures;
                    table["proceed"] = &XmppStream::handleTLSProceed;
                    table["response"] = &XmppStream::handleSaslResponse;
                    table["challenge"] = &XmppStream::handleSaslChallenge;
                    table["failure"] = &XmppStream::handleSaslFailure;
                    table["success"] = &XmppStream::handleSaslSuccess;

                    table["iq"] = &XmppStream::handleMessage;
                    table["message"] = &XmppStream::handleMessage;
                    table["presence"] = &XmppStream::handleMessage;
                    return table;
                }

                void handleStreamOpen(XMLElement::Ptr open)
                {
                    string streamNamespace = open->findNamespace(STREAM_NAMESPACE);

                    if (streamNamespace.size() == 0)
                    {
                        closeWithError("invalid-namespace");
                        return;
                    }
                    if (streamNamespace != "stream")
                    {
                        closeWithError("bad-namespace-prefix");
                        return;
                    }

                    if (open->name() == "stream:stream")
                    {
                        open->getAttribute("id", m_streamID);
                        string serverStreamVersion;
                        if (open->getAttribute("version", serverStreamVersion))
                        {
                            //static const regex s_split("\\.");
                            vector<string> versionParts;
                            // TODO: Use regex when all compiler suites support it.
                            //copy(sregex_token_iterator(serverStreamVersion.begin(),
                            //                           serverStreamVersion.end(), s_split, -1),
                            //     sregex_token_iterator(),
                            //     back_inserter(versionParts));
                            versionParts = str_helper::split(serverStreamVersion, '.');

                            if (versionParts.size() > 0)
                            {
                                m_version.first = strtoul(versionParts[0].c_str(), nullptr, 10);
                            }
                            if (versionParts.size() > 1)
                            {
                                m_version.second = strtoul(versionParts[1].c_str(), nullptr, 10);
                            }

                            if (m_version.first > STREAM_MAJOR_VERSION)
                            {
                                // SHOULD: Server doesn't support our stream version.
                                closeWithError("unsupported-version");
                            }
                        }
                    }
                    else
                    {
                        throw connect_error(connect_error::ecInvalidStream);
                    }
                }

                void closeWithError(const string &errorTag, const string &text = "")
                {
                    XMLDocument::Ptr doc = XMLDocument::createEmptyDocument();
                    XMLElement::Ptr errorElement = doc->createElement("stream:error");
                    XMLElement::Ptr errorTagElement = doc->createElement(errorTag);

                    errorTagElement->setAttribute("xmlns", XMPP_STREAMS_NAMESPACE);

                    errorElement->appendChild(errorTagElement);

                    // OPTIONAL
                    if (text.size() > 0)
                    {
                        XMLElement::Ptr textElement = doc->createElement("text");
                        textElement->setAttribute("xmlns", XMPP_STREAMS_NAMESPACE);
                        textElement->setAttribute("xml:lang", "en");
                        textElement->setValue(text);
                        errorElement->appendChild(textElement);
                    }

                    doc->appendChild(errorElement);

                    m_connection->async_send(doc,
                                             [this](const connect_error &)
                    {
                        close();
                    });
                }

                // MUST (server must send features payload)
                void handleStreamFeatures(XMLElement::Ptr features)
                {
                    bool tlsFound = false, tlsOnly = true;

                    for (const auto &e : features->elements())
                    {
                        if (e->name() == "starttls")
                        {
                            tlsFound = true;

                            string xmlns;
                            if (e->getAttribute("xmlns", xmlns) && xmlns != XMPP_TLS_NAMESPACE)
                            {
                                closeWithError("invalid-namespace");
                                return;
                            }

                            //if (m_tlsNegotiated)
                            //{
                            // TODO: If TLS is already negotiated send an error or ignore?
                            //       The server MUST not send one after negotiation, but
                            //       it doesn't really matter to the client. There is no
                            //       defined error condition for this case.
                            //closeWithError("unsupported-feature");
                            //return;
                            //}

                            for (const auto &tlsElement : e->elements())
                            {
                                if (tlsElement->name() == "required")
                                {
                                    m_config.requireTLSNegotiation();
                                }
                            }
                        }
                        else if (e->name() == "mechanisms")
                        {
                            tlsOnly = false;

                            m_serverSASLMechanisms.clear();
                            for (const auto &mechanism : e->elements())
                            {
                                if (mechanism->name() == "mechanism")
                                {
                                    m_serverSASLMechanisms.push_back(mechanism->value());
                                }
                            }
                        }
                        else if (e->name() == "c")
                        {
                            // TODO: pluggable feature set?
                        }
#ifndef DISABLE_SUPPORT_XEP0077
                        else if (e->name() == "register")
                        {
                            string registerNs;
                            if (m_config.isRequestingInBandRegistration() &&
                                e->getAttribute("xmlns", registerNs) &&
                                registerNs == XMPP_REGISTER_NAMESPACE)
                            {
                                m_runInBandRegistration = true;
                            }
                        }
#endif
                        else if (e->name() == "bind")
                        {
                            string bindNs;
                            if (e->getAttribute("xmlns", bindNs) && bindNs == XMPP_BIND_NAMESPACE)
                            {
                                // NOTE: We are not currently supporting client-side resource
                                //       assignment. It is not expected to be required for the
                                //       use cases this client supports.
                                auto doc = XMLDocument::createEmptyDocument();
                                auto iq = doc->createElement("iq");
                                iq->setAttribute("type", "set");
                                iq->setAttribute("id", getNextID());

                                auto bind = doc->createElement("bind");
                                bind->setAttribute("xmlns", XMPP_BIND_NAMESPACE);

                                iq->appendChild(bind);
                                doc->appendChild(iq);

                                sendQuery(move(iq),
                                          [this](const connect_error & ce, XMLElement::Ptr response)
                                {
                                    bool bound = false;
                                    if (ce.succeeded() && response)
                                    {
                                        string type;
                                        if (response->getAttribute("type", type) && type == "result")
                                        {
                                            for (const auto &i : response->elements())
                                            {
                                                string ns;
                                                if (i->name() == "bind" &&
                                                    i->getAttribute("xmlns", ns) &&
                                                    ns == XMPP_BIND_NAMESPACE)
                                                {
                                                    for (const auto &j : i->elements())
                                                    {
                                                        if (j->name() == "jid")
                                                        {
                                                            m_boundJabberId = j->value();
                                                            bound = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if (bound)
                                    {
                                        // NOTE: Session is deprecated in RFC6121, but eJabberd
                                        // (the current test server) will not communicate with the
                                        // client without a session establishment. Since it
                                        // is not advertising support for session establishment,
                                        // we'll just inject one here anyway.
                                        auto doc = XMLDocument::createEmptyDocument();
                                        auto message = doc->createElement("iq");
                                        message->setAttribute("type", "set");
                                        message->setAttribute("id", getNextID());

                                        auto session = doc->createElement("session");
                                        session->setAttribute("xmlns", XMPP_SESSION_NAMESPACE);

                                        message->appendChild(session);
                                        doc->appendChild(message);
                                        sendMessage(move(message));

                                        onConnected().fire(XmppConnectedEvent(
                                                               connect_error::SUCCESS,
                                                               m_boundJabberId.full()));
                                        m_boundPromise.set_value(m_boundJabberId);
                                        m_negotiatedPromise.set_value();
                                    }
                                    else
                                    {
                                        // Binding is mandatory. If we fail to bind,
                                        // close the stream.
                                        close();
                                    }
                                });
                            }
                        }
                        else if (e->name() == "sm")
                        {
                        }
                        // DEPRECATED
                        //else if (e->name()=="session")
                        //{
                        //}
                    }

                    // Either XMPPConfig already required TLS or the remote server required it.
                    // MUST: If there are no advertised mechanisms other than tls then tls is
                    //        mandatory (RFC6120 5.3.1)
                    if ((m_config.isRequiringTLS() || (tlsOnly && tlsFound)) && !m_tlsNegotiated)
                    {
                        negotiateTLS();
                    }
#ifndef DISABLE_SUPPORT_XEP0077
                    else if (m_runInBandRegistration)
                    {
                        auto registration = make_shared<InBandRegistration>(shared_from_this());
                        addExtension(registration);

                        registration->registerUser([this, registration](const connect_error & ce)
                        {
                            (void)ce;
                            WITH_LOG_INFO
                            (
                                dout << "REGISTRATION RESULT: " << ce.toString() << endl;
                            )

                            // Regardless of the success/fail state, still attempt a SASL
                            // negotiation. It is possible/likely we are already registered.
                            negotiateSASL();
                        });
                    }
#endif
                    else if (!m_saslNegotiated)
                    {
                        negotiateSASL();
                    }
                    else if (m_saslNegotiated && (!m_config.isRequiringTLS() || m_tlsNegotiated))
                    {
                        // NOTE: We will wait till the stream is bound before signaling the
                        //       connected state.
                        m_negotiatedPromise.set_value();
                    }
                }

                void handleStreamError(XMLElement::Ptr error)
                {
                    if (error)
                    {
                        WITH_LOG_ERRORS
                        (
                            dout << error->xml() << endl;
                        )
                    }
                    close();
                }

                void setPhase(NegotiationPhase phase)
                {
                    lock_guard<recursive_mutex> lock(mutex());
                    m_currentPhase = phase;
                }

                NegotiationPhase currentPhase() const
                {
                    lock_guard<recursive_mutex> lock(mutex());
                    return m_currentPhase;
                }


                // TLS Behaviors

                void negotiateTLS()
                {
                    XMLDocument::Ptr doc = XMLDocument::createEmptyDocument();
                    XMLElement::Ptr starttls = doc->createElement("starttls");
                    starttls->setAttribute("xmlns", XMPP_TLS_NAMESPACE);
                    doc->appendChild(starttls);

                    if (currentPhase() == NegotiationPhase::StreamEstablishment)
                    {
                        setPhase(NegotiationPhase::StartTLS);
                        m_connection->async_send(doc, IXmppConnection::SendCallback());
                    }
                    else
                    {
                        failTLS();
                    }
                }

                void handleTLSProceed(XMLElement::Ptr proceed)
                {
                    if (currentPhase() == NegotiationPhase::StartTLS)
                    {
                        string xmlns;
                        if (proceed->getAttribute("xmlns", xmlns) && xmlns != XMPP_TLS_NAMESPACE)
                        {
                            onConnected().fire(XmppConnectedEvent(
                                                   connect_error::ecTlsNegotationFailure));

                            m_negotiatedPromise.set_exception(make_exception_ptr(
                                                                  connect_error(connect_error::ecTlsNegotationFailure)));

                            closeWithError("invalid-namespace");
                            return;
                        }
                        setPhase(NegotiationPhase::TLSNegotation);

                        m_connection->negotiateTLS([this](const connect_error & ce)
                        {
                            if (ce.succeeded())
                            {
                                setPhase(NegotiationPhase::StreamOverTLS);
                                m_tlsNegotiated = true;
                                restartStream();
                            }
                            else
                            {
                                failTLS();
                            }
                        });
                    }
                    else
                    {
                        failTLS();
                    }
                }

                void failTLS()
                {
                    if (currentPhase() == NegotiationPhase::StartTLS)
                    {
                        XMLDocument::Ptr doc = XMLDocument::createEmptyDocument();
                        XMLElement::Ptr failtls = doc->createElement("failure");
                        failtls->setAttribute("xmlns", XMPP_TLS_NAMESPACE);
                        doc->appendChild(failtls);
                        m_connection->async_send(doc, IXmppConnection::SendCallback());
                    }

                    onConnected().fire(XmppConnectedEvent(connect_error::ecTlsNegotationFailure));

                    m_negotiatedPromise.set_exception(make_exception_ptr(
                                                          connect_error(connect_error::ecTlsNegotationFailure)));
                    close();
                }


                // SASL Behaviors

                enum class WriteEmptyValue
                {
                    WriteEmptyAsEquals,
                    IgnoreEmpty
                };

                void negotiateSASL()
                {
                    setPhase(NegotiationPhase::SaslNegotiation);

                    const list<string> &requestedOrder = m_config.SASLOrder();
                    list<string> saslOrder = requestedOrder.size() > 0 ?
                                             SaslFactory::restrictToKnownMechanisms(requestedOrder) :
                                             SaslFactory::defaultSaslOrder();

                    // TODO: Restrict to safe-for-non-auth streams mechanisms.
                    string mechanismName = SaslFactory::selectMechanism(saslOrder,
                                           m_serverSASLMechanisms);
                    if (mechanismName.size() == 0 && m_serverSASLMechanisms.size() != 0)
                    {
                        // No known SASL mechanisms to negotiate.
                        onConnected().fire(XmppConnectedEvent(connect_error::ecNoSaslMechanism));
                        m_negotiatedPromise.set_exception(make_exception_ptr(
                                                              connect_error(connect_error::ecNoSaslMechanism)));
                        close();
                        return;
                    }

                    m_mechanism = SaslFactory::createSaslMechanism(mechanismName);
                    if (!m_mechanism)
                    {
                        onConnected().fire(XmppConnectedEvent(connect_error::ecNoSaslMechanism));
                        m_negotiatedPromise.set_exception(make_exception_ptr(
                                                              connect_error(connect_error::ecNoSaslMechanism)));
                        close();
                        return;
                    }

                    if (m_mechanism->requiresAuthenticatedStream() && !m_tlsNegotiated)
                    {
                        // By default, we do not allow mechanisms that push cleartext to run
                        // over non-TLS-negotiated streams.
                        WITH_LOG_ERRORS
                        (
                            dout << "Attempt to negotiate SASL(" << mechanismName <<
                            ") over unsecured stream refused by client.";

                        )
                        onConnected().fire(XmppConnectedEvent(
                                               connect_error::ecInsecureSaslOverInsecureStream));
                        m_negotiatedPromise.set_exception(make_exception_ptr(
                                                              connect_error(connect_error::ecInsecureSaslOverInsecureStream)));
                        close();
                        return;
                    }

                    m_mechanism->setParams(m_config.saslConfig(mechanismName));

                    writeSasl("auth", m_mechanism->initiate(), WriteEmptyValue::WriteEmptyAsEquals,
                              mechanismName);
                    SecureBuffer challenge = m_mechanism->challenge();
                    if (challenge.size() > 0)
                    {
                        WITH_LOG_WRITES
                        (
                            dout << "Raw Challenge: " <<
                            string((char *)&challenge[0], challenge.size()) << endl;
                        )
                        writeSasl("challenge", challenge,
                                  WriteEmptyValue::IgnoreEmpty);
                    }
                }

                void writeSasl(const string &tag, const SecureBuffer &buf, WriteEmptyValue emptyValue,
                               const string &mechanism = "")
                {
                    XMLDocument::Ptr doc = XMLDocument::createEmptyDocument();
                    XMLElement::Ptr element = doc->createElement(tag);
                    element->setAttribute("xmlns", XMPP_SASL_NAMESPACE);
                    if (mechanism.size() > 0)
                    {
                        element->setAttribute("mechanism", mechanism);
                    }
                    if (buf.size() == 0 && emptyValue == WriteEmptyValue::WriteEmptyAsEquals)
                    {
                        element->setValue("=");
                    }
                    else
                    {
                        SecureBuffer outputBuf;
                        if (buf.base64Encode(outputBuf))
                        {
                            element->setValue((const char *)(&outputBuf[0]), outputBuf.size());
                        }
                        else
                        {

                            onConnected().fire(XmppConnectedEvent(
                                                   connect_error::ecSaslNegotationFailure));
                            m_negotiatedPromise.set_exception(make_exception_ptr(
                                                                  connect_error(connect_error::ecSaslNegotationFailure)));
                            throw runtime_error("base64_failure");
                        }
                    }
                    // Google-talk authentication extension. Add only if required.
                    // References https://developers.google.com/talk/jep_extensions/jid_domain_change
                    //if (tag=="auth")
                    //{
                    //element->setAttribute("xmlns:ga", "http://www.google.com/talk/protocol/auth");
                    //element->setAttribute("ga:client-uses-full-bind-result", "true");
                    //}

                    doc->appendChild(element);
                    m_connection->async_send(doc, IXmppConnection::SendCallback());
                }

                void handleSaslChallenge(XMLElement::Ptr challenge)
                {
                    if (currentPhase() == NegotiationPhase::SaslNegotiation && m_mechanism)
                    {
                        string xmlns;
                        if (challenge->getAttribute("xmlns", xmlns) && xmlns != XMPP_SASL_NAMESPACE)
                        {
                            closeWithError("invalid-namespace");
                            return;
                        }

                        string &&val = challenge->value();
                        SecureBuffer source(val.c_str(), val.size());
                        SecureBuffer base64DecodedResponse;
                        if (source.base64Decode(base64DecodedResponse))
                        {
                            m_mechanism->handleChallenge(base64DecodedResponse,
                                                         [this](const SaslResult & r, const SecureBuffer & buf)
                            {
                                if (r.result() == SaslResult::Response)
                                {
                                    writeSasl("response", buf, WriteEmptyValue::IgnoreEmpty);
                                }
                                else
                                {
                                    failSasl();
                                }
                            });
                        }
                        else
                        {
                            failSasl();
                        }
                    }
                    else
                    {
                        failSasl();
                    }
                }

                void handleSaslResponse(XMLElement::Ptr response)
                {
                    if (currentPhase() == NegotiationPhase::SaslNegotiation && m_mechanism)
                    {
                        string xmlns;
                        if (response->getAttribute("xmlns", xmlns) && xmlns != XMPP_SASL_NAMESPACE)
                        {
                            closeWithError("invalid-namespace");
                            return;
                        }

                        string &&val = response->value();
                        SecureBuffer source(val.c_str(), val.size());
                        SecureBuffer base64DecodedResponse;
                        if (source.base64Decode(base64DecodedResponse))
                        {
                            m_mechanism->handleResponse(base64DecodedResponse,
                                                        [this](const SaslResult & r, const SecureBuffer & buf)
                            {
                                if (r.result() == SaslResult::Challenge)
                                {
                                    writeSasl("challenge", buf, WriteEmptyValue::IgnoreEmpty);
                                }
                                else
                                {
                                    failSasl();
                                }
                            });
                        }
                        else
                        {
                            failSasl();
                        }
                    }
                    else
                    {
                        failSasl();
                    }
                }

                void handleSaslFailure(XMLElement::Ptr failure)
                {
                    if (currentPhase() == NegotiationPhase::SaslNegotiation)
                    {
                        string xmlns;
                        if (failure->getAttribute("xmlns", xmlns) && xmlns != XMPP_SASL_NAMESPACE)
                        {
                            closeWithError("invalid-namespace");
                            return;
                        }

                        //for (const auto &i: failure->elements())
                        //{
                        // TODO: FAILURE handling.
                        //i->name();
                        //}
                        onConnected().fire(XmppConnectedEvent(
                                               connect_error::ecSaslNegotationFailure));
                        m_negotiatedPromise.set_exception(make_exception_ptr(
                                                              connect_error(connect_error::ecSaslNegotationFailure)));

                        close();
                    }
                }

                void handleSaslSuccess(XMLElement::Ptr success)
                {
                    if (currentPhase() == NegotiationPhase::SaslNegotiation)
                    {
                        // We must restart the stream before sending anything else according to
                        // RFC 6120 [6.4.6]. This includes the stream-close that may occur if
                        // there is an error here.
                        restartStream();

                        string xmlns;
                        if (success->getAttribute("xmlns", xmlns) && xmlns != XMPP_SASL_NAMESPACE)
                        {
                            // We are in a bit of a pickle here; having restarted the stream, this
                            // doesn't really make send in the context of the restart-message, but
                            // the succeess case failed. This case does not appear to be addressed
                            // in the specification, so we are taking a stab at it in this manner.
                            closeWithError("invalid-namespace");
                            return;
                        }

                        string &&val = success->value();
                        SecureBuffer source(val.c_str(), val.size());
                        SecureBuffer base64DecodedResponse;
                        if (source.base64Decode(base64DecodedResponse))
                        {
                            m_mechanism->handleSuccess(base64DecodedResponse,
                                                       [this](const SaslResult & r, const SecureBuffer &)
                            {
                                if (r.result() == SaslResult::Success)
                                {
                                    m_saslNegotiated = true;
                                }
                                else
                                {
                                    // Having succeeded with SASL negotation, we can no longer
                                    // abort it. Just close.
                                    close();
                                }
                            });
                        }
                        else
                        {
                            // Having succeeded with SASL negotatiion, we can no longer abort it.
                            // Just closed.
                            close();
                        }
                    }
                }

                void failSasl()
                {
                    onConnected().fire(XmppConnectedEvent(connect_error::ecSaslNegotationAborted));
                    m_negotiatedPromise.set_exception(make_exception_ptr(
                                                          connect_error(connect_error::ecSaslNegotationAborted)));

                    writeSasl("abort", SecureBuffer(), WriteEmptyValue::IgnoreEmpty);
                    close();
                }


                void restartStream()
                {
                    if (m_boundJabberId.full().size() > 0)
                    {
                        // bind-restart
                        // Do not restart the stream after negotiation of resource.
                        throw connect_error(connect_error::ecAttemptToRestartBoundStream);
                    }

                    setPhase(NegotiationPhase::StreamReestablishment);

                    m_version = DEFAULT_SERVER_VERSION;
                    m_from = "";
                    m_streamID = "";
                    XMLDocument::Ptr doc = XMLDocument::createEmptyDocument();
                    XMLElement::Ptr open = createOpenStreamRequest(doc, m_config.initiator().full(),
                                           m_config.host());
                    doc->appendChild(open);
                    m_connection->restartStream();
                    m_connection->async_send(doc, IXmppConnection::SendCallback());
                }

            private:
                NegotiationPhase m_currentPhase;

                XmppConfig m_config;
                shared_ptr<IXmppConnection> m_connection;
                pair<int, int> m_version;
                string m_streamID;
                string m_from;
                list<string> m_serverSASLMechanisms;
                bool m_tlsNegotiated;
                bool m_saslNegotiated;
                shared_ptr<ISaslMechanism> m_mechanism;

                promise<void> m_negotiatedPromise;
                shared_future<void> m_negotiated;

                promise<JabberID> m_boundPromise;
                shared_future<JabberID> m_bound;

                bool m_runInBandRegistration;

                JabberID m_boundJabberId;

                typedef multimap<string, weak_ptr<IXmppExtension>> Extensions;
                Extensions m_extensions;
        };
        /// @endcond


        //////////
        /// @cond HIDDEN_SYMBOLS
        // Action runner for the XMPP client.
        struct XmppClientRunner: public ActionRunner<std::shared_ptr<IXmppConnection>, XmppContext>
        {
                XmppClientRunner(XmppClient &) {}

            protected:
                virtual std::thread createActionThread(std::shared_ptr<runner_queue> queue,
                                                       std::shared_ptr<IXmppConnection> connection) override
                {
                    return thread([this, queue, connection]()
                    {
                        chrono::seconds nextWake = chrono::seconds(10);
                        while (!queue->isClosed())
                        {
                            shared_ptr<runner_action> nextAction;
                            if (queue->pop(nextWake, nextAction))
                            {
                                if (nextAction)
                                {
                                    struct CurrentSessionContext: public XmppContext
                                    {} sessionContext;

                                    try
                                    {
                                        (*nextAction)(sessionContext);
                                    }
                                    catch (const exception &ex)
                                    {
                                        (void)ex;
                                        WITH_LOG_CRITICALS
                                        (
                                            dout << "Exception Running Queued Action " <<
                                            ex.what() << endl;
                                        )
                                    }
                                    catch (...)
                                    {
                                        // TODO: Add logging?
                                    }
                                }
                            }
                        }
                    });
                }
        };
        /// @endcond


        /// @cond HIDDEN_SYMBOLS
        // Private implementation details for the XmppClient class to avoid DLL export issues.
        struct XmppClientPimpl
        {
            XmppClientPimpl(XmppClient &owner):
                m_mutex(), m_shutdown(false), m_streams(), m_runner(owner),
                m_streamCreated(m_mutex)
            {}

            mutable recursive_mutex m_mutex;
            bool m_shutdown;
            set<shared_ptr<IXmppStream>> m_streams;
            XmppClientRunner m_runner;
            SyncEvent<XmppStreamCreatedEvent> m_streamCreated;
        };
        /// @endcond

        void XmppClientPimplDelete::operator()(XmppClientPimpl *p) { delete p; }

        shared_ptr<XmppClient> XmppClient::create()
        {
            return shared_ptr<XmppClient>(new XmppClient);
        }

        XmppClient::XmppClient(): p_(new XmppClientPimpl(*this)) {}

        XmppClient::~XmppClient()
        {
            p_->m_shutdown = true;
            for (auto i : p_->m_streams)
            {
                try
                {
                    i->close();
                }
                catch (...)
                {}
            }
            p_->m_runner.shutdown();
        }

        SyncEvent<XmppStreamCreatedEvent> &XmppClient::onStreamCreated()
        {
            return p_->m_streamCreated;
        }

        void XmppClient::initiateXMPP(const XmppConfig &config,
                                      shared_ptr<IXmppConnection> remoteServer,
                                      XmppStreamPromise xmppConnection)
        {
            if (remoteServer)
            {
                try
                {
                    auto initiateXmppAction =
                        [this, config, remoteServer, xmppConnection](XmppContext &)
                    {
                        shared_ptr<XmppStream> stream;
                        try
                        {

                            stream = make_shared<XmppStream>(config, remoteServer);

                            onStreamCreated().fire(XmppStreamCreatedEvent(stream, remoteServer));
                            remoteServer->connect();

                            {
                                lock_guard<recursive_mutex> lock(p_->m_mutex);
                                p_->m_streams.insert(stream);
                            }

                            queueReadAction(stream, remoteServer);

                            XMLElement::Ptr response;
                            this->sendSynchronousRequest(remoteServer,
                                                         [&config, &stream](XMLDocument::Ptr doc)
                            {
                                return stream->createOpenStreamRequest(doc,
                                                                       config.initiator().full(),
                                                                       config.host());
                            }, response,
                            XMLDocument::DocumentFlags::dfIncludeDeclaration);

                            if (xmppConnection)
                            {
                                xmppConnection->set_value(stream);
                            }
                        }
                        catch (const connect_error &err)
                        {
                            if (stream)
                            {
                                lock_guard<recursive_mutex> lock(p_->m_mutex);
                                p_->m_streams.erase(stream);
                            }
                            onStreamCreated().fire(XmppStreamCreatedEvent(err, remoteServer));
                            if (xmppConnection)
                            {
                                xmppConnection->set_exception(current_exception());
                            }
                        }
                        catch (const exception &)
                        {
                            if (stream)
                            {
                                lock_guard<recursive_mutex> lock(p_->m_mutex);
                                p_->m_streams.erase(stream);
                            }
                            onStreamCreated().fire(
                                XmppStreamCreatedEvent(connect_error::ecInvalidStream,
                                                       remoteServer));
                            if (xmppConnection)
                            {
                                xmppConnection->set_exception(current_exception());
                            }
                        }
                    };

                    p_->m_runner.getQueue(remoteServer)->push(
                        XmppClientRunner::make_action_from(initiateXmppAction));
                }
                catch (const exception &)
                {
                    onStreamCreated().fire(
                        XmppStreamCreatedEvent(connect_error::ecInvalidStream,
                                               remoteServer));
                    if (xmppConnection)
                    {
                        xmppConnection->set_exception(current_exception());
                    }
                }
            }
            else
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
        }

        void XmppClient::queueReadAction(shared_ptr<IXmppStream> stream,
                                         shared_ptr<IXmppConnection> remoteServer)
        {
            auto self = shared_from_this();
            if (remoteServer && self)
            {
                weak_ptr<XmppClient> weakSelf(self);
                auto readAction = [weakSelf, remoteServer, stream](XmppContext &)
                {
                    remoteServer->async_receive(
                        [weakSelf, remoteServer, stream](connect_error ec, XMLElement::Ptr element)
                    {
                        auto self = weakSelf.lock();
                        if (self && element && ec.succeeded())
                        {
                            WITH_LOG_READS
                            (
                                dout << element->xml() << endl;
                            )

                            if (stream)
                            {
                                stream->handleXML(move(element));
                            }
                            // Continue reading by recursively queuing up a new read action.
                            // Note that this will not consume stack resources as the next
                            // read is queued up on the XmppClient action queue.
                            self->queueReadAction(stream, remoteServer);
                        }
                        else if (self && ec.errorType() == connect_error::etConnectError() &&
                                 ec.errorCode() == connect_error::ecTLSNegotiationInProgress)
                        {
                            // TODO: Change to queue TLS negotiated action

                            // Continue reading by recursively queuing up a new read action.
                            // Note that this will not consume stack resources as the next
                            // read is queued up on the XmppClient action queue.
                            self->queueReadAction(stream, remoteServer);
                        }
                        else
                        {
                            if (stream)
                            {
                                stream->onClosed().fire(XmppClosedEvent(
                                                            connect_error::ecServerClosedStream));
                            }
                            remoteServer->close();
                        }

                    });
                };

                p_->m_runner.getQueue(remoteServer)->push(
                    XmppClientRunner::make_action_from(readAction));
            }
        }

        void XmppClient::sendSynchronousRequest(shared_ptr<IXmppConnection> connection,
                                                XML::XMLDocument::Ptr request,
                                                XML::XMLElement::Ptr &)
        {
            if (request && connection)
            {
                try
                {
                    connection->send(request);
                }
                catch (const connect_error &ce)
                {
                    connection->close();
                    throw ce;
                }
            }
            else
            {
                throw connect_error(LocalError(connect_error::ecInvalidParameter));
            }
        }
    }
}

#endif // DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
