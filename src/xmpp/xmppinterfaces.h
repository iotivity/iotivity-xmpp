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

/// @file xmppinterfaces.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "../xml/portabledom.h"
#include "../common/sync_notify.h"
#include "../include/ccfxmpp.h"

#include <functional>
#include <future>
#include <memory>


#ifndef _NOEXCEPT
#ifndef _MSC_VER
#define _NOEXCEPT noexcept
#else
#define _NOEXCEPT
#endif
#endif



namespace Iotivity
{
    class SecureBuffer;

    namespace Xmpp
    {
        struct SaslResult;
        class connect_error;
        class XmppConfig;


        /// @brief XML Stream interface. Provides a stream from which XML payloads may be
        ///        received.
        ///
        /// This is the base for IXmppStream. It is differentiated from an IXmlConnection
        /// in that the stream is provided by the connection interface and hides the
        /// stream establishment details that the connection needs to process.
        class XMPP_API IXmlStream
        {
            public:
                virtual ~IXmlStream() _NOEXCEPT {}

                virtual void close() = 0;
                virtual void handleXML(XML::XMLElement::Ptr payload) = 0;
                //virtual void send(XML::XMLElement::Ptr payload) = 0;
                //virtual void receive(XML::XMLElement::Ptr &payload) = 0;
        };

        class JabberID;

        /// @brief XMPP Stream Extended interface for unit testing.
        ///
        ///        When supported, this interface provides access to behavior that
        ///        should not be used by external applications. Behavior of applications
        ///        that interface to IXmppStreamTest is undefined. This interface is subject
        ///        to change without notice.
        class XMPP_API IXmppStreamTest
        {
            public:
                virtual void forceRestartStreamNow() = 0;
        };


        struct XmppConnectedEvent;
        struct XmppClosedEvent;
        struct XmppMessageEvent;

        /// @brief XMPP Stream interface. Provides a stream of XML stanzas that can be used
        ///        to communication requests and messages to/from an XMPP server.
        ///
        class XMPP_API IXmppStream: public IXmlStream
        {
            public:
                virtual ~IXmppStream() _NOEXCEPT {}

                virtual std::shared_future<void> &whenNegotiated() = 0;
                virtual std::shared_future<JabberID> &whenBound() = 0;

                virtual SyncEvent<XmppConnectedEvent> &onConnected() = 0;
                virtual SyncEvent<XmppClosedEvent> &onClosed() = 0;

                virtual std::string getNextID() =  0;
                virtual JabberID boundResource() const = 0;

                typedef std::function<void(const connect_error &, XML::XMLElement::Ptr)> QueryResponse;
                virtual void sendQuery(XML::XMLElement::Ptr query, QueryResponse callback) = 0;
                virtual void haltQuery(const std::string &ID) = 0;
                virtual void sendMessage(XML::XMLElement::Ptr message) = 0;

                virtual SyncEvent<XmppMessageEvent> &onMessage() = 0;

                virtual std::shared_ptr<IXmppStreamTest> getTestInterface()
                { return std::shared_ptr<IXmppStreamTest>(); }
        };

        /// @brief Interface describing a set of parameters to be passed to a SASL mechanism for
        /// user authentication.
        struct XMPP_API ISaslParams
        {
            virtual ~ISaslParams() {}

            // NOTE: This is done in lieu of RTTI. The mechanism name must be acceptable to
            //       the Sasl mechanism it becomes attached to.
            virtual bool supportsMechanism(const std::string &mechanism) const = 0;
            virtual std::string authenticationIdentity() const = 0;
            virtual SecureBuffer password() const = 0;
        };


        /// Interface describing a SASL mechanism. (RFC4422)
        class ISaslMechanism
        {
            public:
                virtual ~ISaslMechanism() {}

                virtual bool requiresAuthenticatedStream() const = 0;

                virtual void setParams(std::shared_ptr<ISaslParams> params) = 0;

                virtual SecureBuffer initiate() = 0;
                virtual SecureBuffer challenge() = 0;
                typedef std::function<void(const SaslResult &, const SecureBuffer &)> ResponseCallback;
                virtual void handleChallenge(const SecureBuffer &challenge,
                                             ResponseCallback callback) = 0;
                virtual void handleResponse(const SecureBuffer &response,
                                            ResponseCallback callback) = 0;
                virtual void handleSuccess(const SecureBuffer &response,
                                           ResponseCallback callback) = 0;
        };


        /// @brief Base interface for classes which provide XMPP features or extensions.
        class IXmppProvider
        {
            public:
                ~IXmppProvider() {}
        };

        /// @brief Interface describing a set of parameters to be attached to an extension
        ///        when the extension is attached to a stream.
        struct XMPP_API IExtensionParams
        {
            virtual ~IExtensionParams() {}

            // NOTE: This is done in lieu of RTTI.
            virtual bool supportsExtension(const std::string &extensionName) const = 0;
        };

        /// @brief Specialization for IXmppProvider which provides an XMPP protocol extension
        class IXmppExtension: public IXmppProvider
        {
            public:
                virtual std::string getExtensionName() const = 0;
                virtual void assignConfiguration(std::shared_ptr<IExtensionParams> config) = 0;
        };


        /// @brief Xml Connection Interface
        ///
        /// Provides an interface describing a connection to which XML stanzas may be written
        /// and from which XML stanzas may be read. This is intended to provide a means
        /// of reading/writing to/from both XMPP and XMPP-BOSH consistently.
        class XMPP_API IXmlConnection
        {
            public:
                virtual ~IXmlConnection() _NOEXCEPT {}

                virtual void connect() = 0;
                virtual void close() = 0;

                virtual void send(XML::XMLDocument::Ptr payload) = 0;
                virtual void receive(XML::XMLElement::Ptr &payload) = 0;

                typedef std::function<void(const connect_error &, XML::XMLElement::Ptr)>
                ReceiveCallback;
                virtual void async_receive(ReceiveCallback receiveComplete) = 0;

                typedef std::function<void(const connect_error &)> SendCallback;
                virtual void async_send(XML::XMLDocument::Ptr payload, SendCallback sendComplete) = 0;

                typedef std::function<void(const connect_error &)> TLSCallback;
                virtual void negotiateTLS(TLSCallback callback) = 0;
        };

        /// @brief XMPP Connection interface. Extends IXmlConnection to support Xmpp requirement.
        ///
        /// Provides an interface describing an XMPP stream to which XML stanzas may be written
        /// and from which XML stanzas may be read. This is intended to extend IXmlConnection
        /// to provide stream restart semantics (for parsing unterminated XML).
        class XMPP_API IXmppConnection: public IXmlConnection
        {
            public:
                virtual void restartStream() = 0;
        };

        struct XmppStreamCreatedEvent;

        /// @brief Base interface describing an XMPP client that communicates XMPP over
        ///        an XMPP stream.
        class XMPP_API IXmppClient
        {
            public:
                typedef std::shared_ptr<std::promise<std::shared_ptr<IXmppStream>>>
                XmppStreamPromise;

                virtual ~IXmppClient() {}

                virtual void initiateXMPP(const XmppConfig &config,
                                          std::shared_ptr<IXmppConnection> remoteServer,
                                          XmppStreamPromise xmppConnection =
                                              XmppStreamPromise()) = 0;
                virtual SyncEvent<XmppStreamCreatedEvent> &onStreamCreated() = 0;
        };

        /// @brief Context use for Actions running in an XMPP client. This may be used to provide
        /// detailed parameters to actions that require state.
        struct XMPP_API XmppContext
        {
            virtual ~XmppContext() {}
        };

    }
}
