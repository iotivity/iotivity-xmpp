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

/// @file xmppstrohe.h

#include "../include/xmpp_feature_flags.h"
#include "../xmpp/xmppinterfaces.h"
#include "../xmpp/xmppevents.h"

#ifndef DISABLE_SUPPORT_LIBSTROPHE

#include <string>

namespace Iotivity
{
    namespace Xmpp
    {
        struct XmppClientPimpl;

        /// @cond HIDDEN_SYMBOLS
        // Xmpp Client Impl unique_ptr delete helper
        struct XmppClientPimplDelete
        {
            void operator()(XmppClientPimpl *);
        };
        /// @endcond
    }
}

struct _xmpp_ctx_t;
struct _xmpp_conn_t;
struct _xmpp_stanza_t;

namespace Iotivity
{
    namespace Xmpp
    {
        class XmppConfig;


        /// @brief The strophe implementation of IXmppConnection.
        ///
        /// @ingroup XMPP
        class XMPP_API XmppStropheConnection:
            public IXmppConnection, public std::enable_shared_from_this<XmppStropheConnection>
        {
            public:
                XmppStropheConnection(const std::string &host, const std::string &port);
                virtual ~XmppStropheConnection() _NOEXCEPT override;

                virtual void connect() override;

                virtual void close() override;
                virtual void send(XML::XMLDocument::Ptr payload) override;
                virtual void receive(XML::XMLElement::Ptr &payload) override;

                virtual void async_receive(ReceiveCallback receiveComplete) override;
                virtual void async_send(XML::XMLDocument::Ptr payload,
                                        SendCallback sendCallback) override;

                virtual void negotiateTLS(TLSCallback callback) override;
                virtual void restartStream() override;


                // Must be called prior to connect(). Assigned by the owning client.
                void useContext(std::shared_ptr<IXmppClient> owner, _xmpp_ctx_t *context,
                                const XmppConfig &config, std::shared_ptr<IXmppStream> stream);

                JabberID getBoundJID() const;

            protected:
                void handleStanza(_xmpp_stanza_t *const stanza) const;
            private:
                std::shared_ptr<IXmppClient> m_owner;
                mutable std::recursive_mutex m_mutex;
                _xmpp_ctx_t *m_ctx;
                _xmpp_conn_t *m_conn;
                std::string m_host;
                unsigned short m_port;
                std::shared_ptr<IXmppStream> m_stream;
                std::recursive_mutex m_sendMutex;
        };


        /// @brief Default implementation of an XMPP client that uses an IXmppConnection to
        /// establish XMPP streams for communicating XMPP stanzas.
        /// @ingroup XMPP
        class XMPP_API XmppStropheClient: public std::enable_shared_from_this<XmppStropheClient>,
            public IXmppClient
        {
            public:
                static std::shared_ptr<XmppStropheClient> create();

                virtual ~XmppStropheClient() override;
                XmppStropheClient(const XmppStropheClient &) = delete;

                XmppStropheClient &operator=(const XmppStropheClient &) = delete;

                virtual SyncEvent<XmppStreamCreatedEvent> &onStreamCreated();

                typedef std::shared_ptr<std::promise<std::shared_ptr<IXmppStream>>>
                XmppStreamPromise;

                void initiateXMPP(const XmppConfig &config,
                                  std::shared_ptr<XmppStropheConnection> remoteServer,
                                  XmppStreamPromise xmppConnection = XmppStreamPromise());

            protected:
                XmppStropheClient();
            private:
                std::unique_ptr<XmppClientPimpl, XmppClientPimplDelete> p_;
        };

        typedef XmppStropheClient XmppClient;
    }
}

#endif // DISABLE_SUPPORT_LIBSTROPHE
