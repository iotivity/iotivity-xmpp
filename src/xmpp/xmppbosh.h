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

/// @file xmppbosh.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "xmppinterfaces.h"
#include "../bosh/boshclient.h"

#include <memory>

namespace Iotivity
{
    namespace Xmpp
    {
        class IConnectionManager;
        class IHttpConnection;
        class XmppBOSHConnection;
    }
}

#ifdef _WIN32
XMPP_TEMPLATE template class XMPP_API std::shared_ptr<Iotivity::Xmpp::IConnectionManager>;
XMPP_TEMPLATE template class XMPP_API std::shared_ptr<Iotivity::Xmpp::IHttpConnection>;
XMPP_TEMPLATE template class XMPP_API std::shared_ptr<Iotivity::Xmpp::IBOSHConnection>;
XMPP_TEMPLATE template class XMPP_API std::weak_ptr<Iotivity::Xmpp::XmppBOSHConnection>;
//XMPP_TEMPLATE template class XMPP_API
//std::shared_ptr<Iotivity::NotifySyncBase<Iotivity::Xmpp::BOSHConnectedEvent>>;
#endif


namespace Iotivity
{
    namespace Xmpp
    {

        /// @brief The BOSH implementation of IXmppConnection.
        ///
        /// Provides a connection to an XMPP Server given an HTTP connection
        /// to establish the XMPP stream through the BOSH protocol.
        ///
        /// @ingroup XMPP
        class XMPP_API XmppBOSHConnection : public IXmppConnection,
            public std::enable_shared_from_this<XmppBOSHConnection>
        {
            public:
                XmppBOSHConnection(std::shared_ptr<IConnectionManager> manager,
                                   std::shared_ptr<IHttpConnection> httpConnection,
                                   const BOSHConfig &config);
                virtual ~XmppBOSHConnection() _NOEXCEPT override;

                virtual void connect() override;

                virtual void close() override;
                virtual void send(XML::XMLDocument::Ptr payload) override;
                virtual void receive(XML::XMLElement::Ptr &payload) override;

                virtual void async_receive(ReceiveCallback receiveComplete) override;
                virtual void async_send(XML::XMLDocument::Ptr payload,
                                        SendCallback sendCallback) override;

                virtual void negotiateTLS(TLSCallback callback) override;
                virtual void restartStream() override;

            protected:
                //size_t parseStanza(const ByteBuffer &buffer, size_t at, size_t forBytes,
                //XML::XMLElement::Ptr &streamElement);

            private:
                std::recursive_mutex m_mutex;
                std::shared_ptr<IConnectionManager> m_manager;
                std::shared_ptr<IHttpConnection> m_httpConnection;
                BOSHConfig m_config;
                std::shared_ptr<IBOSHConnection> m_BOSHConnection;
                //NotifySyncBase<BOSHConnectedEvent>::Ptr m_connectedCallback;
                //bool m_closed;
                //std::shared_ptr<IStreamConnection> m_streamConnection;
                //bool m_restartPending;
                //std::shared_ptr<StreamBuffer> m_workingBuffer;
        };
    }
}
