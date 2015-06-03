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

/// @file xmppclient.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "../connect/connecterror.h"
#include "../xml/portabledom.h"
#include "../common/actions.h"
#include "../common/stcqueue.h"
#include "xmppinterfaces.h"
#include "xmppevents.h"

#include <string>
#include <memory>
#include <future>
#include <map>
#include <set>

#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT

namespace Iotivity
{
    class StreamBuffer;
    namespace Xmpp
    {
        class XmppConnection;
        class XmppClient;
        class XmppConfig;
        class IStreamConnection;
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

#ifdef _WIN32
XMPP_TEMPLATE template class XMPP_API std::basic_string<char, std::char_traits<char>,
        std::allocator<char>>;
XMPP_TEMPLATE template class XMPP_API std::weak_ptr<Iotivity::Xmpp::XmppConnection>;
XMPP_TEMPLATE template class XMPP_API std::weak_ptr<Iotivity::Xmpp::XmppClient>;
XMPP_TEMPLATE template class XMPP_API std::shared_ptr<Iotivity::Xmpp::IStreamConnection>;
XMPP_TEMPLATE template class XMPP_API std::shared_ptr<Iotivity::StreamBuffer>;
XMPP_TEMPLATE template class XMPP_API std::unique_ptr<Iotivity::Xmpp::XmppClientPimpl,
        Iotivity::Xmpp::XmppClientPimplDelete>;
XMPP_TEMPLATE template class XMPP_API std::list<std::string>;
class XMPP_API std::recursive_mutex;

#endif

/// @defgroup XMPP XMPP Client Implementation

namespace Iotivity
{
    namespace Xmpp
    {
        class IStreamConnection;

        /// @brief The default implementation of IXmppConnection.
        ///
        /// Provides a connection to an XMPP Server given a stream connection or BOSH
        /// connection to establish the XMPPstream through.
        ///
        /// @ingroup XMPP
        class XMPP_API XmppConnection: public IXmppConnection,
            public std::enable_shared_from_this<XmppConnection>
        {
            public:
                XmppConnection(std::shared_ptr<IStreamConnection> streamConnection);
                virtual ~XmppConnection() _NOEXCEPT override;

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
                size_t parseStanza(const ByteBuffer &buffer, size_t at, size_t forBytes,
                                   XML::XMLElement::Ptr &streamElement);

            private:
                std::recursive_mutex m_mutex;
                bool m_closed;
                std::shared_ptr<IStreamConnection> m_streamConnection;
                bool m_restartPending;
                std::shared_ptr<StreamBuffer> m_workingBuffer;
        };


        /// @brief Default implementation of an XMPP client that uses an IXmppConnection to
        /// establish XMPP streams for communicating XMPP stanzas.
        /// @ingroup XMPP
        class XMPP_API XmppClient: public std::enable_shared_from_this<XmppClient>,
            public IXmppClient
        {
            public:
                static std::shared_ptr<XmppClient> create();

                virtual ~XmppClient() override;
                XmppClient(const XmppClient &) = delete;

                XmppClient &operator=(const XmppClient &) = delete;

                virtual SyncEvent<XmppStreamCreatedEvent> &onStreamCreated();

                virtual void initiateXMPP(const XmppConfig &config,
                                          std::shared_ptr<IXmppConnection> remoteServer,
                                          XmppStreamPromise xmppConnection =
                                              XmppStreamPromise()) override;

            protected:
                XmppClient();

                void sendSynchronousRequest(std::shared_ptr<IXmppConnection> connection,
                                            XML::XMLDocument::Ptr request,
                                            XML::XMLElement::Ptr &response);

                template <typename RequestFunc_>
                void sendSynchronousRequest(std::shared_ptr<IXmppConnection> connection,
                                            RequestFunc_ buildRequest,
                                            XML::XMLElement::Ptr &response,
                                            XML::XMLDocument::DocumentFlags flags =
                                                XML::XMLDocument::DocumentFlags::dfNone)
                {
                    using namespace XML;
                    XMLDocument::Ptr reqDoc = XMLDocument::createEmptyDocument(flags);
                    if (reqDoc)
                    {
                        XMLElement::Ptr sessionRequest = buildRequest(reqDoc);
                        if (sessionRequest)
                        {
                            reqDoc->appendChild(sessionRequest);
                            this->sendSynchronousRequest(connection, reqDoc, response);
                        }
                        else
                        {
                            throw connect_error(LocalError(connect_error::ecOutOfMemory));
                        }
                    }
                    else
                    {
                        throw connect_error(LocalError(connect_error::ecInvalidParameter));
                    }
                }

                void queueReadAction(std::shared_ptr<IXmppStream> stream,
                                     std::shared_ptr<IXmppConnection> remoteServer);

            private:
                friend struct XmppClientRunner;
                // NOTE: It should be noted that the Delete helper is just default
                //       delete behavior. It was added because the presence of the
                //       destructor definition in the object file was not sufficient
                //       for certain compiler flavors to not mark this unique pointer
                //       as an incomplete type.
                std::unique_ptr<XmppClientPimpl, XmppClientPimplDelete> p_;
        };
    }


    /// @brief Provides a factory for creating providers of various Xmpp features.
    ///
    class XmppFeatureFactory
    {
        public:
    };

}

#endif // DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
