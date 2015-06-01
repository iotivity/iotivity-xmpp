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

/// @file xmppbosh.cpp

#include "stdafx.h"
#include "xmppbosh.h"

#include <iostream>

using namespace std;
using namespace Iotivity::Xmpp;
using namespace Iotivity::XML;

namespace Iotivity
{
    namespace Xmpp
    {
        XmppBOSHConnection::XmppBOSHConnection(shared_ptr<IConnectionManager> manager,
                                               shared_ptr<IHttpConnection> httpConnection,
                                               const BOSHConfig &config):
            m_mutex(),
            m_manager(manager),
            m_httpConnection(httpConnection),
            m_config(config),
            m_BOSHConnection()
        {
            /*
            if (m_manager)
            {
                auto boshConnectedFunc =
                    [](BOSHConnectedEvent & e)
                {
                    (void)e;

                    cout << "BOSH CONNECTED EVENT " << e.result().toString() << endl;
                };
                using BOSHConnectedFunc = NotifySyncFunc<BOSHConnectedEvent,
                      decltype(boshConnectedFunc)>;
                m_connectedCallback = make_shared<BOSHConnectedFunc>(boshConnectedFunc);
                m_manager->onConnected() += m_connectedCallback;
            }
            */
        }

        XmppBOSHConnection::~XmppBOSHConnection() _NOEXCEPT
        {
            //m_manager->onConnected() -= m_connectedCallback;
            try
            {
                close();
            }
            catch (...) {}
        }

        void XmppBOSHConnection::connect()
        {
            if (m_manager && m_httpConnection)
            {
                auto promiseConnection = make_shared<promise<shared_ptr<IBOSHConnection>>>();
                auto connectionFuture = promiseConnection->get_future();

                m_manager->initiateSession(m_config, m_httpConnection, promiseConnection);
                m_BOSHConnection = connectionFuture.get();
            }
            else
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
        }

        void XmppBOSHConnection::close()
        {}

        void XmppBOSHConnection::send(XMLDocument::Ptr payload)
        {
            if (!m_BOSHConnection)
            {
                throw connect_error(connect_error::ecInvalidStream);
            }
            if (!payload)
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
            XMLElement::Ptr element = payload->documentElement();
            if (!element)
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
            m_BOSHConnection->sendRequest(move(element));
        }

        void XmppBOSHConnection::receive(XMLElement::Ptr &payload)
        {
            if (!m_BOSHConnection)
            {
                throw connect_error(connect_error::ecInvalidStream);
            }
            (void) payload;
            cout << "RECEIVE (SYNC)" << endl;
        }

        void XmppBOSHConnection::async_receive(ReceiveCallback receiveComplete)
        {
            if (!m_BOSHConnection)
            {
                throw connect_error(connect_error::ecInvalidStream);
            }
            auto response = m_BOSHConnection->receiveResponse();
            if (response)
            {
                cout << "ASYNC RECEIVE (RESPONSE)" << endl;
                if (response->name() == "body")
                {
                    for (auto && i : response->elements())
                    {
                        if (i->name() == "stream:features")
                        {
                            // Repackage the features into a stream:stream to avoid
                            // having the next layer up need to know anything about BOSH.
                            auto tempDoc = XMLDocument::createEmptyDocument();
                            auto streamHeader = tempDoc->createElement("stream:stream");
                            auto importedNode = tempDoc->importNode(*i);

                            for (auto && attr : i->attributes())
                            {
                                streamHeader->setAttribute(attr->name(), attr->value());
                            }

                            streamHeader->appendChild(importedNode);
                            tempDoc->appendChild(streamHeader);

                            auto streamElement = tempDoc->documentElement();
                            cout << "ASYNC RECEIVE COMPLETION" << endl;
                            receiveComplete(connect_error::SUCCESS, move(streamElement));
                        }
                        else
                        {
                            cout << "ASYNC RECEIVE COMPLETION" << endl;
                            receiveComplete(connect_error::SUCCESS, move(i));
                        }
                    }
                }
                else
                {
                    cout << "ASYNC RECEIVE (NO BODY)" << endl;
                }
            }
            else
            {
                // TODO: Wait on async response...
                // TODO: Remove temp sleep
                this_thread::sleep_for(chrono::milliseconds(100));
                cout << "ASYNC RECEIVE (BLOCKING)" << endl;
                receiveComplete(connect_error::ecStreamWouldBlock, XMLElement::Ptr());

            }
        }

        void XmppBOSHConnection::async_send(XMLDocument::Ptr payload,
                                            SendCallback sendCallback)
        {

            cout << "ASYNC SEND" << endl;
        }

        void XmppBOSHConnection::negotiateTLS(TLSCallback callback)
        {
            if (callback)
            {
                callback(connect_error::SUCCESS);
            }
        }

        void XmppBOSHConnection::restartStream()
        {
            // NO-OP
        }
    }
}

