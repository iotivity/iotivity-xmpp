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

/// @file xmppstream.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "../xmpp/xmppinterfaces.h"

#include <string>
#include <chrono>
#include <map>

namespace Iotivity
{
    namespace Xmpp
    {
        class XmppStreamBase: public IXmppStream
        {
            public:
                XmppStreamBase();
                XmppStreamBase(const XmppStreamBase &) = delete;
                XmppStreamBase &operator=(const XmppStreamBase &) = delete;
                virtual ~XmppStreamBase() _NOEXCEPT {}

                virtual std::string getNextID() override;

                virtual SyncEvent<XmppConnectedEvent> &onConnected() override { return m_connected; }
                virtual SyncEvent<XmppClosedEvent> &onClosed() override { return m_closed; }

                virtual void sendQuery(XML::XMLElement::Ptr query, QueryResponse callback) override;
                virtual void haltQuery(const std::string &ID) override;
                virtual void sendMessage(XML::XMLElement::Ptr message) override;

                virtual SyncEvent<XmppMessageEvent> &onMessage() override { return m_onMessage; }

            protected:
                virtual void handleMessage(XML::XMLElement::Ptr message);
                virtual void sendStanza(XML::XMLDocument::Ptr stanza) = 0;


                std::recursive_mutex &mutex() const { return m_mutex; }
            private:
                mutable std::recursive_mutex m_mutex;
                uint64_t m_rollingCounter;

                struct ActiveQuery
                {
                    ActiveQuery(): m_callback(), m_submittedAt(std::chrono::system_clock::now()) {}

                    QueryResponse m_callback;
                    std::chrono::system_clock::time_point m_submittedAt;
                };
                typedef std::map<std::string, ActiveQuery> Queries;
                Queries m_queries;

                OneShotSyncEvent<XmppConnectedEvent> m_connected;
                OneShotSyncEvent<XmppClosedEvent> m_closed;
                SyncEvent<XmppMessageEvent> m_onMessage;
        };
    }
}

