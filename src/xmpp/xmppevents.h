
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

/// @file xmppevents.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "../connect/connecterror.h"
#include <memory>


namespace Iotivity
{
    namespace Xmpp
    {
        class IXmppStream;
        class IXmppConnection;

        struct XmppBasicEvent
        {
                XmppBasicEvent(const connect_error &errorResult): m_result(errorResult) {}

                connect_error result() const { return m_result; }

            private:
                connect_error m_result;
        };

        struct XmppStreamCreatedEvent: public XmppBasicEvent
        {
                XmppStreamCreatedEvent() = delete;
                XmppStreamCreatedEvent(std::shared_ptr<IXmppStream> stream,
                                       std::shared_ptr<IXmppConnection> remoteServer):
                    XmppBasicEvent(connect_error::SUCCESS), m_stream(stream),
                    m_remoteServer(remoteServer)
                {}
                XmppStreamCreatedEvent(const connect_error &errorResult,
                                       std::shared_ptr<IXmppConnection> remoteServer):
                    XmppBasicEvent(errorResult), m_stream(), m_remoteServer(remoteServer)
                {}

                std::shared_ptr<IXmppStream> stream() const { return m_stream; }
                std::shared_ptr<IXmppConnection> remoteServer() const { return m_remoteServer; }
            private:
                std::shared_ptr<IXmppStream> m_stream;
                std::shared_ptr<IXmppConnection> m_remoteServer;
        };

        struct XmppConnectedEvent: public XmppBasicEvent
        {
                XmppConnectedEvent() = delete;
                XmppConnectedEvent(const connect_error &errorResult):
                    XmppBasicEvent(errorResult), m_boundJID() {}
                XmppConnectedEvent(const connect_error &errorResult, const std::string &boundJID):
                    XmppBasicEvent(errorResult), m_boundJID(boundJID) {}

                std::string boundJID() const { return m_boundJID; }
            private:
                std::string m_boundJID;
        };

        struct XmppClosedEvent: public XmppBasicEvent
        {
            XmppClosedEvent() = delete;
            XmppClosedEvent(const connect_error &errorResult): XmppBasicEvent(errorResult) {}
        };

        struct XmppMessageEvent: public XmppBasicEvent
        {
                XmppMessageEvent() = delete;
                XmppMessageEvent(const connect_error &errorResult, XML::XMLElement::Ptr &&message):
                    XmppBasicEvent(errorResult), m_message(move(message))
                {}

                const XML::XMLElement::Ptr &message() const { return m_message; }

            private:
                XML::XMLElement::Ptr m_message;
        };

    }
}
