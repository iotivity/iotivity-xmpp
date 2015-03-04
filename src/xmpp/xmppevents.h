
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

        struct XmppStreamCreatedEvent
        {
                XmppStreamCreatedEvent() = delete;
                XmppStreamCreatedEvent(std::shared_ptr<IXmppStream> stream,
                                       std::shared_ptr<IXmppConnection> remoteServer):
                    m_result(connect_error::SUCCESS), m_stream(stream), m_remoteServer(remoteServer)
                {}
                XmppStreamCreatedEvent(const connect_error &errorResult,
                                       std::shared_ptr<IXmppConnection> remoteServer):
                    m_result(errorResult), m_stream(), m_remoteServer(remoteServer)
                {}


                connect_error result() const { return m_result; }
                std::shared_ptr<IXmppStream> stream() const { return m_stream; }
                std::shared_ptr<IXmppConnection> remoteServer() const { return m_remoteServer; }
            private:
                connect_error m_result;
                std::shared_ptr<IXmppStream> m_stream;
                std::shared_ptr<IXmppConnection> m_remoteServer;
        };
    }
}
