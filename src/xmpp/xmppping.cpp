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

/// @file xmppping.cpp

#include "stdafx.h"

#include "xmppping.h"
#include "jabberid.h"
#include "../connect/connecterror.h"

#ifndef DISABLE_SUPPORT_XEP0199

using namespace std;
using namespace Iotivity::XML;

namespace Iotivity
{
    namespace Xmpp
    {
        static const string XMPP_PING_NS = "urn:xmpp:ping";

        shared_ptr<XmppPing::Params> XmppPing::Params::create()
        {
            return shared_ptr<Params>(new Params);
        }

        bool XmppPing::Params::supportsExtension(const string &extensionName) const
        {
            return extensionName == XmppPing::extensionName();
        }

        XmppPing::XmppPing(shared_ptr<IXmppStream> overStream):
            XmppExtension(overStream)
        {}

        XmppPing::~XmppPing()
        {
            // Called here so any captured this is not stale when the queries halt.
            haltSafeQueries();
        }

        void XmppPing::assignConfiguration(std::shared_ptr<IExtensionParams> config)
        {
            if (config && config->supportsExtension(XmppPing::extensionName()))
            {
                m_config = static_pointer_cast<Params>(config);
            }
        }

        void XmppPing::sendPing(const JabberID &target, PongCallback onPong)
        {
            XMLElement::Ptr request = constructIQ("get", target.full());
            XMLElement::Ptr query = request->owner()->createElement("ping");
            query->setAttribute("xmlns", XMPP_PING_NS);
            request->appendChild(query);

            sendSafeQuery(move(request),
                          [this, onPong]
                          (const connect_error & ce, XMLElement::Ptr response)
            {
                if (!ce.succeeded())
                {
                    onPong(ce);
                    return;
                }

                connect_error result = testAndProcessErrorResponse(response);
                if (result.succeeded())
                {

                }
                onPong(result);
            });
        }


    }
}

#endif

