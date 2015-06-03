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

/// @file xmppservicedisc.cpp

#include "stdafx.h"

#include "xmppservicedisc.h"
#include "jabberid.h"

#include "../connect/connecterror.h"

#ifndef DISABLE_SUPPORT_XEP0030

using namespace std;
using namespace Iotivity::XML;

namespace Iotivity
{
    namespace Xmpp
    {
        static const string XMPP_SERVICE_DISCOVERY_INFO_NS = "http://jabber.org/protocol/disco#info";
        static const string XMPP_SERVICE_DISCOVERY_ITEMS_NS = "http://jabber.org/protocol/disco#items";


        shared_ptr<XmppServiceDiscovery::Params> XmppServiceDiscovery::Params::create()
        {
            return shared_ptr<Params>(new Params);
        }

        bool XmppServiceDiscovery::Params::supportsExtension(const string &extensionName) const
        {
            return extensionName == XmppServiceDiscovery::extensionName();
        }

        XmppServiceDiscovery::XmppServiceDiscovery(shared_ptr<IXmppStream> overStream):
            XmppExtension(overStream)
        {
        }

        XmppServiceDiscovery::~XmppServiceDiscovery()
        {
            // Called here so any captured this is not stale when the queries halt.
            haltSafeQueries();
        }

        void XmppServiceDiscovery::assignConfiguration(std::shared_ptr<IExtensionParams> config)
        {
            if (config && config->supportsExtension(XmppServiceDiscovery::extensionName()))
            {
                m_config = static_pointer_cast<Params>(config);
            }
        }

        void XmppServiceDiscovery::queryInfo(const JabberID &target, DiscoveryCallback callback)
        {
            XMLElement::Ptr request = constructIQ("get", target.full());
            XMLElement::Ptr query = request->owner()->createElement("query");
            query->setAttribute("xmlns", XMPP_SERVICE_DISCOVERY_INFO_NS);
            request->appendChild(query);

            sendSafeQuery(move(request),
                          [this, callback]
                          (const connect_error & ce, XMLElement::Ptr response)
            {
                if (!ce.succeeded())
                {
                    callback(ce, response);
                    return;
                }

                connect_error result = testAndProcessErrorResponse(response);
                if (result.succeeded())
                {
                    // TODO: Decode response.
                }
                callback(result, response);
            });
        }

        void XmppServiceDiscovery::queryItems(const JabberID &target, DiscoveryCallback callback)
        {
            XMLElement::Ptr request = constructIQ("get", target.full());
            XMLElement::Ptr query = request->owner()->createElement("query");
            query->setAttribute("xmlns", XMPP_SERVICE_DISCOVERY_ITEMS_NS);
            request->appendChild(query);

            sendSafeQuery(move(request),
                          [this, callback]
                          (const connect_error & ce, XMLElement::Ptr response)
            {
                if (!ce.succeeded())
                {
                    callback(ce, response);
                    return;
                }

                connect_error result = testAndProcessErrorResponse(response);
                if (result.succeeded())
                {
                    // TODO: Decode response.
                }
                callback(result, response);
            });
        }

    }
}

#endif


