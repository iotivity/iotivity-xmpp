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

/// @file xmppservicedisc.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "xmppextension.h"

#include <map>

// @file xmppservicedisc.h
// XEP-0030 [Service Discovery]

#ifndef DISABLE_SUPPORT_XEP0030

namespace Iotivity
{
    namespace Xmpp
    {
        // XEP-0030 Service Discovery
        class XmppServiceDiscovery: public XmppExtension
        {
            public:
                class XMPP_API Params: public IExtensionParams
                {
                    public:
                        Params() = default;
                        Params(const Params &) = default;
                        static std::shared_ptr<Params> create();

                        virtual bool supportsExtension(const std::string &extensionName) const override;
                };
            public:
                XmppServiceDiscovery(std::shared_ptr<IXmppStream> overStream);
                virtual ~XmppServiceDiscovery() override;

                static std::string extensionName() { return "XEP0030"; }
                virtual std::string getExtensionName() const override
                {
                    return XmppServiceDiscovery::extensionName();
                }

                virtual void assignConfiguration(std::shared_ptr<IExtensionParams> config) override;

                typedef std::function<void(const connect_error &,
                                           const XML::XMLElement::Ptr &)> DiscoveryCallback;
                void queryInfo(const JabberID &target, DiscoveryCallback callback);
                void queryItems(const JabberID &target, DiscoveryCallback callback);


            private:
                std::shared_ptr<Params> m_config;
        };
    }
}

#endif

