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

/// @file xmppconfig.h

#pragma once

#include "../include/xmpp_feature_flags.h"

#include "../xmpp/xmppinterfaces.h"
#include "../xmpp/jabberid.h"


namespace Iotivity
{
    namespace Xmpp
    {
        struct XmppConfigImpl;

        /// @cond HIDDEN_SYMBOLS
        // Xmpp Config Impl unique_ptr delete helper
        struct XmppConfigImplDelete
        {
            void operator()(XmppConfigImpl *);
        };
        /// @endcond

    }
}


#ifdef _WIN32
XMPP_TEMPLATE template class XMPP_API std::unique_ptr<Iotivity::Xmpp::XmppConfigImpl,
        Iotivity::Xmpp::XmppConfigImplDelete>;
#endif


namespace Iotivity
{
    namespace Xmpp
    {
        /// @ingroup XMPP
        /// @brief Configuration parameters for an XMPP client instance.
        class XMPP_API XmppConfig
        {
            public:
                XmppConfig();
                XmppConfig(const JabberID &initiator, const std::string &host);
                XmppConfig(const XmppConfig &);
                XmppConfig(XmppConfig &&);
                ~XmppConfig();

                XmppConfig &operator=(const XmppConfig &);

                void requireTLSNegotiation();
                bool isRequiringTLS() const;

                // Override the default order for SASL mechanism selection. If this is unchanged,
                // the SASL mechanism will be selected using registration order (controlled elsewhere)
                void overrideSASLOrder(const std::list<std::string> &order);

                JabberID initiator() const;
                std::string host() const;
                std::list<std::string> SASLOrder() const;

                void setSaslConfig(const std::string &mechanism, std::shared_ptr<ISaslParams> config);
                std::shared_ptr<ISaslParams> saslConfig(const std::string &mechanism) const;

                void setExtensionConfig(const std::string &extensionName,
                                        std::shared_ptr<IExtensionParams> config);
                std::shared_ptr<IExtensionParams> extensionConfig(const std::string &
                        extensionName) const;

                void setLanguage(const std::string &);
                std::string language() const;

#ifndef DISABLE_SUPPORT_XEP0077
                void requestInBandRegistration(bool request = true);
                bool isRequestingInBandRegistration();
#endif

            private:
                std::unique_ptr<XmppConfigImpl, XmppConfigImplDelete> p_;
        };

    }
}