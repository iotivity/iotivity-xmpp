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

/// @file xmppconfig.cpp

#include "stdafx.h"

#include "xmppconfig.h"


using namespace std;
using namespace Iotivity;
using namespace Iotivity::XML;

namespace Iotivity
{
    namespace Xmpp
    {
        //////////
        /// @cond HIDDEN_SYMBOLS
        // XmppConfig implementation details (to hide std::map for Windows DLL Export)
        struct XmppConfigImpl
        {
            XmppConfigImpl(const JabberID &initiator, const std::string &host):
                m_initiator(initiator), m_host(host), m_requiresTLS(false), m_saslOrder(),
                m_mechanismParams(), m_extensionParams(), m_lang("en"),
                m_inBandRegistration(false)
            {}

            XmppConfigImpl(const XmppConfigImpl &) = default;

            // NOTE: We are not defaulting this constructor as the MSVC target compiler
            //       fails to recognize this as a defaultable function.
            XmppConfigImpl(XmppConfigImpl &&xc)
            {
                m_initiator = move(xc.m_initiator);
                m_host = move(xc.m_host);
                m_requiresTLS = move(xc.m_requiresTLS);
                m_saslOrder = move(xc.m_saslOrder);
                m_mechanismParams = move(xc.m_mechanismParams);
                m_extensionParams = move(xc.m_extensionParams);
                m_lang = move(xc.m_lang);
                m_inBandRegistration = move(xc.m_inBandRegistration);
            }

            XmppConfigImpl &operator=(const XmppConfigImpl &) = default;

            JabberID m_initiator;
            string m_host;
            bool m_requiresTLS;
            list<string> m_saslOrder;
            map<string, shared_ptr<ISaslParams>> m_mechanismParams;
            map<string, shared_ptr<IExtensionParams>> m_extensionParams;
            string m_lang;
            bool m_inBandRegistration;
        };
        /// @endcond

        void XmppConfigImplDelete::operator()(XmppConfigImpl *p)
        {
            delete p;
        }


        //////////
        XmppConfig::XmppConfig():
            p_(new XmppConfigImpl(JabberID(""), ""))
        {}

        XmppConfig::XmppConfig(const JabberID &initiator, const std::string &host):
            p_(new XmppConfigImpl(initiator, host))
        {}

        XmppConfig::XmppConfig(const XmppConfig &xc):
            p_(new XmppConfigImpl(*xc.p_))
        {}

        XmppConfig::XmppConfig(XmppConfig &&xc)
        {
            *p_ = move(*xc.p_);
        }

        XmppConfig::~XmppConfig() {}

        XmppConfig &XmppConfig::operator=(const XmppConfig &xc)
        {
            *p_ = *xc.p_;
            return *this;
        }

        void XmppConfig::requireTLSNegotiation() { p_->m_requiresTLS = true; }
        bool XmppConfig::isRequiringTLS() const { return p_->m_requiresTLS; }

        // Override the default order for SASL mechanism selection. If this is unchanged,
        // the SASL mechanism will be selected using registration order (controlled elsewhere)
        void XmppConfig::overrideSASLOrder(const std::list<std::string> &order)
        {
            p_->m_saslOrder = order;
        }

        JabberID XmppConfig::initiator() const { return p_->m_initiator; }
        string XmppConfig::host() const { return p_->m_host; }
        list<string> XmppConfig::SASLOrder() const { return p_->m_saslOrder; }

        void XmppConfig::setSaslConfig(const string &mechanism, shared_ptr<ISaslParams> config)
        {
            p_->m_mechanismParams[mechanism] = config;
        }

        shared_ptr<ISaslParams> XmppConfig::saslConfig(const string &mechanism) const
        {
            const auto f = p_->m_mechanismParams.find(mechanism);
            return f != p_->m_mechanismParams.end() ? f->second : shared_ptr<ISaslParams>();
        }

        void XmppConfig::setExtensionConfig(const string &extensionName,
                                            shared_ptr<IExtensionParams> config)
        {
            p_->m_extensionParams[extensionName] = config;
        }

        shared_ptr<IExtensionParams> XmppConfig::extensionConfig(const string &extensionName) const
        {
            const auto f = p_->m_extensionParams.find(extensionName);
            return f != p_->m_extensionParams.end() ? f->second : shared_ptr<IExtensionParams>();
        }

        void XmppConfig::setLanguage(const std::string &lang)
        {
            p_->m_lang = lang;
        }

        string XmppConfig::language() const
        {
            return p_->m_lang;
        }

#ifndef DISABLE_SUPPORT_XEP0077
        void XmppConfig::requestInBandRegistration(bool request)
        {
            p_->m_inBandRegistration = request;
        }

        bool XmppConfig::isRequestingInBandRegistration()
        {
            return p_->m_inBandRegistration;
        }
#endif



    }
}

