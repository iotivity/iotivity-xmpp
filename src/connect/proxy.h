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

/// @file proxy.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "../common/bufferencrypt.h"
#include "../include/ccfxmpp.h"
#include <string>


#ifdef _WIN32
XMPP_TEMPLATE template class XMPP_API std::basic_string<char, std::char_traits<char>,
        std::allocator<char>>;
#endif


namespace Iotivity
{
    namespace Xmpp
    {

        /// @brief Provides configuration parameters for establishing a connection over a
        ///        proxy
        ///
        /// Supports configuring HTTP proxy information for BOSH and SOCKS5 proxy information for
        /// direct XMPP connections.
        /// @ingroup TCPIP
        /// @ingroup BOSH
        class XMPP_API ProxyConfig
        {
            public:
                enum class ProxyType
                {
                    ProxyUndefined,
                    ProxyHTTP,
                    ProxySOCKS5
                };

            public:
                ProxyConfig();
                ProxyConfig(const std::string &url);
                ProxyConfig(const std::string &host, const std::string &port, ProxyType type);
                ProxyConfig(const ProxyConfig &) = default;
                ProxyConfig(ProxyConfig &&);

                static ProxyConfig queryProxy();

                ProxyConfig &operator=(const ProxyConfig &) = default;

                ProxyType type() const { return m_proxyType; }
                std::string url() const { return m_urlOrHost; }
                std::string host() const { return m_urlOrHost; }
                std::string port() const { return m_port; }

                std::string userName() const { return m_userName; }
                const SecureBuffer &password() const { return m_password; }


            private:
                ProxyType m_proxyType;
                std::string m_urlOrHost;
                std::string m_port;
                std::string m_userName;
                SecureBuffer m_password;
        };

    }
}
