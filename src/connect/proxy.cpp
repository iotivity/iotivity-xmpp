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

/// @file proxy.cpp

#include "stdafx.h"
#include "proxy.h"

#ifdef _WIN32
#include <winhttp.h>
#include <codecvt>
#endif

using namespace std;

namespace Iotivity
{
    namespace Xmpp
    {
        //////////
        ProxyConfig::ProxyConfig(): m_proxyType(ProxyType::ProxyUndefined) {}

        ProxyConfig::ProxyConfig(const string &url):
            m_proxyType(ProxyType::ProxyHTTP), m_urlOrHost(url), m_port() {}

        ProxyConfig::ProxyConfig(const string &host, const string &port, ProxyType type):
            m_proxyType(type), m_urlOrHost(host), m_port(port) {}


        ProxyConfig::ProxyConfig(ProxyConfig &&pc)
        {
            m_proxyType = pc.m_proxyType;
            m_urlOrHost = std::move(pc.m_urlOrHost);
            m_port = std::move(pc.m_port);
            m_userName = std::move(pc.m_userName);
            m_password = std::move(pc.m_password);
        }

#ifdef _WIN32
        ProxyConfig ProxyConfig::queryProxy()
        {
            WINHTTP_PROXY_INFO proxyInfo = {0};
            if (WinHttpGetDefaultProxyConfiguration(&proxyInfo) && proxyInfo.lpszProxy)
            {
                wstring_convert<codecvt_utf8<wchar_t>, wchar_t> converter;
                return ProxyConfig(converter.to_bytes(wstring(proxyInfo.lpszProxy)));
            }
            return ProxyConfig();
        }
#elif defined(__APPLE__)
        ProxyConfig ProxyConfig::queryProxy()
        {
            return ProxyConfig();
        }
#else
        ProxyConfig ProxyConfig::queryProxy()
        {
            return ProxyConfig();
        }
#endif


    }
}
