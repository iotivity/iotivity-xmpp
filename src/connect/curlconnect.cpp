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

/// @file curlconnect.cpp

#include "stdafx.h"

#include "curlconnect.h"
#include "proxy.h"
#include <curl/curl.h>

#include <mutex>


using namespace std;

namespace Iotivity
{
    namespace Xmpp
    {

        //////////
        SList::SList(CurlConnection &owner): m_owner(owner), m_slist(nullptr)
        {}

        void SList::push_back(const list<string> &strings)
        {
            m_owner.detachSList(m_slist);
            for (const auto &s : strings)
            {
                m_slist = curl_slist_append(m_slist, s.c_str());
            }
            m_owner.attachSList(m_slist);
        }

        //////////
        CurlConnection::CurlConnection(): m_curl(nullptr), m_slists()
        {
            forceGlobalCurlInit();
            m_curl = curl_easy_init();

            if (m_curl)
            {
#ifdef _DEBUG
                curl_easy_setopt(curl(), CURLOPT_VERBOSE, 1);
                curl_easy_setopt(curl(), CURLOPT_DEBUGDATA, reinterpret_cast<void *>(this));
                curl_easy_setopt(curl(), CURLOPT_DEBUGFUNCTION, static_cast<curl_debug_callback>(
                                     [](CURL * handle, curl_infotype type, char *data, size_t size, void *userptr)
                {
                    if (handle && userptr && data && size > 0)
                    {
                        try
                        {
                            string tempStr;
                            tempStr.assign(data, size);

                            reinterpret_cast<CurlConnection *>(userptr)->curlDebugCallback(
                                static_cast<infotype_t>(type), tempStr);
                        }
                        catch (...) {}
                    }
                    return static_cast<int>(CURLE_OK);
                }));
#endif
            }
        }

        CurlConnection::~CurlConnection()
        {
            if (m_curl)
            {
                purgeSLists();
#ifdef _DEBUG
                curl_easy_setopt(curl(), CURLOPT_VERBOSE, 0);
                curl_easy_setopt(curl(), CURLOPT_DEBUGFUNCTION, nullptr);
                curl_easy_setopt(curl(), CURLOPT_DEBUGDATA, nullptr);
#endif
                curl_easy_cleanup(m_curl);
            }
        }

        void CurlConnection::setUrl(const string &url)
        {
            if (m_curl)
            {
                CURLcode result = curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str());
                (void) result;
            }
        }

        void CurlConnection::setProxy(const ProxyConfig &pc)
        {
            if (m_curl)
            {
                switch (pc.type())
                {
                    case ProxyConfig::ProxyType::ProxyHTTP:
                        curl_easy_setopt(m_curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
                        curl_easy_setopt(m_curl, CURLOPT_PROXY, pc.url().c_str());
                        break;
                    default:
                        break;
                }
            }
        }

        void CurlConnection::attachSList(curl_slist *sl)
        {
            if (sl != nullptr)
            {
                m_slists.insert(sl);
            }
        }

        void CurlConnection::detachSList(curl_slist *sl)
        {
            if (sl != nullptr)
            {
                m_slists.erase(sl);
            }
        }

        void CurlConnection::curlDebugCallback(infotype_t, const string &) const {}

        void CurlConnection::purgeSLists()
        {
            if (m_curl)
            {
                for (auto sl : m_slists)
                {
                    curl_slist_free_all(sl);
                }
                m_slists.clear();
            }
        }

        void CurlConnection::forceGlobalCurlInit()
        {
            static once_flag s_callOnce;

            call_once(s_callOnce, []()
            {
                if (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK)
                {
                    atexit([]() { curl_global_cleanup(); });

                    // Add global_init_mem here if needed. // curl_global_init_mem(...);
                }
            });
        }


        // Construct a global instance at static init to ensure curl_global_init() is called early.
        volatile CurlConnection g_forceInit;


    }
}
