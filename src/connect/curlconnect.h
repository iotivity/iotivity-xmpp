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

/// @file curlconnect.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "connecterror.h"

#include <list>
#include <set>

// We are avoiding including curl.h in the header, but we are assuming that CURL is defined
// as it is defined in the curl.h header. If this changes then this definition will be invalid and
// must be changed.
typedef void CURL;
typedef unsigned int infotype_t;
struct curl_slist;

namespace Iotivity
{
    namespace Xmpp
    {
        class ProxyConfig;

        /// @brief Provides an HTTP connection using the libcurl library.
        class CurlConnection
        {
            public:
                CurlConnection();
                ~CurlConnection();
                CurlConnection(const CurlConnection &) = delete;

                CurlConnection &operator=(const CurlConnection &) = delete;

                virtual void setUrl(const std::string &url);
                virtual void setProxy(const ProxyConfig &proxy);
                //virtual void proxyTunnel(bool tunnel);

            protected:
                virtual void curlDebugCallback(infotype_t type, const std::string &data) const;

                CURL *curl() const { return m_curl; }
                void purgeSLists();

                void attachSList(curl_slist *);
                void detachSList(curl_slist *);

            private:
                CURL *m_curl;
                std::set<curl_slist *> m_slists;
                static void forceGlobalCurlInit();

                friend struct SList;
        };


        /// @brief Wrapper for CURL SList objects.
        ///
        /// This object must be used only within the context of a valid CurlConnection and
        /// is only valid while the CurlConnection is valid.
        ///
        /// @note Note that the CurlConnection owns the underlying slists of this object so that
        /// the cleanup may happen only after the slist has been used by curl.
        struct SList
        {
                explicit SList(CurlConnection &owner);
                SList(const SList &) = delete;

                SList &operator=(const SList &) = delete;

                bool isValid() const { return m_slist != nullptr; }
                void push_back(const std::list<std::string> &strings);

                curl_slist *getSList() const { return m_slist; }
                operator curl_slist *() const { return m_slist; }

            private:
                CurlConnection &m_owner;
                curl_slist *m_slist;
        };


    }
}
