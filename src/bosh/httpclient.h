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

/// @file httpclient.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "../connect/connecterror.h"
#include "../connect/curlconnect.h"
#include "../xml/portabledom.h"

#include <string>
#include <iostream>
#include <sstream>
#include <chrono>
#include <list>


#ifndef DISABLE_SUPPORT_BOSH

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

        /// Provides an interface for an HTTP connection which supports BOSH primitives (POST)
        class IHttpConnection
        {
            public:
                virtual ~IHttpConnection() {}

                virtual void close() = 0;
                virtual void postHttp(const std::list<std::string> &headers,
                                      const std::string &body) = 0;
                virtual void performSynchronousConnect() = 0;
                virtual std::string response() const = 0;
        };


        /// @brief An HTTP connection which provides support for a BOSH connection for XMPP.
        ///
        /// @note HttpConnection is NOT intended to be used from multiple threads simultaneously.
        /// Plan accordingly.
        ///
        /// @ingroup BOSH
        class HttpCurlConnection: public CurlConnection, public IHttpConnection
        {
            public:
                HttpCurlConnection();
                HttpCurlConnection(const std::string &url);
                virtual ~HttpCurlConnection() override;

                bool isValid() const { return curl() != nullptr; }

                void setRequestTimeout(const std::chrono::milliseconds &ms);

                virtual void close() override;
                virtual void postHttp(const std::list<std::string> &headers,
                                      const std::string &body) override;

                virtual void performSynchronousConnect() override;

                virtual std::string response() const override { return m_response.str(); }


            protected:
                virtual void curlDebugCallback(infotype_t type,
                                               const std::string &data) const override;
                void writeCallback(const std::string &data);
                void headerCallback(const std::string &data);

            private:
                void initCurl(const std::string &url);

                HttpCurlConnection(const HttpCurlConnection &) = delete;
                HttpCurlConnection &operator=(const HttpCurlConnection &) = delete;

                std::ostringstream m_response;

                static void forceGlobalCurlInit();
        };


    }
}

#endif // DISABLE_SUPPORT_BOSH
