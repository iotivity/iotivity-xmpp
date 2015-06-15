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

/// @file httpclient.cpp

#include "stdafx.h"
#include "httpclient.h"
#include "../common/logstream.h"

#include <curl/curl.h>
#include <locale>
#include <sstream>

#ifndef DISABLE_SUPPORT_BOSH

using namespace std;

namespace Iotivity
{
    using namespace XML;
    namespace Xmpp
    {
        //////////
        static_assert(sizeof(curl_infotype) <= sizeof(unsigned int),
                      "Cast of enum curl_infotype to uint not possible."
                      " Increase the size of infotype_t.");

        HttpCurlConnection::HttpCurlConnection()
        {
            initCurl("");
        }

        HttpCurlConnection::HttpCurlConnection(const string &url)
        {
            initCurl(url);
        }

        void HttpCurlConnection::initCurl(const string &url)
        {
            if (curl())
            {
                // TODO: Manage certs
                //curl_easy_setopt(curl, CURLOPT_CAINFO, _certPath.c_str());
                curl_easy_setopt(curl(), CURLOPT_SSL_VERIFYPEER, 1);
                curl_easy_setopt(curl(), CURLOPT_SSL_VERIFYHOST, 2);

                curl_easy_setopt(curl(), CURLOPT_NOSIGNAL, 1L);

                curl_easy_setopt(curl(), CURLOPT_WRITEDATA, reinterpret_cast<void *>(this));
                curl_easy_setopt(curl(), CURLOPT_WRITEFUNCTION, static_cast<curl_write_callback>(
                                     [](char *buffer, size_t size, size_t nitems, void *outstream)
                {
                    size_t written = 0;
                    if (buffer && outstream)
                    {
                        try
                        {
                            string tempStr;
                            tempStr.assign(buffer, size * nitems);

                            reinterpret_cast<HttpCurlConnection *>(outstream)->writeCallback(
                                tempStr);
                            written = tempStr.size();
                        }
                        catch (...) {}
                    }
                    return written;
                }));

                curl_easy_setopt(curl(), CURLOPT_HEADERDATA, reinterpret_cast<void *>(this));
                curl_easy_setopt(curl(), CURLOPT_HEADERFUNCTION, static_cast<curl_write_callback>(
                                     [](char *buffer, size_t size, size_t nitems, void *outstream)
                {
                    size_t written = 0;
                    if (buffer && outstream)
                    {
                        try
                        {
                            string tempStr;
                            tempStr.assign(buffer, size * nitems);

                            reinterpret_cast<HttpCurlConnection *>(outstream)->headerCallback(
                                tempStr);
                            written = tempStr.size();
                        }
                        catch (...) {}
                    }
                    return written;
                }));

                setUrl(url);
            }


//curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, AbortCallback);
//curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, this);
//curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

        }

        HttpCurlConnection::~HttpCurlConnection()
        {
            close();
        }

        void HttpCurlConnection::setRequestTimeout(const chrono::milliseconds &ms)
        {
            if (curl())
            {
                curl_easy_setopt(curl(), CURLOPT_TIMEOUT_MS, static_cast<long>(ms.count()));
            }
        }

        void HttpCurlConnection::close()
        {
            if (curl())
            {
                curl_easy_setopt(curl(), CURLOPT_WRITEFUNCTION, nullptr);
            }
        }

        void HttpCurlConnection::postHttp(const list<string> &headers, const string &body)
        {
            if (curl())
            {
                curl_easy_setopt(curl(), CURLOPT_POST, 1);
                curl_easy_setopt(curl(), CURLOPT_COPYPOSTFIELDS, body.c_str());

                SList header(*this);
                header.push_back(headers);
                if (header.isValid())
                {
                    curl_easy_setopt(curl(), CURLOPT_HTTPHEADER, header.getSList());
                }
            }
        }

        void HttpCurlConnection::performSynchronousConnect()
        {
            if (curl())
            {

                CURLcode result = curl_easy_perform(curl());

                if (result != CURLE_OK)
                {
                    throw connect_error((ECODE)result, connect_error::etCurlError());
                }

                long responseCode = 0;
                curl_easy_getinfo(curl(), CURLINFO_RESPONSE_CODE, &responseCode);
                if (responseCode != 0)
                {
                    // TODO: Add substatus if required.
                    connect_error result((int)responseCode, 0);
                    if (!result.succeeded())
                    {
                        throw result;
                    }
                }

                purgeSLists();
            }
        }

        void HttpCurlConnection::curlDebugCallback(infotype_t type, const string &data) const
        {
            CurlConnection::curlDebugCallback(type, data);

            // TODO: Synchronize?
            WITH_LOG_READS
            (
                curl_infotype infoType = static_cast<curl_infotype>(type);
                dout << "CURL(infoType=" << infoType << "): " << data;
                if (data.size() == 0 || data[data.size() - 1] != '\n') dout << endl;
            )
            }

        void HttpCurlConnection::writeCallback(const string &data)
        {
            m_response << data;
        }

        void HttpCurlConnection::headerCallback(const std::string &)
        {
        }

    }
}

#endif // DISABLE_SUPPORT_BOSH
