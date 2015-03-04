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

/// @file xmppextension.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "xmppinterfaces.h"
#include <map>

// @file xmppextension.h

namespace Iotivity
{
    namespace Xmpp
    {
        /// @brief Base implementation for Xmpp extensions.
        /// @warning When subclassing XmppExtension ALWAYS call haltSafeQueries() from
        ///          within the derived destructor. Create a derived destructor for this if
        ///          one is not otherwise needed. This will ensure that the this pointer captured
        ///          in any query callbacks (made using sendSafeQuery) are valid and point to the
        ///          furthest-derived vtable at all times.
        class XmppExtension: public IXmppExtension
        {
            public:
                XmppExtension(std::shared_ptr<IXmppStream> overStream);
                virtual ~XmppExtension();

            protected:
                std::recursive_mutex &mutex() const { return m_mutex; }

                std::shared_ptr<IXmppStream> stream() const { return m_stream; }

                virtual XML::XMLElement::Ptr constructIQ(const std::string &type,
                        const std::string &to = "");
                virtual connect_error testAndProcessErrorResponse(XML::XMLElement::Ptr &response);

                /// @brief Call sendSafeQuery instead of stream()->sendQuery() when the callback
                ///        needs to capture this. A call to haltSafeQueries in the destructor
                ///        ensures all callbacks are stopped before the this pointer is invalidated.
                void sendSafeQuery(XML::XMLElement::Ptr query, IXmppStream::QueryResponse callback);

                /// @brief Call haltSafeQueries in the furthest-derived destructor to ensure
                ///        all response callbacks finish before the this pointer is invalidated.
                virtual void haltSafeQueries();

            private:
                mutable std::recursive_mutex m_mutex;
                std::recursive_mutex m_safeQueryMutex;
                std::shared_ptr<IXmppStream> m_stream;

                bool m_shuttingDown;
                typedef std::map<std::string, IXmppStream::QueryResponse> SafeQueries;
                SafeQueries m_queries;
        };
    }
}

