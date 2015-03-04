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

/// @file xmppextension.cpp

#include "stdafx.h"

#include "xmppextension.h"

#include "../connect/connecterror.h"

using namespace std;
using namespace Iotivity::XML;

namespace Iotivity
{
    namespace Xmpp
    {
        XmppExtension::XmppExtension(shared_ptr<IXmppStream> overStream):
            m_mutex(), m_safeQueryMutex(), m_stream(overStream), m_shuttingDown(false), m_queries()
        {
            if (!m_stream) throw connect_error(LocalError(LocalError::ecInvalidParameter));
        }

        XmppExtension::~XmppExtension()
        {
            m_shuttingDown = true;
            haltSafeQueries();
        }

        XMLElement::Ptr XmppExtension::constructIQ(const std::string &type,
                const std::string &to)
        {
            XMLDocument::Ptr doc = XMLDocument::createEmptyDocument();
            XMLElement::Ptr iq = doc->createElement("iq");
            iq->setAttribute("type", type);
            iq->setAttribute("id", m_stream->getNextID());
            if (to.size() > 0)
            {
                iq->setAttribute("to", to);
            }
            doc->appendChild(iq);
            return iq;
        }

        connect_error XmppExtension::testAndProcessErrorResponse(XMLElement::Ptr &response)
        {
            connect_error result = connect_error::SUCCESS;
            string type;
            if (response->getAttribute("type", type) && type == "error")
            {
                result = connect_error::ecRequestFailed;
            }
            return result;
        }

        void XmppExtension::sendSafeQuery(XMLElement::Ptr query,
                                          IXmppStream::QueryResponse callback)
        {
            if (m_shuttingDown)
            {
                callback(connect_error::ecExtensionInShutdown, XMLElement::Ptr());
                return;
            }
            if (query)
            {
                string id;
                // Safe queries must have a unique id known to the extension.
                if (!query->getAttribute("id", id))
                {
                    id = m_stream->getNextID();
                    query->setAttribute("id", id);
                }
                {
                    lock_guard<recursive_mutex> lock(m_mutex);
                    m_queries[id] = callback;
                }
                m_stream->sendQuery(move(query),
                                    [this, id, callback](const connect_error & ce, XMLElement::Ptr response)
                {
                    {
                        lock_guard<recursive_mutex> lock(m_mutex);
                        m_queries.erase(id);
                    }

                    // NOTE: We do not expect a stream to make more than one of
                    //       these calls at a time, otherwise we should use a
                    //       read lock with haltSafeQueries using a write lock.
                    lock_guard<recursive_mutex> safeLock(m_safeQueryMutex);
                    callback(ce, move(response));
                });
            }
            else
            {
                callback(LocalError(connect_error::ecInvalidParameter), XMLElement::Ptr());
            }
        }

        void XmppExtension::haltSafeQueries()
        {
            {
                lock_guard<recursive_mutex> lock(m_mutex);
                for (const auto &i : m_queries)
                {
                    m_stream->haltQuery(i.first);
                }
                m_queries.clear();
            }

            // Now that halt has happened we won't get any subsequent callbacks from the
            // stream. We may have one in progress, though. Wait for it by acquiring the
            // m_safeQueryMutex.
            lock_guard<recursive_mutex> safeLock(m_safeQueryMutex);
        }


    }
}
