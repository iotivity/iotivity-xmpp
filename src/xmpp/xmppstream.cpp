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

/// @file xmppstream.cpp

#include "stdafx.h"
#include "xmppstream.h"
#include "xmppevents.h"

#include "../connect/connecterror.h"
#include "../common/rand_helper.h"
#include "../common/bufferencrypt.h"
#include "../common/logstream.h"

using namespace std;
using namespace Iotivity::XML;

namespace Iotivity
{
    namespace Xmpp
    {
        XmppStreamBase::XmppStreamBase():
            m_mutex(), m_rollingCounter(0), m_queries(), m_connected(m_mutex), m_closed(m_mutex),
            m_onMessage(m_mutex)
        {
            mt19937 &rand = rand_helper::rng();
            uniform_int_distribution<uint32_t> rngSelector(0, numeric_limits<uint32_t>::max());
            m_rollingCounter = rngSelector(rand);
        }

        std::string XmppStreamBase::getNextID()
        {
            // Query for id.
            // NOTE: We don't care about the rolling counter endianness. The IDs
            //       must be unique, it doesn't really matter in what way.
            SecureBuffer tempBuffer(&m_rollingCounter, sizeof(m_rollingCounter));

            // TODO: Increment rolling counter by random amount?
            ++m_rollingCounter;

            SecureBuffer encodedBuffer;
            if (tempBuffer.base64Encode(encodedBuffer))
            {
                encodedBuffer.write("");
#ifdef USE_ID_HEADER
                return ID_HEADER + string((const char *)&encodedBuffer[0], encodedBuffer.size());
#else
                return string((const char *)&encodedBuffer[0], encodedBuffer.size());
#endif
            }
            else
            {
                throw connect_error(LocalError(LocalError::ecOutOfMemory));
            }
        }

        void XmppStreamBase::sendQuery(XMLElement::Ptr query, QueryResponse callback)
        {
            if (!query)
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
            string id;
            if (!query->getAttribute("id", id))
            {
                id = getNextID();
                query->setAttribute("id", id);
            }

            {
                lock_guard<recursive_mutex> lock(m_mutex);

                if (m_queries.find(id) != m_queries.end())
                {
                    throw connect_error(connect_error::ecQueryIDAlreadySubmitted);
                }
                m_queries[id].m_callback = callback;
            }

            sendStanza(query->owner());
        }

        void XmppStreamBase::haltQuery(const std::string &id)
        {
            lock_guard<recursive_mutex> lock(m_mutex);
            auto f = m_queries.find(id);
            if (f != m_queries.end())
            {
                m_queries.erase(f);
            }
        }

        void XmppStreamBase::sendMessage(XML::XMLElement::Ptr message)
        {
            if (!message)
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }

            sendStanza(message->owner());
            // TODO: Valid message. (optional id embedded?)
        }


        void XmppStreamBase::handleMessage(XMLElement::Ptr message)
        {
            if (message)
            {
                string id;
                if (message->getAttribute("id", id))
                {
                    QueryResponse callback;
                    {
                        lock_guard<recursive_mutex> lock(m_mutex);
                        auto f = m_queries.find(id);
                        if (f != m_queries.end())
                        {
                            callback = f->second.m_callback;
                            m_queries.erase(f);
                        }
                    }

                    if (callback)
                    {
                        callback(connect_error::SUCCESS, move(message));
                    }
                    else
                    {
                        onMessage().fire(XmppMessageEvent(connect_error::SUCCESS, move(message)));
                    }
                }
                else
                {
                    WITH_LOG_WARNINGS
                    (
                        dout << "XmppStream message received with unknown id:" <<
                        endl << message->xml() << endl;
                    )
                    // TODO: Meta-Handler
                }
            }
        }
    }
}


