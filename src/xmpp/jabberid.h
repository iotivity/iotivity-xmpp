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

/// @file jabberid.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "xmppinterfaces.h"

#include <string>

#ifdef _WIN32
XMPP_TEMPLATE template class XMPP_API std::basic_string<char, std::char_traits<char>,
        std::allocator<char>>;
#endif

namespace Iotivity
{
    namespace Xmpp
    {
        class IStreamConnection;

        /// @brief Simple structure for manipulating a JabberID.
        /// @ingroup XMPP
        class XMPP_API JabberID
        {
            public:
                JabberID() = default;
                JabberID(const std::string &id): m_jabberID(id) {}
                JabberID(const JabberID &) = default;
                JabberID(JabberID &&jid) { m_jabberID = std::move(jid.m_jabberID); }

                JabberID &operator=(const JabberID &) = default;
                JabberID &operator=(const JabberID &&jid)
                {
                    m_jabberID = std::move(jid.m_jabberID); return *this;
                }

                bool operator==(const JabberID &jid) const { return m_jabberID == jid.m_jabberID; }
                bool operator!=(const JabberID &jid) const { return m_jabberID != jid.m_jabberID; }

                explicit operator std::string() const { return m_jabberID; }
                std::string full() const { return m_jabberID; }

            private:
                std::string m_jabberID;
        };

        typedef JabberID JID;

    }
}


