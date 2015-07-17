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

/// @file ping_tests.cpp

#include "stdafx.h"
#include <gtest/gtest.h>

#include <xmpp/xmppping.h>
#include <connect/connecterror.h>

#include "xmpp_test_config.h"
#include "xmpp_connect_config.h"
#include "xmpp_connect_establish.h"


extern "C"
{
#if !defined(_WIN32)
#ifdef WITH_SAFE
#include <safe_mem_lib.h>
#include <safe_str_lib.h>
#endif
#endif //WIN32
}



using namespace std;
using namespace Iotivity;
using namespace Iotivity::Xmpp;


#ifndef DISABLE_SUPPORT_XEP0199

#ifdef ENABLE_FUNCTIONAL_TESTING
TEST(Ping, XEP_0199_One_Shot_Ping)
#else
TEST(Ping, DISABLED_XEP_0199_One_Shot_Ping)
#endif
{
    shared_ptr<IXmppClient> client;
    shared_ptr<IXmppStream> stream;
    xmpp_test_default_connect_client(stream, client);
    EXPECT_NE(client, nullptr);
    ASSERT_NE(stream, nullptr);

    try
    {
        string xmppDomain;
#ifdef ENABLE_LIBSTROPHE
        xmppDomain = xmpp_connect_config::xmppDomain("NO_PROXY");
#else
        xmppDomain = xmpp_connect_config::xmppDomain();
#endif

        XmppPing ping(stream);

        promise<void> pingPromise;
        future<void> pinged = pingPromise.get_future();

        ping.sendPing(xmppDomain, [&pingPromise](const connect_error & ce)
        {
            auto promise = move(pingPromise);
            EXPECT_TRUE(ce.succeeded());

            promise.set_value();
        });

        pinged.get();

        stream->close();
    }
    catch (...)
    {}
}

#endif // DISABLE_SUPPORT_XEP0199
