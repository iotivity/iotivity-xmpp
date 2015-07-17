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

/// @file servicedisc_tests.cpp

#include "stdafx.h"
#include <gtest/gtest.h>

#include <xmpp/xmppservicedisc.h>
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
#endif
}



using namespace std;
using namespace Iotivity;
using namespace Iotivity::Xmpp;
using namespace Iotivity::XML;


#ifndef DISABLE_SUPPORT_XEP0030

#ifdef ENABLE_FUNCTIONAL_TESTING
TEST(ServiceDiscovery, XEP_0030_Discovery_Info)
#else
TEST(ServiceDiscovery, DISABLED_XEP_0030_Discovery_Info)
#endif
{
    shared_ptr<IXmppClient> client;
    shared_ptr<IXmppStream> stream;
    xmpp_test_default_connect_client(stream, client);
    EXPECT_NE(client, nullptr);
    ASSERT_NE(stream, nullptr);

    try
    {
        XmppServiceDiscovery serviceDisc(stream);

        string xmppDomain;
#ifdef ENABLE_LIBSTROPHE
        xmppDomain = xmpp_connect_config::xmppDomain("NO_PROXY");
#else
        xmppDomain = xmpp_connect_config::xmppDomain();
#endif

        promise<void> queriedPromise;
        future<void> queried = queriedPromise.get_future();
        serviceDisc.queryInfo(xmppDomain,
                              [&queriedPromise](const connect_error & ce,
                                                const XMLElement::Ptr & e)
        {
            auto activeQuery = move(queriedPromise);

            EXPECT_TRUE(ce.succeeded());
            cout << "RESULT: " << ce.toString() << endl;
            EXPECT_NE(e, nullptr);
            if (e)
            {

            }

            activeQuery.set_value();
        });


        queried.get();

        stream->close();
    }
    catch (...)
    {
        EXPECT_NO_THROW(throw);
    }
}


#ifdef ENABLE_FUNCTIONAL_TESTING
TEST(ServiceDiscovery, XEP_0030_Items_Info)
#else
TEST(ServiceDiscovery, DISABLED_XEP_0030_Items_Info)
#endif
{
    shared_ptr<IXmppClient> client;
    shared_ptr<IXmppStream> stream;
    xmpp_test_default_connect_client(stream, client);
    EXPECT_NE(client, nullptr);
    ASSERT_NE(stream, nullptr);

    try
    {
        XmppServiceDiscovery serviceDisc(stream);

        string xmppDomain;
#ifdef ENABLE_LIBSTROPHE
        xmppDomain = xmpp_connect_config::xmppDomain("NO_PROXY");
#else
        xmppDomain = xmpp_connect_config::xmppDomain();
#endif

        promise<void> queriedPromise;
        future<void> queried = queriedPromise.get_future();
        serviceDisc.queryItems(xmppDomain,
                               [&queriedPromise](const connect_error & ce,
                                       const XMLElement::Ptr & e)
        {
            auto activeQuery = move(queriedPromise);

            EXPECT_TRUE(ce.succeeded());
            cout << "RESULT: " << ce.toString() << endl;
            EXPECT_NE(e, nullptr);
            if (e)
            {

            }

            activeQuery.set_value();
        });


        queried.get();

        stream->close();
    }
    catch (...)
    {
        EXPECT_NO_THROW(throw);
    }

}


#endif // DISABLE_SUPPORT_XEP0030

