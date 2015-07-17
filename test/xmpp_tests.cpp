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

/// @file xmpp_tests.cpp

#include "stdafx.h"
#include <gtest/gtest.h>
#include <algorithm>

#ifdef ENABLE_LIBSTROPHE
#include <xmpp/xmppstrophe.h>
#else
#include <xmpp/xmppclient.h>
#endif
#include <xmpp/xmppconfig.h>
#include <xmpp/sasl.h>
#include <xmpp/jabberid.h>
#include <connect/tcpclient.h>
#include <connect/proxy.h>
#include <bosh/httpclient.h>
#include <bosh/boshclient.h>
#include <common/buffers.h>
#include <common/logstream.h>
#include <common/str_helpers.h>
#include <xml/portabledom.h>

#include "xmpp_test_config.h"
#include "xmpp_dummy_server.h"
#include "xmpp_connect_config.h"

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


TEST(XmppClient, XMPPConfig)
{
    list<string> saslTestOrder;
    saslTestOrder.push_back("PLAIN");
    saslTestOrder.push_back("EXTERNAL");
    saslTestOrder.push_back("ANONYMOUS");

    XmppConfig config(MY_JID, DUMMY_TEST_HOST);
    EXPECT_EQ(config.initiator(), MY_JID);
    EXPECT_EQ(config.host(), DUMMY_TEST_HOST);
    EXPECT_EQ(config.language(), "en");
#ifndef DISABLE_SUPPORT_XEP0077
    EXPECT_FALSE(config.isRequestingInBandRegistration());
#endif

    config.setLanguage("es");

    config.overrideSASLOrder(saslTestOrder);
    EXPECT_EQ(config.SASLOrder(), saslTestOrder);

#ifndef DISABLE_SUPPORT_XEP0077
    config.requestInBandRegistration();
    EXPECT_TRUE(config.isRequestingInBandRegistration());

#endif

    XmppConfig copyConfig(config);
    EXPECT_EQ(copyConfig.initiator(), MY_JID);
    EXPECT_EQ(copyConfig.host(), DUMMY_TEST_HOST);
    EXPECT_EQ(copyConfig.SASLOrder(), saslTestOrder);
    EXPECT_EQ(copyConfig.language(), "es");
#ifndef DISABLE_SUPPORT_XEP0077
    EXPECT_TRUE(copyConfig.isRequestingInBandRegistration());
#endif

    XmppConfig moveConfig;
    EXPECT_EQ(moveConfig.initiator().full(), "");
    EXPECT_EQ(moveConfig.host(), "");
    moveConfig = std::move(config);
    EXPECT_EQ(moveConfig.initiator(), MY_JID);
    EXPECT_EQ(moveConfig.language(), "es");
    EXPECT_EQ(moveConfig.host(), DUMMY_TEST_HOST);
    EXPECT_EQ(moveConfig.SASLOrder(), saslTestOrder);
#ifndef DISABLE_SUPPORT_XEP0077
    EXPECT_TRUE(moveConfig.isRequestingInBandRegistration());
#endif
}



#ifdef ENABLE_FUNCTIONAL_TESTING
TEST(XmppClient, XMPP_StreamEstablish)
#else
TEST(XmppClient, DISABLED_XMPP_StreamEstablish)
#endif
{
#ifdef ENABLE_LIBSTROPHE
    if (!xmpp_connect_config::hasConfig("NO_PROXY"))
#else
    if (!xmpp_connect_config::hasConfig())
#endif
    {
        cout << "XMPP_StreamEstablish skipped. No DEFAULT XMPP config." << endl;
        return;
    }

#ifdef ENABLE_LIBSTROPHE
    auto xmlConnection = make_shared<XmppStropheConnection>(xmpp_connect_config::host("NO_PROXY"),
                         xmpp_connect_config::port("NO_PROXY"));
#else
    const Iotivity::Xmpp::ProxyConfig proxy(xmpp_connect_config::proxyHost(),
                                            xmpp_connect_config::proxyPort(),
                                            Iotivity::Xmpp::ProxyConfig::ProxyType::ProxySOCKS5);
    auto remoteTcp = make_shared<TcpConnection>(xmpp_connect_config::host(),
                     xmpp_connect_config::port(), proxy);

    auto xmlConnection = make_shared<XmppConnection>(
                             static_pointer_cast<IStreamConnection>(remoteTcp));
#endif // ENABLE_LIBSTROPHE

    auto streamPromise = make_shared<promise<shared_ptr<IXmppStream>>>();
    auto streamFuture = streamPromise->get_future();

    SecureBuffer password;
    password.write(xmpp_connect_config::password());
    auto scramConfig = SaslScramSha1::Params::create(xmpp_connect_config::userName(), password);
    auto plainConfig = SaslPlain::Params::create(xmpp_connect_config::userName(), password);

#ifdef ENABLE_LIBSTROPHE
    XmppConfig config(JabberID(xmpp_connect_config::userJID("NO_PROXY")),
                      xmpp_connect_config::xmppDomain("NO_PROXY"));
#else
    XmppConfig config(JabberID(xmpp_connect_config::userJID()), xmpp_connect_config::xmppDomain());
#endif
    config.requireTLSNegotiation();
    config.setSaslConfig("SCRAM-SHA-1", scramConfig);
    config.setSaslConfig("PLAIN", plainConfig);

    auto client = XmppClient::create();
    ASSERT_NO_THROW(client->initiateXMPP(config, xmlConnection, streamPromise));

    shared_ptr<IXmppStream> xmppStream;
    EXPECT_NO_THROW(xmppStream = streamFuture.get());
    EXPECT_NE(xmppStream, nullptr);
    if (xmppStream)
    {
        cout << "GOT STREAM FUTURE" << endl;
        ASSERT_TRUE(xmppStream->whenNegotiated().valid());

        auto status = xmppStream->whenNegotiated().wait_for(chrono::seconds(10));
#if __cplusplus>=201103L || defined(_WIN32)
        EXPECT_EQ(status, future_status::ready);
        if (status == future_status::ready)
#else
        EXPECT_TRUE(status);
        if (status)
#endif
        {
            try
            {
                xmppStream->whenNegotiated().get();
                auto doc = XMLDocument::createEmptyDocument();
                auto message = doc->createElement("iq");
                message->setAttribute("type", "get");
                message->setAttribute("id", xmppStream->getNextID());
#ifdef ENABLE_LIBSTROPHE
                message->setAttribute("to", xmpp_connect_config::xmppDomain("NO_PROXY"));
#else
                message->setAttribute("to", xmpp_connect_config::xmppDomain());
#endif

                auto query = doc->createElement("query");
                query->setAttribute("xmlns", "http://jabber.org/protocol/disco#info");

                message->appendChild(query);
                doc->appendChild(message);

                promise<void> ready;
                future<void> readyFuture = ready.get_future();
                xmppStream->sendQuery(move(message),
                                      [&ready](const connect_error &, XMLElement::Ptr)
                {
                    promise<void> localReady = move(ready);
                    localReady.set_value();
                });
                readyFuture.wait_for(chrono::seconds(2));
            }
            catch (...)
            {
                EXPECT_NO_THROW(throw);
            }
        }
    }
}



#ifdef ENABLE_FUNCTIONAL_TESTING
TEST(XmppClient, XMPP_StreamEstablish_Event_Callbacks)
#else
TEST(XmppClient, DISABLED_XMPP_StreamEstablish_Event_Callbacks)
#endif
{

#ifdef ENABLE_LIBSTROPHE
    if (!xmpp_connect_config::hasConfig("NO_PROXY"))
#else
    if (!xmpp_connect_config::hasConfig())
#endif
    {
        cout << "XMPP_StreamEstablish_Event_Callbacks skipped. No DEFAULT XMPP config." << endl;
        return;
    }

#ifdef ENABLE_LIBSTROPHE
    auto xmlConnection = make_shared<XmppStropheConnection>(xmpp_connect_config::host("NO_PROXY"),
                         xmpp_connect_config::port("NO_PROXY"));
#else
    const Iotivity::Xmpp::ProxyConfig proxy(xmpp_connect_config::proxyHost(),
                                            xmpp_connect_config::proxyPort(),
                                            Iotivity::Xmpp::ProxyConfig::ProxyType::ProxySOCKS5);
    auto remoteTcp = make_shared<TcpConnection>(xmpp_connect_config::host(),
                     xmpp_connect_config::port(), proxy);

    auto xmlConnection = make_shared<XmppConnection>(
                             static_pointer_cast<IStreamConnection>(remoteTcp));
#endif // ENABLE_LIBSTROPHE

    SecureBuffer password;
    password.write("unitTestPassword");
    auto scramConfig = SaslScramSha1::Params::create("unittest", password);
    auto plainConfig = SaslPlain::Params::create("unittest", password);

#ifdef ENABLE_LIBSTROPHE
    XmppConfig config(JabberID("unittest@xmpp.local"), xmpp_connect_config::xmppDomain("NO_PROXY"));
#else
    XmppConfig config(JabberID(""), xmpp_connect_config::xmppDomain());
#endif
    config.requireTLSNegotiation();
    config.setSaslConfig("SCRAM-SHA-1", scramConfig);
    config.setSaslConfig("PLAIN", plainConfig);

    auto client = XmppClient::create();
    promise<void> streamCallbackPromise, openCallbackPromise, closedCallbackPromise;
    future<void> streamCallbackFuture = streamCallbackPromise.get_future(),
                 openCallbackFuture = openCallbackPromise.get_future(),
                 closedCallbackFuture = closedCallbackPromise.get_future();

    auto connectedFunc = [&openCallbackPromise](XmppConnectedEvent & connected)
    {
        if (connected.result().succeeded())
        {
            openCallbackPromise.set_value();
        }
        else
        {
            try
            {
                cout << "CONNECTED FAILURE " << connected.result().toString() << endl;
                throw connected.result();
            }
            catch (const connect_error &)
            {
                openCallbackPromise.set_exception(current_exception());
            }
        }
    };
    auto closedFunc = [&closedCallbackPromise](XmppClosedEvent & closed)
    {
        if (closed.result().succeeded() ||
            closed.result() == connect_error::ecServerClosedStream)
        {
            closedCallbackPromise.set_value();
        }
        else
        {
            try
            {
                cout << "CLOSED FAILURE " << closed.result().toString() << endl;
                throw closed.result();
            }
            catch (connect_error)
            {
                closedCallbackPromise.set_exception(current_exception());
            }
        }
    };
    auto streamConnectedCallback = make_shared<NotifySyncFunc<XmppConnectedEvent,
         decltype(connectedFunc)>>(connectedFunc);
    auto streamClosedCallback = make_shared<NotifySyncFunc<XmppClosedEvent,
         decltype(closedFunc)>>(closedFunc);

    shared_ptr<IXmppStream> stream;

    auto createdFunc =
        [&streamCallbackPromise, &closedCallbackPromise, &stream,
         streamConnectedCallback, streamClosedCallback](XmppStreamCreatedEvent & e)
    {
        EXPECT_TRUE(e.result().succeeded());
        EXPECT_NE(e.stream(), nullptr);
        if (e.result().succeeded() && e.stream())
        {
            stream = e.stream();
            e.stream()->onConnected() += streamConnectedCallback;
            e.stream()->onClosed() += streamClosedCallback;
        }
        streamCallbackPromise.set_value();
    };
    auto streamCreatedCallback = make_shared<NotifySyncFunc<XmppStreamCreatedEvent,
         decltype(createdFunc)>>(createdFunc);

    client->onStreamCreated() += streamCreatedCallback;

    ASSERT_NO_THROW(client->initiateXMPP(config, xmlConnection));

    auto status1 = streamCallbackFuture.wait_for(chrono::seconds(5));

#if __cplusplus>=201103L || defined(_WIN32)
    EXPECT_EQ(status1, future_status::ready);
    if (status1 == future_status::ready)
#else
    EXPECT_TRUE(status1);
    if (status1)
#endif
    {
        try
        {
            streamCallbackFuture.get();

            auto status2 = openCallbackFuture.wait_for(chrono::seconds(10));
#if __cplusplus>=201103L || defined(_WIN32)
            EXPECT_EQ(status2, future_status::ready);
            if (status2 == future_status::ready)
#else
            EXPECT_TRUE(status2);
            if (status2)
#endif
            {
                openCallbackFuture.get();

                cout << "OPENED" << endl;

                EXPECT_NE(stream, nullptr);
                if (stream)
                {
                    stream->close();
                }

                auto status3 = closedCallbackFuture.wait_for(chrono::seconds(5));
#if __cplusplus>=201103L || defined(_WIN32)
                EXPECT_EQ(status3, future_status::ready);
                if (status3 == future_status::ready)
#else
                EXPECT_TRUE(status3);
                if (status3)
#endif
                {
                    try
                    {
                        closedCallbackFuture.get();
                    }
                    catch (...)
                    {
                        EXPECT_NO_THROW(throw);
                    }

                    cout << "CLOSED" << endl;
                }
            }
        }
        catch (...)
        {
            // NOTE: This is done instead of ASSERT_NO_THROW in lieu of adding
            //       an object to clean up the callbacks as we leave the scope
            //       due to an exception throw. If we don't clean up the callbacks
            //       they will happen after the promises have already been cleaned up.
            EXPECT_NO_THROW(throw);
        }

    }

    client->onStreamCreated() -= streamCreatedCallback;
    if (stream)
    {
        stream->onConnected() -= streamConnectedCallback;
        stream->onClosed() -= streamClosedCallback;
    }
    cout << "EXITING" << endl;
}



#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT


TEST(Sasl, SaslFactory)
{
    list<string> defaults = SaslFactory::defaultSaslOrder();
    EXPECT_GT(defaults.size(), 0UL);

    size_t originalDefaultsSize = defaults.size();

    shared_ptr<ISaslMechanism> plainMechanism = SaslFactory::createSaslMechanism("PLAIN");
    EXPECT_NE(plainMechanism, nullptr);

    shared_ptr<ISaslMechanism> newMechanism = SaslFactory::createSaslMechanism("DUMMY");
    EXPECT_EQ(newMechanism, nullptr);

    struct DummySasl: public ISaslMechanism
    {
        bool requiresAuthenticatedStream() const { return false; }

        virtual void setParams(std::shared_ptr<ISaslParams>) {}

        virtual SecureBuffer initiate()
        {
            const char testArray[] = "test";
            return SecureBuffer(testArray, sizeof(testArray));
        }

        virtual SecureBuffer challenge()
        {
            return SecureBuffer();
        }

        virtual void handleChallenge(const SecureBuffer &response,
                                     ResponseCallback callback) override
        {}

        virtual void handleResponse(const SecureBuffer &response,
                                    ResponseCallback callback) override
        {}
        virtual void handleSuccess(const SecureBuffer &response,
                                   ResponseCallback callback) override
        {}
    };

    SaslFactory::registerSaslMechanism("DUMMY", SaslFactory::HIGHEST_BUILT_IN_SASL_PRIORITY + 1,
                                       [](const std::string & name)
    {
        EXPECT_EQ(name, "DUMMY");
        return make_shared<DummySasl>();
    });

    list<string> newdefaults = SaslFactory::defaultSaslOrder();
    ASSERT_GT(newdefaults.size(), 0UL);
    EXPECT_EQ(newdefaults.size(), originalDefaultsSize + 1);
    EXPECT_EQ(newdefaults.back(), "DUMMY");

    shared_ptr<ISaslMechanism> newMechanism2 = SaslFactory::createSaslMechanism("DUMMY");
    ASSERT_NE(newMechanism2, nullptr);
    EXPECT_GT(newMechanism2->initiate().size(), 0UL);

    list<string> overflowDefaults;
    overflowDefaults.push_back("DUMMY");
    overflowDefaults.push_back("FAKE1");
    overflowDefaults.push_back("PLAIN");
    overflowDefaults.push_back("FAKE2");

    list<string> restricted = SaslFactory::restrictToKnownMechanisms(overflowDefaults);

    EXPECT_NE(find(restricted.begin(), restricted.end(), "DUMMY"), restricted.end());
    EXPECT_NE(find(restricted.begin(), restricted.end(), "PLAIN"), restricted.end());
    EXPECT_EQ(find(restricted.begin(), restricted.end(), "FAKE1"), restricted.end());
    EXPECT_EQ(find(restricted.begin(), restricted.end(), "FAKE2"), restricted.end());

    EXPECT_EQ(SaslFactory::selectMechanism(overflowDefaults, defaults), "PLAIN");

    list<string> fakeMechanisms;
    fakeMechanisms.push_back("FAKE1");
    fakeMechanisms.push_back("FAKE2");
    fakeMechanisms.push_back("FAKE3");
    fakeMechanisms.push_back("FAKE4");

    EXPECT_EQ(SaslFactory::selectMechanism(fakeMechanisms, defaults), "");

}


TEST(XmppClient, XMPP_StreamParseTests)
{
    SegmentArray segmentArrays[] =
    {
        // Test normal initation with fragmented reads.
        {   {"", Segment::WaitForSend},
            {"", Segment::IncompleteNegotation},
            {"<stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http"},
            {"://etherx.jabber.org/streams\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" ver"},
            {"sion=\"1.0\" xml:lang=\"en\"><stream"},
            {
                ":features><starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/><mechani"
                "sms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>PLAIN</mechanism><mechan"
                "ism>DIGEST-MD5</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms><c xmln"
                "s=\"http://jabber.org/protocol/caps\" hash=\"sha-1\" node=\"http://www.dummy.ne"
                "t/en/ejabberd/\" ver=\"aIT+/ulfcbHXDKPkCA+iw9x5mU8=\"/><register xmlns=\"http://jabb"
                "er.org/features/iq-register\"/></stream:features>"
            },
            {"", Segment::WaitForSend}
        },

        // Test normal initation with fragmented reads with xml prologue
        {   {"", Segment::WaitForSend},
            {"", Segment::IncompleteNegotation},
            {"<?xml version='1.0'?"},
            {"><stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http"},
            {"://etherx.jabber.org/streams\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" ver"},
            {"sion=\"1.0\" xml:lang=\"en\"><stream"},
            {
                ":features><starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/><mechani"
                "sms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>PLAIN</mechanism><mechan"
                "ism>DIGEST-MD5</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms><c xmln"
                "s=\"http://jabber.org/protocol/caps\" hash=\"sha-1\" node=\"http://www.dummy.ne"
                "t/en/ejabberd/\" ver=\"aIT+/ulfcbHXDKPkCA+iw9x5mU8=\"/><register xmlns=\"http://jabb"
                "er.org/features/iq-register\"/></stream:features>"
            },
            {"", Segment::WaitForSend}
        },

        // Test normal initation with fragmented reads with mssing xmlns name (error)
        {   {"", Segment::WaitForSend},
            {"", Segment::IncompleteNegotation},
            {"<?xml version='1.0'?"},
            {"><stream:stream xmlns=\"jabber:client\""},
            {"id=\"65140440\" from=\"test-xmpp.dummy-host.com\" ver"},
            {"sion=\"1.0\" xml:lang=\"en\">"},
            {
                "<stream:error><invalid-namespace xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\"/>"
                "</stream:error>", Segment::WaitForSend
            }
        },

        // Test normal initation with fragmented reads with non-conformant xmlns name (error)
        {   {"", Segment::WaitForSend},
            {"", Segment::IncompleteNegotation},
            {"<?xml version='1.0'?"},
            {"><s:stream xmlns=\"jabber:client\" xmlns:s=\"http"},
            {"://etherx.jabber.org/streams\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" ver"},
            {"sion=\"1.0\" xml:lang=\"en\">"},
            {
                "<stream:error><bad-namespace-prefix xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\"/>"
                "</stream:error>", Segment::WaitForSend
            }
        },

        // Test unexpected version number (error)
        {   {"", Segment::WaitForSend},
            {"", Segment::IncompleteNegotation},
            {"<?xml version='1.0'?"},
            {"><stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http"},
            {"://etherx.jabber.org/streams\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" ver"},
            {"sion=\"2.1\" xml:lang=\"en\">"},
            {
                "<stream:error><unsupported-version xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\"/>"
                "</stream:error>", Segment::WaitForSend
            }
        },

        // TODO:

        // Test invalid encoding
        /*        {{"", Segment::WaitForSend},
                 {"<?xml version='1.0' encoding='UTF-16'?"},
                 {"><s:stream xmlns=\"jabber:client\" xmlns:s=\"http"},
                 {"://etherx.jabber.org/streams\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" ver"},
                 {"sion=\"1.0\" xml:lang=\"en\">"},
                 {"W", Segment::WaitForSend}},*/

        // Test PLAIN SASL negotiation
        {   {"", Segment::WaitForSend},
            {"PLAIN", Segment::UpdateSASLPreferences},
            {"<?xml version='1.0'?"},
            {"><stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http"},
            {"://etherx.jabber.org/streams\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" ver"},
            {"sion=\"1.0\" xml:lang=\"en\"><stream"},
            {
                ":features><starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"><required/></starttls>"
                "<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">"
                "<mechanism>PLAIN</mechanism><mechanism>DIGEST-MD5</mechanism><mechanism>SCRAM-SHA-1"
                "</mechanism></mechanisms><c xmlns=\"http://jabber.org/protocol/caps\" "
                "hash=\"sha-1\" node=\"http://www.dummy.net/en/ejabberd/\" "
                "ver=\"aIT+/ulfcbHXDKPkCA+iw9x5mU8=\"/><register xmlns=\"http://jabb"
                "er.org/features/iq-register\"/></stream:features>"
            },
            {"<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>", Segment::WaitForSend},
            {"<proceed xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>"},
            {
                "<stream:stream from=\"unittest\" to=\"test-xmpp.dummy-host.co"
                "m\" version=\"1.0\" xml:lang=\"en\" xmlns=\"jabber:client\" "
                "xmlns:stream=\"http://etherx.jabber.org/streams\">", Segment::WaitForSend
            },
            {
                "<stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http"
                "://etherx.jabber.org/streams\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" "
                "version=\"1.0\" xml:lang=\"en\"><stream:features>"
                "<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">"
                "<mechanism>PLAIN</mechanism><mechanism>DIGEST-MD5</mechanism><mechanism>SCRAM-SHA-1"
                "</mechanism></mechanisms><c xmlns=\"http://jabber.org/protocol/caps\" "
                "hash=\"sha-1\" node=\"http://www.dummy.net/en/ejabberd/\" "
                "ver=\"aIT+/ulfcbHXDKPkCA+iw9x5mU8=\"/><register xmlns=\"http://jabb"
                "er.org/features/iq-register\"/></stream:features>"
            },
            {
                "<auth xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\""
                " mechanism=\"PLAIN\">AHVuaXR0ZXN0AHVuaXRUZXN0UGFzc3dvcmQ=</auth>",
                Segment::WaitForSend
            },
            {"<success xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"/>"},
            {
                "<stream:stream from=\"unittest\" to=\"test-xmpp.dummy-host.co"
                "m\" version=\"1.0\" xml:lang=\"en\" xmlns=\"jabber:client\" "
                "xmlns:stream=\"http://etherx.jabber.org/streams\">", Segment::WaitForSend
            },
            {
                "<stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http"
                "://etherx.jabber.org/streams\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" "
                "version=\"1.0\" xml:lang=\"en\"><stream:features>"
                "<c xmlns=\"http://jabber.org/protocol/caps\" "
                "hash=\"sha-1\" node=\"http://www.dummy.net/en/ejabberd/\" "
                "ver=\"aIT+/ulfcbHXDKPkCA+iw9x5mU8=\"/><register xmlns=\"http://jabb"
                "er.org/features/iq-register\"/></stream:features>"
            },
            {"", Segment::WaitForSend}
        },

        // Test PLAIN SASL negotiation Failure
        {   {"", Segment::WaitForSend},
            {"PLAIN", Segment::UpdateSASLPreferences},
            {"<?xml version='1.0'?"},
            {"><stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http"},
            {"://etherx.jabber.org/streams\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" ver"},
            {"sion=\"1.0\" xml:lang=\"en\"><stream"},
            {
                ":features><starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"><required/></starttls>"
                "<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">"
                "<mechanism>PLAIN</mechanism><mechanism>DIGEST-MD5</mechanism><mechanism>SCRAM-SHA-1"
                "</mechanism></mechanisms><c xmlns=\"http://jabber.org/protocol/caps\" "
                "hash=\"sha-1\" node=\"http://www.dummy.net/en/ejabberd/\" "
                "ver=\"aIT+/ulfcbHXDKPkCA+iw9x5mU8=\"/><register xmlns=\"http://jabb"
                "er.org/features/iq-register\"/></stream:features>"
            },
            {"<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>", Segment::WaitForSend},
            {"<proceed xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>"},
            {
                "<stream:stream from=\"unittest\" to=\"test-xmpp.dummy-host.co"
                "m\" version=\"1.0\" xml:lang=\"en\" xmlns=\"jabber:client\" "
                "xmlns:stream=\"http://etherx.jabber.org/streams\">", Segment::WaitForSend
            },
            {
                "<stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http"
                "://etherx.jabber.org/streams\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" "
                "version=\"1.0\" xml:lang=\"en\"><stream:features>"
                "<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">"
                "<mechanism>PLAIN</mechanism><mechanism>DIGEST-MD5</mechanism><mechanism>SCRAM-SHA-1"
                "</mechanism></mechanisms><c xmlns=\"http://jabber.org/protocol/caps\" "
                "hash=\"sha-1\" node=\"http://www.dummy.net/en/ejabberd/\" "
                "ver=\"aIT+/ulfcbHXDKPkCA+iw9x5mU8=\"/><register xmlns=\"http://jabb"
                "er.org/features/iq-register\"/></stream:features>"
            },
            {
                "<auth xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\""
                " mechanism=\"PLAIN\">AHVuaXR0ZXN0AHVuaXRUZXN0UGFzc3dvcmQ=</auth>",
                Segment::WaitForSend
            },
            {"<failure xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><not-authorized/></failure>"},
            {"", Segment::WaitForSend}
        }

        // TODO:
        // Test SCRAM-SHA-1 SASL negotiation

        // TODO:
        // Test SCRAM-SHA-1 SASL negotiation abort

    };

    size_t parseTestNumber = 0;
    for (const auto &segments : segmentArrays)
    {
        cout << "PARSE TEST #" << ++parseTestNumber << endl;
        try
        {
            bool willCompleteNegotiation = true;
            list<string> SASLPreferences;
            for (const auto &s : segments)
            {
                if (s.m_action == Segment::UpdateSASLPreferences)
                {
                    SASLPreferences.push_back(s.m_data);
                }
                else if (s.m_action == Segment::IncompleteNegotation)
                {
                    willCompleteNegotiation = false;
                }
            }

            auto remoteTcp = make_shared<SegmentedDummyTCPConnect>(segments);

            auto xmlConnection = make_shared<XmppConnection>(
                                     static_pointer_cast<IStreamConnection>(remoteTcp));

            auto streamPromise = make_shared<promise<shared_ptr<IXmppStream>>>();
            auto streamFuture = streamPromise->get_future();

            SecureBuffer password;
            password.write("unitTestPassword");
            auto plainConfig = SaslPlain::Params::create("unittest", password);

            XmppConfig config(MY_JID, DUMMY_TEST_HOST);
            config.overrideSASLOrder(SASLPreferences);
            config.setSaslConfig("PLAIN", plainConfig);

            auto client = XmppClient::create();
            ASSERT_NO_THROW(client->initiateXMPP(config, xmlConnection, streamPromise));

            shared_ptr<IXmppStream> xmppStream;
            xmppStream = streamFuture.get();
            EXPECT_NE(xmppStream, nullptr);

            if (xmppStream)
            {
                if (willCompleteNegotiation)
                {
                    auto status = xmppStream->whenNegotiated().wait_for(chrono::seconds(5));
#if __cplusplus>=201103L || defined(_WIN32)
                    EXPECT_EQ(status, future_status::ready);
#else
                    EXPECT_TRUE(status);
#endif
                }
                else
                {
                    size_t sleepCount = 0;
                    while (!remoteTcp->lastSegmentRan() && sleepCount < 1000)
                    {
                        ++sleepCount;
                        this_thread::sleep_for(chrono::milliseconds(1));
                    }
                }

                cout << "CLOSING" << endl;
                EXPECT_NO_THROW(xmppStream->close());

                remoteTcp->closed().wait();
                EXPECT_EQ(remoteTcp->expressionMatchFailures(), 0UL);
            }
        }
        catch (const connect_error &ce)
        {
            EXPECT_NO_THROW(throw ce);
        }
        catch (const runtime_error &re)
        {
            EXPECT_NO_THROW(throw re);
        }
    }
}



TEST(XmppClient, DISABLED_Dummy_Chat_Test)
{

    if (!xmpp_connect_config::hasConfig())
    {
        cout << "Dummy_Chat_Test skipped. No DEFAULT XMPP config." << endl;
        return;
    }

    const Iotivity::Xmpp::ProxyConfig proxy(xmpp_connect_config::proxyHost(),
                                            xmpp_connect_config::proxyPort(),
                                            Iotivity::Xmpp::ProxyConfig::ProxyType::ProxySOCKS5);

    auto remoteTcp = make_shared<TcpConnection>(xmpp_connect_config::host(),
                     xmpp_connect_config::port(), proxy);

    auto xmlConnection = make_shared<XmppConnection>(
                             static_pointer_cast<IStreamConnection>(remoteTcp));

    auto streamPromise = make_shared<promise<shared_ptr<IXmppStream>>>();
    auto streamFuture = streamPromise->get_future();

    SecureBuffer password;
    password.write("unitTestUserName1Password");
    auto plainConfig = SaslPlain::Params::create("unitTestUserName1", password);
    auto scramConfig = SaslScramSha1::Params::create("unitTestUserName1", password);

    XmppConfig config(JabberID(""), xmpp_connect_config::xmppDomain());
    config.requireTLSNegotiation();
    config.setSaslConfig("PLAIN", plainConfig);
    config.setSaslConfig("SCRAM-SHA-1", scramConfig);

    auto client = XmppClient::create();
    ASSERT_NO_THROW(client->initiateXMPP(config, xmlConnection, streamPromise));

    shared_ptr<IXmppStream> xmppStream;
    EXPECT_NO_THROW(xmppStream = streamFuture.get());
    EXPECT_NE(xmppStream, nullptr);
    if (xmppStream)
    {
        ASSERT_TRUE(xmppStream->whenNegotiated().valid());

        auto status = xmppStream->whenNegotiated().wait_for(chrono::seconds(20));
#if __cplusplus>=201103L || defined(_WIN32)
        EXPECT_EQ(status, future_status::ready);
        if (status == future_status::ready)
#else
        EXPECT_TRUE(status);
        if (status)
#endif
        {
            ASSERT_NO_THROW(xmppStream->whenNegotiated().get());

            JabberID myID;
            ASSERT_NO_THROW(myID = xmppStream->whenBound().get());


            /*

            {
                auto doc = XMLDocument::createEmptyDocument();
                auto message = doc->createElement("iq");
                message->setAttribute("type", "get");
                message->setAttribute("id", xmppStream->getNextID());
                message->setAttribute("to", xmpp_connect_config::xmppDomain());

                auto query = doc->createElement("query");
                query->setAttribute("xmlns", "http://jabber.org/protocol/disco#items");

                message->appendChild(query);
                doc->appendChild(message);

                xmppStream->sendQuery(message,
                    [](const connect_error &, XMLElement::Ptr)
                    {
                    });
            }

            {
                auto doc = XMLDocument::createEmptyDocument();
                auto message = doc->createElement("iq");
                message->setAttribute("type", "get");
                message->setAttribute("id", xmppStream->getNextID());
                message->setAttribute("to", xmpp_connect_config::xmppDomain());

                auto query = doc->createElement("query");
                query->setAttribute("xmlns", "http://jabber.org/protocol/disco#info");

                message->appendChild(query);
                doc->appendChild(message);

                promise<void> ready;
                future<void> readyFuture = ready.get_future();
                xmppStream->sendQuery(message,
                    [&ready](const connect_error &, XMLElement::Ptr)
                    {
                        ready.set_value();
                    });
                readyFuture.wait_for(chrono::seconds(2));
            }

            {
                auto doc = XMLDocument::createEmptyDocument();
                auto message = doc->createElement("iq");
                message->setAttribute("type", "get");
                message->setAttribute("id", xmppStream->getNextID());
                message->setAttribute("from", myID.full());

                auto query = doc->createElement("query");
                query->setAttribute("xmlns", "jabber:iq:roster");

                message->appendChild(query);
                doc->appendChild(message);

                promise<void> ready;
                future<void> readyFuture = ready.get_future();
                xmppStream->sendQuery(message,
                    [&ready](const connect_error &, XMLElement::Ptr)
                    {
                        ready.set_value();
                    });
                readyFuture.wait_for(chrono::seconds(2));
            }
            */

            /*
            {
                auto doc = XMLDocument::createEmptyDocument();
                auto message = doc->createElement("iq");
                message->setAttribute("type", "set");
                message->setAttribute("id", xmppStream->getNextID());
                message->setAttribute("to", "testroom1@conference.xmpp-dev");

                auto query = doc->createElement("query");
                query->setAttribute("xmlns", "http://jabber.org/protocol/muc#owner");

                auto x = doc->createElement("x");
                x->setAttribute("type", "submit");
                x->setAttribute("xmlns", "jabber:x:data");

                query->appendChild(x);
                message->appendChild(query);
                doc->appendChild(message);

                xmppStream->sendQuery(message,
                    [](const connect_error &, XMLElement::Ptr)
                    {
                    });
            }
            */

            /*
            {
                 auto doc = XMLDocument::createEmptyDocument();
                 auto presence = doc->createElement("presence");

                 auto show = doc->createElement("show");
                 show->setValue("chat");

                 auto priority = doc->createElement("priority");
                 priority->setValue("1");

                 presence->appendChild(show);
                 presence->appendChild(priority);
                 doc->appendChild(presence);

                 xmppStream->sendMessage(presence);
             }

             */

            /*
                        // Temporary test code.
                        cout<< "Enter Test Messages [ENTER TO QUIt]: "<< endl;

                        string messageStr;
                        do
                        {
                            getline(cin, messageStr);
                            if (messageStr.size()==0) continue;

                            auto doc = XMLDocument::createEmptyDocument();
                            auto message = doc->createElement("message");
                            message->setAttribute("type", "chat");
                            message->setAttribute("id", xmppStream->getNextID());
                            message->setAttribute("to", "unittest@xmpp-dev");

                            auto active = doc->createElement("active");
                            active->setAttribute("xmlns", "http://jabber.org/protocol/chatstates");

                            auto body = doc->createElement("body");

                            body->setValue(messageStr);

                            message->appendChild(active);
                            message->appendChild(body);
                            doc->appendChild(message);

                            xmppStream->sendMessage(message);

                        } while (messageStr.size()>0);
                        */
        }
    }
}


#ifdef ENABLE_FUNCTIONAL_TESTING
TEST(XmppClient, XMPP_Request_ID_Generation)
#else
TEST(XmppClient, XMPP_Request_ID_Generation)
#endif
{
    if (!xmpp_connect_config::hasConfig())
    {
        cout << "XMPP_Request_ID_Generation skipped. No DEFAULT XMPP config." << endl;
        return;
    }

    const Iotivity::Xmpp::ProxyConfig proxy(xmpp_connect_config::proxyHost(),
                                            xmpp_connect_config::proxyPort(),
                                            Iotivity::Xmpp::ProxyConfig::ProxyType::ProxySOCKS5);

    auto remoteTcp = make_shared<TcpConnection>(xmpp_connect_config::host(),
                     xmpp_connect_config::port(), proxy);

    auto xmlConnection = make_shared<XmppConnection>(
                             static_pointer_cast<IStreamConnection>(remoteTcp));

    auto streamPromise = make_shared<promise<shared_ptr<IXmppStream>>>();
    auto streamFuture = streamPromise->get_future();

    XmppConfig config(JabberID(""), xmpp_connect_config::xmppDomain());

    auto client = XmppClient::create();
    ASSERT_NO_THROW(client->initiateXMPP(config, xmlConnection, streamPromise));

    shared_ptr<IXmppStream> xmppStream;
    EXPECT_NO_THROW(xmppStream = streamFuture.get());
    ASSERT_NE(xmppStream, nullptr);

    set<string> ids;
    for (size_t i = 0; i < 100; ++i)
    {
        string nextID = xmppStream->getNextID();
        EXPECT_NE(nextID, "");
        EXPECT_TRUE(ids.find(nextID) == ids.end());
        ids.insert(nextID);
    }
}


TEST(XmppClient, XmppStream_OpenCloseEvent)
{
}


TEST(XmppClient, XMPP_Sasl_Prep)
{
    // MSVC did not support U"" string literals at the time this build was made, so
    // we are generating the converted string the hard way.
    vector<char32_t> testChars =
    {
        0x00A0UL,  //00A0; NO-BREAK SPACE
        0x1680UL,  //1680; OGHAM SPACE MARK
        0x2000UL,  //2000; EN QUAD
        0x2001UL,  //2001; EM QUAD
        0x2002UL,  //2002; EN SPACE
        0x2003UL,  //2003; EM SPACE
        0x2004UL,  //2004; THREE-PER-EM SPACE
        0x2005UL,  //2005; FOUR-PER-EM SPACE
        0x2006UL,  //2006; SIX-PER-EM SPACE
        0x2007UL,  //2007; FIGURE SPACE
        0x2008UL,  //2008; PUNCTUATION SPACE
        0x2009UL,  //2009; THIN SPACE
        0x200AUL,  //200A; HAIR SPACE
        0x200BUL,  //200B; ZERO WIDTH SPACE
        0x202FUL,  //202F; NARROW NO-BREAK SPACE
        0x205FUL,  //205F; MEDIUM MATHEMATICAL SPACE
        0x3000UL,  //3000; IDEOGRAPHIC SPACE
        0x007FUL,  //007F; DELETE
        0x06DDUL,  //06DD; ARABIC END OF AYAH
        0x070FUL,  //070F; SYRIAC ABBREVIATION MARK
        0x180EUL,  //180E; MONGOLIAN VOWEL SEPARATOR
        0x200CUL,  //200C; ZERO WIDTH NON-JOINER
        0x200DUL,  //200D; ZERO WIDTH JOINER
        0x2028UL,  //2028; LINE SEPARATOR
        0x2029UL,  //2029; PARAGRAPH SEPARATOR
        0x2060UL,  //2060; WORD JOINER
        0x2061UL,  //2061; FUNCTION APPLICATION
        0x2062UL,  //2062; INVISIBLE TIMES
        0x2063UL,  //2063; INVISIBLE SEPARATOR
        0xFEFFUL,  //FEFF; ZERO WIDTH NO-BREAK SPACE
        0xFFF9UL,  //FFF9; INTERLINEAR ANNOTATION ANCHOR
        0xFFFAUL,  //FFFA; INTERLINEAR ANNOTATION SEPARATOR
        0xFFFBUL,  //FFFB; INTERLINEAR ANNOTATION TERMINATOR
        0xFFFCUL,  //FFFC; OBJECT REPLACEMENT CHARACTER
        0XFFFDUL,  //FFFD; REPLACEMENT CHARACTER
        0x0340UL,  //0340; COMBINING GRAVE TONE MARK
        0x0341UL,  //0341; COMBINING ACUTE TONE MARK
        0x200EUL,  //200E; LEFT-TO-RIGHT MARK
        0x200FUL,  //200F; RIGHT-TO-LEFT MARK
        0x202AUL,  //202A; LEFT-TO-RIGHT EMBEDDING
        0x202BUL,  //202B; RIGHT-TO-LEFT EMBEDDING
        0x202CUL,  //202C; POP DIRECTIONAL FORMATTING
        0x202DUL,  //202D; LEFT-TO-RIGHT OVERRIDE
        0x202EUL,  //202E; RIGHT-TO-LEFT OVERRIDE
        0x206AUL,  //206A; INHIBIT SYMMETRIC SWAPPING
        0x206BUL,  //206B; ACTIVATE SYMMETRIC SWAPPING
        0x206CUL,  //206C; INHIBIT ARABIC FORM SHAPING
        0x206DUL,  //206D; ACTIVATE ARABIC FORM SHAPING
        0x206EUL,  //206E; NATIONAL DIGIT SHAPES
        0x206FUL,  //206F; NOMINAL DIGIT SHAPES
        0xE0001UL  //E0001; LANGUAGE TAG
    };

    //0000-001F; [CONTROL CHARACTERS]
    for (char32_t i = 0x0000; i <= 0x001F; ++i)
    {
        testChars.push_back(i);
    }
    //0080-009F; [CONTROL CHARACTERS]
    for (char32_t i = 0x0080; i <= 0x009F; ++i)
    {
        testChars.push_back(i);
    }
    //206A-206F; [CONTROL CHARACTERS]
    for (char32_t i = 0x206A; i <= 0x206F; ++i)
    {
        testChars.push_back(i);
    }
    //0080-009F; [CONTROL CHARACTERS]
    for (char32_t i = 0x0080; i <= 0x009F; ++i)
    {
        testChars.push_back(i);
    }
    //FFF9-FFFC; [CONTROL CHARACTERS]
    for (char32_t i = 0xFFF9; i <= 0xFFFC; ++i)
    {
        testChars.push_back(i);
    }
    //1D173-1D17A; [MUSICAL CONTROL CHARACTERS]
    for (char32_t i = 0x1D173; i <= 0x1D17A; ++i)
    {
        testChars.push_back(i);
    }
    //E000-F8FF; [PRIVATE USE, PLANE 0]
    for (char32_t i = 0xE000; i <= 0xF8FF; ++i)
    {
        testChars.push_back(i);
    }
    //F0000-FFFFD; [PRIVATE USE, PLANE 15]
    for (char32_t i = 0xF0000; i <= 0xFFFFD; ++i)
    {
        testChars.push_back(i);
    }
    //100000-10FFFD; [PRIVATE USE, PLANE 16]
    for (char32_t i = 0x100000; i <= 0x10FFFD; ++i)
    {
        testChars.push_back(i);
    }
    //FDD0-FDEF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0xFDD0; i <= 0xFDEF; ++i)
    {
        testChars.push_back(i);
    }
    //FFFE-FFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0xFFFE; i <= 0xFFFF; ++i)
    {
        testChars.push_back(i);
    }
    //1FFFE-1FFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0x1FFFE; i <= 0x1FFFF; ++i)
    {
        testChars.push_back(i);
    }
    //2FFFE-2FFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0x2FFFE; i <= 0x2FFFF; ++i)
    {
        testChars.push_back(i);
    }
    //3FFFE-3FFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0x3FFFE; i <= 0x3FFFF; ++i)
    {
        testChars.push_back(i);
    }
    //4FFFE-4FFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0x4FFFE; i <= 0x4FFFF; ++i)
    {
        testChars.push_back(i);
    }
    //5FFFE-5FFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0x5FFFE; i <= 0x5FFFF; ++i)
    {
        testChars.push_back(i);
    }
    //6FFFE-6FFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0x6FFFE; i <= 0x6FFFF; ++i)
    {
        testChars.push_back(i);
    }
    //7FFFE-7FFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0x7FFFE; i <= 0x7FFFF; ++i)
    {
        testChars.push_back(i);
    }
    //8FFFE-8FFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0x8FFFE; i <= 0x8FFFF; ++i)
    {
        testChars.push_back(i);
    }
    //9FFFE-9FFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0x9FFFE; i <= 0x9FFFF; ++i)
    {
        testChars.push_back(i);
    }
    //AFFFE-AFFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0xAFFFE; i <= 0xAFFFF; ++i)
    {
        testChars.push_back(i);
    }
    //BFFFE-BFFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0xBFFFE; i <= 0xBFFFF; ++i)
    {
        testChars.push_back(i);
    }
    //CFFFE-CFFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0xCFFFE; i <= 0xCFFFF; ++i)
    {
        testChars.push_back(i);
    }
    //DFFFE-DFFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0xDFFFE; i <= 0xDFFFF; ++i)
    {
        testChars.push_back(i);
    }
    //EFFFE-EFFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0xEFFFE; i <= 0xEFFFF; ++i)
    {
        testChars.push_back(i);
    }
    //FFFFE-FFFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0xFFFFE; i <= 0xFFFFF; ++i)
    {
        testChars.push_back(i);
    }
    //10FFFE-10FFFF; [NONCHARACTER CODE POINTS]
    for (char32_t i = 0x10FFFE; i <= 0x10FFFF; ++i)
    {
        testChars.push_back(i);
    }
    //D800-DFFF; [SURROGATE CODES]
    for (char32_t i = 0xD800; i <= 0xDFFF; ++i)
    {
        testChars.push_back(i);
    }
    //2FF0-2FFB; [IDEOGRAPHIC DESCRIPTION CHARACTERS]
    for (char32_t i = 0x2FF0; i <= 0x2FFB; ++i)
    {
        testChars.push_back(i);
    }
    //E0020-E007F; [TAGGING CHARACTERS]
    for (char32_t i = 0xE0020; i <= 0xE007F; ++i)
    {
        testChars.push_back(i);
    }

    char tempBuffer[16] = {0};

    const char32_t *nextIn = &testChars[0];

    string initialStr;
    // Convert one character at time; we are not attempting to be efficient here.
    while (nextIn <= &testChars[testChars.size() - 1])
    {
        size_t charsWritten = 0;

        str_helper::utf32ToUtf8(*nextIn++, &tempBuffer[0],
                                sizeof(tempBuffer) / sizeof(tempBuffer[0]), charsWritten);

        ASSERT_NE(charsWritten, 0UL);

        initialStr += string(&tempBuffer[0], charsWritten);
    }
    initialStr += "A";

    SecureBuffer prepBuffer;
    EXPECT_NO_THROW(prepBuffer = testSaslPrep(initialStr));

    ASSERT_GT(prepBuffer.size(), 0UL);
    EXPECT_EQ(prepBuffer.size(), 18UL);
    EXPECT_EQ(prepBuffer[prepBuffer.size() - 1], 'A');


    string escapeStr("user,name=test");
    SecureBuffer afterEscapeChars(string("user=2Cname=3Dtest"));
    SecureBuffer escapePrep1 = testSaslPrep(escapeStr, true);
    EXPECT_EQ(escapePrep1, afterEscapeChars);
}


#ifdef ENABLE_FUNCTIONAL_TESTING
TEST(XmppClient, XMPP_StreamEstablishOverBOSH)
#else
TEST(XmppClient, DISABLED_XMPP_StreamEstablishOverBOSH)
#endif
{
    auto remoteConnect = make_shared<HttpCurlConnection>(xmpp_connect_config::BOSHUrl());

    remoteConnect->setProxy(ProxyConfig::queryProxy());

    shared_ptr<ConnectionManager> manager = ConnectionManager::create();
    ASSERT_NE(manager, nullptr);
    BOSHConfig boshConfig(xmpp_connect_config::host());

    boshConfig.setUseKeys(true);
    //auto xmppBOSH = make_shared<XmppBOSHConnection>(manager, remoteConnect, boshConfig);

    /*

    auto xmlConnection = make_shared<XmppConnection>(
                                static_pointer_cast<IXmlConnection>(xmppBOSH));

    auto streamPromise = make_shared<promise<shared_ptr<IXmppStream>>>();
    auto streamFuture = streamPromise->get_future();

    SecureBuffer password;
    password.write("unitTestPassword");
    auto plainConfig = SaslPlain::Params::create("unittest", password);

    XmppConfig config("", xmpp_connect_config::xmppDomain());
    config.requireTLSNegotiation();
    config.setSaslConfig("PLAIN", plainConfig);

    auto client = XmppClient::create();
    ASSERT_NO_THROW(client->initiateXMPP(config, xmlConnection, streamPromise));

    shared_ptr<IXmppStream> xmppStream;
    EXPECT_NO_THROW(xmppStream = streamFuture.get());
    EXPECT_NE(xmppStream, nullptr);
    if (xmppStream)
    {
        ASSERT_TRUE(xmppStream->whenNegotiated().valid());

        auto status = xmppStream->whenNegotiated().wait_for(chrono::seconds(5));
        EXPECT_EQ(status, future_status::ready);
        if (status==future_status::ready)
        {
            EXPECT_NO_THROW(xmppStream->whenNegotiated().get());
        }
    }
    */
}

#endif // ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
