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

/// @file xmpp_compliance_tests.cpp

#include "stdafx.h"
#include <gtest/gtest.h>

#ifdef ENABLE_LIBSTROPHE
#include <xmpp/xmppstrophe.h>
#else
#include <xmpp/xmppclient.h>
#endif

#include <xmpp/sasl.h>
#include <xmpp/xmppconfig.h>

#include "xmpp_test_config.h"
#include "xmpp_dummy_server.h"

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


#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT

static const string SERVER_FIRST_RESPONSE =
    "<stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams"
    "\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" version=\"1.0\" xml:lang"
    "=\"en\"><stream:features><starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"><required/>"
    "</starttls><mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>PLAIN"
    "</mechanism><mechanism>DIGEST-MD5</mechanism><mechanism>SCRAM-SHA-1</mechanism>"
    "</mechanisms><c xmlns=\"http://jabber.org/protocol/caps\" hash=\"sha-1\" "
    "node=\"http://www.dummy.net/en/ejabberd/\" ver=\"aIT+/ulfcbHXDKPkCA+iw9x5mU8=\"/>"
    "<register xmlns=\"http://jabber.org/features/iq-register\"/></stream:features>";
static const string CLIENT_START_TLS = "<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>";
static const string SERVER_PROCEED_TLS = "<proceed xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>";
static const string CLIENT_RESTART_STREAM =
    "<stream:stream from=\"unittest\" to=\"test-xmpp.dummy-host.co"
    "m\" version=\"1.0\" xml:lang=\"en\" xmlns=\"jabber:client\" "
    "xmlns:stream=\"http://etherx.jabber.org/streams\">";
static const string SERVER_POST_TLS_RESPONSE =
    "<stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams"
    "\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" version=\"1.0\" xml:lang"
    "=\"en\"><stream:features><mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">"
    "<mechanism>PLAIN</mechanism><mechanism>DIGEST-MD5</mechanism><mechanism>SCRAM-SHA-1"
    "</mechanism></mechanisms><c xmlns=\"http://jabber.org/protocol/caps\" hash=\"sha-1\" "
    "node=\"http://www.dummy.net/en/ejabberd/\" ver=\"aIT+/ulfcbHXDKPkCA+iw9x5mU8=\"/>"
    "<register xmlns=\"http://jabber.org/features/iq-register\"/></stream:features>";
static const string SERVER_POST_SASL_RESPONSE =
    "<stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams"
    "\" id=\"65140440\" from=\"test-xmpp.dummy-host.com\" version=\"1.0\" xml:lang"
    "=\"en\"><stream:features><bind xmlns=\"urn:ietf:params:xml:ns:xmpp-bind\"/><c xmln"
    "s=\"http://jabber.org/protocol/caps\" hash=\"sha-1\" node=\"http://www.dummy.ne"
    "t/en/ejabberd/\" ver=\"aIT+/ulfcbHXDKPkCA+iw9x5mU8=\"/><register xmlns=\"http://jabb"
    "er.org/features/iq-register\"/></stream:features>";
static const string CLIENT_UNITTEST_PLAIN_AUTH =
    "<auth xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\""
    " mechanism=\"PLAIN\">AHVuaXR0ZXN0AHVuaXRUZXN0UGFzc3dvcmQ=</auth>";
static const string SERVER_AUTH_SUCCESS = "<success xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"/>";

// bind-gen [Client N/A]
// bind-mtn [Client MUST]
#ifdef REGEX_SUPPORTED
TEST(Xmpp_Compliance, bind_mtn)
#else
TEST(Xmpp_Compliance, DISABLED_bind_mtn)
#endif
{
    // Verify that bind is generated in a normal negotation
    SegmentArray normalSegments =
    {
        {"", Segment::WaitForSend},
        {"", Segment::WillCompleteBind},
        {"PLAIN", Segment::UpdateSASLPreferences},
        {SERVER_FIRST_RESPONSE},
        {CLIENT_START_TLS, Segment::WaitForSend},
        {SERVER_PROCEED_TLS},
        {CLIENT_RESTART_STREAM, Segment::WaitForSend},
        {SERVER_POST_TLS_RESPONSE},
        {CLIENT_UNITTEST_PLAIN_AUTH, Segment::WaitForSend},
        {SERVER_AUTH_SUCCESS},
        {CLIENT_RESTART_STREAM, Segment::WaitForSend},
        {SERVER_POST_SASL_RESPONSE},
        {"BINDRESULT", Segment::WaitForSendCapture},
        {
            "<iq id=\"${BINDRESULT.iq.id}\" type=\"result\"><bind xmlns=\"urn:ietf:par"
            "ams:xml:ns:xmpp-bind\"><jid>unittest@xmpp-dev/20750453861430175248849395</jid>"
            "</bind></iq>", Segment::ServerSubstitution
        },
        {"", Segment::ExitWithStateIntact}
    };

    XmppConfig config(MY_JID, DUMMY_TEST_HOST);

    SecureBuffer password;
    password.write("unitTestPassword");
    auto plainConfig = SaslPlain::Params::create("unittest", password);
    config.setSaslConfig("PLAIN", plainConfig);

    SegmentRunner runner(config);
    runner.run(normalSegments);
    EXPECT_NE(runner.captures()["BINDRESULT"].find(
                  "<bind xmlns=\"urn:ietf:params:xml:ns:xmpp-bind\"/>"),
              string::npos);

    auto stream = runner.stream();
    ASSERT_NE(stream, nullptr);
    JabberID boundID = stream->boundResource();
    ASSERT_GT(boundID.full().size(), 0UL);

    // It is not clear whether the compliance to bind-mtn requires that stanzas be limited
    // if binding does not complete. That is in constrast with the behavior of extensions like
    // in-band-registration, so we are assuming here that compliance implies that if the server
    // offers bind that we (as client) always bind.
}

// bind-restart [Client MUST]
#ifdef REGEX_SUPPORTED
TEST(Xmpp_Compliance, bind_restart)
#else
TEST(Xmpp_Compliance, DISABLED_bind_restart)
#endif
{
    // Attempt a manual restart after the resource-bind completes.
    SegmentArray normalSegments =
    {
        {"", Segment::WaitForSend},
        {"", Segment::WillCompleteBind},
        {"PLAIN", Segment::UpdateSASLPreferences},
        {SERVER_FIRST_RESPONSE},
        {CLIENT_START_TLS, Segment::WaitForSend},
        {SERVER_PROCEED_TLS},
        {CLIENT_RESTART_STREAM, Segment::WaitForSend},
        {SERVER_POST_TLS_RESPONSE},
        {CLIENT_UNITTEST_PLAIN_AUTH, Segment::WaitForSend},
        {SERVER_AUTH_SUCCESS},
        {CLIENT_RESTART_STREAM, Segment::WaitForSend},
        {SERVER_POST_SASL_RESPONSE},
        {"BINDRESULT", Segment::WaitForSendCapture},
        {
            "<iq id=\"${BINDRESULT.iq.id}\" type=\"result\"><bind xmlns=\"urn:ietf:par"
            "ams:xml:ns:xmpp-bind\"><jid>unittest@xmpp-dev/20750453861430175248849395</jid>"
            "</bind></iq>", Segment::ServerSubstitution
        },
        {"", Segment::ExitWithStateIntact}
    };

    XmppConfig config(MY_JID, DUMMY_TEST_HOST);

    SecureBuffer password;
    password.write("unitTestPassword");
    auto plainConfig = SaslPlain::Params::create("unittest", password);
    config.setSaslConfig("PLAIN", plainConfig);

    SegmentRunner runner(config);
    runner.run(normalSegments);

    auto stream = runner.stream();
    ASSERT_NE(stream, nullptr);

    auto streamTests = stream->getTestInterface();
    ASSERT_NE(streamTests, nullptr);
    EXPECT_THROW(streamTests->forceRestartStreamNow(), connect_error);
}

// bind-support [Client MUST]
#ifdef REGEX_SUPPORTED
TEST(Xmpp_Compliance, bind_support)
#else
TEST(Xmpp_Compliance, DISABLED_bind_support)
#endif
{
    // Verify that bind support is present.
    SegmentArray normalSegments =
    {
        {"", Segment::WaitForSend},
        {"", Segment::WillCompleteBind},
        {"PLAIN", Segment::UpdateSASLPreferences},
        {SERVER_FIRST_RESPONSE},
        {CLIENT_START_TLS, Segment::WaitForSend},
        {SERVER_PROCEED_TLS},
        {CLIENT_RESTART_STREAM, Segment::WaitForSend},
        {SERVER_POST_TLS_RESPONSE},
        {CLIENT_UNITTEST_PLAIN_AUTH, Segment::WaitForSend},
        {SERVER_AUTH_SUCCESS},
        {CLIENT_RESTART_STREAM, Segment::WaitForSend},
        {SERVER_POST_SASL_RESPONSE},
        {"BINDRESULT", Segment::WaitForSendCapture},
        {
            "<iq id=\"${BINDRESULT.iq.id}\" type=\"result\"><bind xmlns=\"urn:ietf:par"
            "ams:xml:ns:xmpp-bind\"><jid>unittest@xmpp-dev/20750453861430175248849395</jid>"
            "</bind></iq>", Segment::ServerSubstitution
        },
        {"", Segment::ExitWithStateIntact}
    };

    XmppConfig config(MY_JID, DUMMY_TEST_HOST);

    SecureBuffer password;
    password.write("unitTestPassword");
    auto plainConfig = SaslPlain::Params::create("unittest", password);
    config.setSaslConfig("PLAIN", plainConfig);

    SegmentRunner runner(config);
    runner.run(normalSegments);

    auto stream = runner.stream();
    ASSERT_NE(stream, nullptr);

    EXPECT_EQ(stream->boundResource(), JabberID("unittest@xmpp-dev/20750453861430175248849395"));
}


// sasl-correlate [Client SHOULD]
TEST(Xmpp_Compliance,  DISABLED_sasl_correlate)
{
    // TODO: If client has support for server SASL? This does not appear to be supported by
    //       our client flavors.
    EXPECT_TRUE(false);
}

// sasl-errors [Client MUST]
TEST(Xmpp_Compliance, sasl_errors)
{
    // Verify that bind support is present.
    SegmentArray normalSegments =
    {
        {"", Segment::WaitForSend},
        {"", Segment::WillCompleteBind},
        {"PLAIN", Segment::UpdateSASLPreferences},
        {SERVER_FIRST_RESPONSE},
        {CLIENT_START_TLS, Segment::WaitForSend},
        {SERVER_PROCEED_TLS},
        {CLIENT_RESTART_STREAM, Segment::WaitForSend},
        {SERVER_POST_TLS_RESPONSE},
        {CLIENT_UNITTEST_PLAIN_AUTH, Segment::WaitForSend},
        {
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><account-disabled/>"
            "<text xml:lang='en'>Test Text Value.</text></failure>"
        },
        {"", Segment::ExitWithStateIntact}
    };

    XmppConfig config(MY_JID, DUMMY_TEST_HOST);

    SecureBuffer password;
    password.write("unitTestPassword");
    auto plainConfig = SaslPlain::Params::create("unittest", password);
    config.setSaslConfig("PLAIN", plainConfig);

    SegmentRunner runner(config);
    runner.run(normalSegments);

    auto stream = runner.stream();
    ASSERT_NE(stream, nullptr);
    connect_error fail_err;
    EXPECT_THROW(
        try
    {
        stream->whenNegotiated().get();
    }
    catch (const connect_error &e)
    {
        fail_err = e;
        throw e;
    }, connect_error);

    EXPECT_EQ(fail_err, connect_error(connect_error::ecSaslNegotationFailure));

    // TODO: Support exposure of the SASL error to the upper layer...
}

// sasl-mtn [Client MUST]
TEST(Xmpp_Compliance,  DISABLED_sasl_mtn)
{
    EXPECT_TRUE(false);
}

// sasl-restart [Client MUST]
TEST(Xmpp_Compliance,  DISABLED_sasl_restart)
{
    EXPECT_TRUE(false);
}

// sasl-support [Client MUST]
TEST(Xmpp_Compliance,  DISABLED_sasl_support)
{
    EXPECT_TRUE(false);
}

// security-mti-auth-scram [Client MUST]  // TODO
TEST(Xmpp_Compliance,  DISABLED_security_mti_auth_scram)
{
    EXPECT_TRUE(false);
}

// security-mti-both-external [Client SHOULD]
TEST(Xmpp_Compliance,  DISABLED_security_mti_both_external)
{
    // TODO: Client does not currenly support 'EXTERNAL' SASL
    EXPECT_TRUE(false);
}

// security-mti-both-plain [Client SHOULD]
TEST(Xmpp_Compliance,  DISABLED_security_mti_both_plain)
{
    EXPECT_TRUE(false);
}

// security-mti-both-scram [Client MUST]
TEST(Xmpp_Compliance,  DISABLED_security_mti_both_scram)
{
    EXPECT_TRUE(false);
}


// Establish the stream normallly
shared_ptr<IXmppStream> establishStream()
{
    // Verify that bind support is present.
    SegmentArray normalSegments =
    {
        {"", Segment::WaitForSend},
        {"", Segment::WillCompleteBind},
        {SERVER_FIRST_RESPONSE},
        {CLIENT_START_TLS, Segment::WaitForSend},
        {SERVER_PROCEED_TLS},
        {CLIENT_RESTART_STREAM, Segment::WaitForSend},
        {SERVER_POST_TLS_RESPONSE},
        {CLIENT_UNITTEST_PLAIN_AUTH, Segment::WaitForSend},
        {SERVER_AUTH_SUCCESS},
        {CLIENT_RESTART_STREAM, Segment::WaitForSend},
        {SERVER_POST_SASL_RESPONSE},
        {"BINDRESULT", Segment::WaitForSendCapture},
        {
            "<iq id=\"${BINDRESULT.iq.id}\" type=\"result\"><bind xmlns=\"urn:ietf:par"
            "ams:xml:ns:xmpp-bind\"><jid>unittest@xmpp-dev/20750453861430175248849395</jid>"
            "</bind></iq>", Segment::ServerSubstitution
        },
        {"", Segment::ExitWithStateIntact}
    };

    XmppConfig config(MY_JID, DUMMY_TEST_HOST);

    SecureBuffer password;
    password.write("unitTestPassword");
    auto plainConfig = SaslPlain::Params::create("unittest", password);
    config.setSaslConfig("PLAIN", plainConfig);

    SegmentRunner runner(config);
    runner.run(normalSegments);

    return runner.stream();
}


// security-mti-confidentiality [Client N/A]
// stanza-attribute-from [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_attribute_from)
{
    //auto stream = establishStream();
    //ASSERT_NE(stream, nullptr);

    EXPECT_TRUE(false);
    //EXPECT_NO_THROW(stream->sendMessage(
}

// stanza-attribute-from-stamp [Client N/A]
// stanza-attribute-from-validate [Client N/A]
// stanza-attribute-id [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_attribute_id)
{
    EXPECT_TRUE(false);
}

// stanza-attribute-to [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_attribute_to)
{
    EXPECT_TRUE(false);
}

// stanza-attribute-to-validate [Client N/A]
// stanza-attribute-type [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_attribute_type)
{
    EXPECT_TRUE(false);
}

// stanza-attribute-xmllang [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_attribute_xmllang)
{
    EXPECT_TRUE(false);
}

// stanza-error [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_error)
{
    EXPECT_TRUE(false);
}

// stanza-error-child [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_error_child)
{
    EXPECT_TRUE(false);
}

// stanza-error-id [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_error_id)
{
    EXPECT_TRUE(false);
}

// stanza-error-reply [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_error_reply)
{
    EXPECT_TRUE(false);
}

// stanza-extension [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_extension)
{
    EXPECT_TRUE(false);
}

// stanza-iq-child [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_iq_child)
{
    EXPECT_TRUE(false);
}

// stanza-iq-id [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_iq_id)
{
    EXPECT_TRUE(false);
}

// stanza-iq-reply [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_iq_reply)
{
    EXPECT_TRUE(false);
}

// stanza-iq-type [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_iq_type)
{
    EXPECT_TRUE(false);
}

// stanza-kind-iq [CLIENT MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_kind_iq)
{
    EXPECT_TRUE(false);
}

// stanza-kind-message [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_kind_message)
{
    EXPECT_TRUE(false);
}

// stanza-kind-presence [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stanza_kind_presence)
{
    EXPECT_TRUE(false);
}

// stream-attribute-initial-from [Client SHOULD]
TEST(Xmpp_Compliance, DISABLED_stream_attribute_initial_from)
{
    EXPECT_TRUE(false);
}

// stream-attribute-initial-lang [Client SHOULD]
TEST(Xmpp_Compliance, DISABLED_stream_attribute_initial_lang)
{
    EXPECT_TRUE(false);
}

// stream-attribute-initial-to [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stream_attribute_initial_to)
{
    EXPECT_TRUE(false);
}

// stream-attribute-response-from [Client N/A]
// stream-attribute-response-id [Client N/A]
// stream-attribute-response-id-unique [Client N/A]
// stream-attribute-response-to [Client N/A]
// stream-error-generate [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stream_error_generate)
{
    EXPECT_TRUE(false);
}

// stream-fqdn-resolution [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stream_fqdn_resolution)
{
    EXPECT_TRUE(false);
}

// stream-negotiation-complete [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stream_negotiation_complete)
{
    EXPECT_TRUE(false);
}

// stream-negotiation-features [Client N/A]
TEST(Xmpp_Compliance, DISABLED_stream_negotiation_features)
{
    EXPECT_TRUE(false);
}

// stream-negotiation-restart [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stream_negotiation_restart)
{
    EXPECT_TRUE(false);
}

// stream-reconnect [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stream_reconnect)
{
    EXPECT_TRUE(false);
}

// stream-tcp-binding [Client MUST]
TEST(Xmpp_Compliance, DISABLED_stream_tcp_binding)
{
    EXPECT_TRUE(false);
}

// tls-cert [Client MUST]
TEST(Xmpp_Compliance, DISABLED_tls_cert)
{
    EXPECT_TRUE(false);
}

// tls-mtn [Client MUST]
TEST(Xmpp_Compliance, DISABLED_tls_mtn)
{
    EXPECT_TRUE(false);
}

// tls-restart [Client MUST]
TEST(Xmpp_Compliance, DISABLED_tls_restart)
{
    EXPECT_TRUE(false);
}

// tls-support [Client MUST]
TEST(Xmpp_Compliance, DISABLED_tls_support)
{
    EXPECT_TRUE(false);
}

// tls-correlate [Client SHOULD]
TEST(Xmpp_Compliance, DISABLED_tls_correlate)
{
    EXPECT_TRUE(false);
}

// xml-namespace-content-client [Client MUST]
TEST(Xmpp_Compliance, DISABLED_xml_namespace_content_client)
{
    EXPECT_TRUE(false);
}

// xml-namespace-context-server [Client N/A]
// xml-namespace-streams-declaration [Client MUST]
TEST(Xmpp_Compliance, DISABLED_xml_namespace_streams_declaration)
{
    EXPECT_TRUE(false);
}

// xml-namesapce-stream-prefix [Client MUST]
TEST(Xmpp_Compliance, DISABLED_xml_namespace_stream_prefix)
{
    EXPECT_TRUE(false);
}

// xml-restriction-comment [Client MUST]
TEST(Xmpp_Compliance, DISABLED_xml_restriction_comment)
{
    EXPECT_TRUE(false);
}

// xml-restriction-dtd [Client MUST]
TEST(Xmpp_Compliance, DISABLED_xml_restriction_dtd)
{
    EXPECT_TRUE(false);
}

// xml-restriction-pl [Client MUST]
TEST(Xmpp_Compliance, DISABLED_xml_restriction_pl)
{
    EXPECT_TRUE(false);
}

// xml-restriction-ref [Client MUST]
TEST(Xmpp_Compliance, DISABLED_xml_restriction_ref)
{
    EXPECT_TRUE(false);
}

// xml-wellformed-xml [Client MUST]
TEST(Xmpp_Compliance, DISABLED_xml_wellformed_xml)
{
    EXPECT_TRUE(false);
}

// xml-wellformed-ns [Client MUST]
TEST(Xmpp_Compliance, DISABLED_xml_wellformed_ns)
{
    EXPECT_TRUE(false);
}


#endif // ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
