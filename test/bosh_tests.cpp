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

/// @file bosh_tests.cpp

#include "stdafx.h"
#include <gtest/gtest.h>


#include <bosh/httpclient.h>
#include <bosh/boshclient.h>
#include <connect/proxy.h>
#include <common/logstream.h>
#include <common/bufferencrypt.h>

#include "xmpp_test_config.h"
#include "xmpp_connect_config.h"

#include <openssl/sha.h>

#include <future>
#include <algorithm>


#ifndef DISABLE_SUPPORT_BOSH

using namespace std;
using namespace Iotivity;
using namespace Iotivity::XML;
using namespace Iotivity::Xmpp;

TEST(BOSH, BOSHConfig)
{
    BOSHConfig config(DUMMY_TEST_HOST);
    EXPECT_EQ(config.host(), DUMMY_TEST_HOST);

    BOSHConfig copyConfig(config);
    EXPECT_EQ(copyConfig.host(), DUMMY_TEST_HOST);

    BOSHConfig moveConfig;
    EXPECT_EQ(moveConfig.host(), "");
    moveConfig = std::move(config);
    EXPECT_EQ(moveConfig.host(), DUMMY_TEST_HOST);
}

TEST(BOSH, TestPromise)
{
    shared_ptr<promise<int>> resultPromise = make_shared<promise<int>>();
    thread([](shared_ptr<promise<int>> p)
    {
        this_thread::sleep_for(chrono::seconds(2));
        p->set_value(2);
    }, resultPromise).detach();
    resultPromise->get_future().wait_for(chrono::milliseconds(100));
}

#ifdef ENABLE_FUNCTIONAL_TESTING
TEST(BOSH, TestClientConnection)
#else
TEST(BOSH, DISABLED_TestClientConnection)
#endif
{
#ifdef ENABLE_LIBSTROPHE
    if (!xmpp_connect_config::hasConfig("NO_PROXY"))
#else
    if (!xmpp_connect_config::hasConfig())
#endif
    {
        cout << "TestClientConnection skipped. No XMPP config." << endl;
        return;
    }

    auto connection = make_shared<HttpCurlConnection>(xmpp_connect_config::BOSHUrl());

    connection->setProxy(ProxyConfig::queryProxy());

    shared_ptr<ConnectionManager> manager = ConnectionManager::create();
    ASSERT_NE(manager, nullptr);
    BOSHConfig config(xmpp_connect_config::host());

    config.setUseKeys(true);

    auto promiseConnection = make_shared<promise<shared_ptr<IBOSHConnection>>>();
    auto connectionFuture = promiseConnection->get_future();

    ASSERT_NO_THROW(
        manager->initiateSession(config, static_pointer_cast<IHttpConnection>(connection),
                                 promiseConnection));

    shared_ptr<IBOSHConnection> boshConnection;
    EXPECT_NO_THROW(boshConnection = connectionFuture.get());
    EXPECT_NE(boshConnection, nullptr);
    if (boshConnection)
    {
        boshConnection->close();
    }
}


// Dummy server. Not intended to handle multiple connections.
class DummyServer: public enable_shared_from_this<DummyServer>
{
    private:
        bool m_showHTTP;
        bool m_clientWellBehaved;
        recursive_mutex m_mutex;

        size_t m_bodyCount;
        list<string> m_responses;
        string m_sid;
        uint64_t m_clientRID;
        size_t m_clientWait;
        size_t m_clientHold;
        string m_prevKey;

    protected:
        void handleHttp(const list<string> &headers, const string &body)
        {
            if (m_showHTTP)
            {
                cout << "DUMMY SERVER" << endl;
                for (auto h : headers)
                {
                    cout << "HEADER: " << h << endl;
                }
                cout << "BODY" << body << endl;
            }

            try
            {
                auto bodyDoc = XMLDocument::createEmptyDocument();
                auto respDoc = XMLDocument::createEmptyDocument();
                if (bodyDoc && respDoc)
                {
                    bodyDoc->parse(body);

                    XMLElement::Ptr element = bodyDoc->documentElement();
                    if (element)
                    {
                        string ridStr;
                        element->getAttribute("rid", ridStr);
                        uint64_t ridVal = strtoull(ridStr.c_str(), nullptr, 10);

                        string sidStr;
                        element->getAttribute("sid", sidStr);
                        if (sidStr.size() > 0)
                        {
                            if (sidStr != "testsid")
                            {
                                m_clientWellBehaved = false;
                                sendTerminate();
                            }

                            string currentKey, newKey;
                            element->getAttribute("key", currentKey);
                            element->getAttribute("newkey", newKey);

                            if (currentKey.size() > 0 && m_prevKey.size() > 0)
                            {
                                testKey(currentKey);
                                m_prevKey = newKey.size() > 0 ? newKey : currentKey;
                            }

                            ++m_bodyCount;

                            // With intermediate routing the server may experience out-of-order
                            // bodies, but since this is a simulation, we are testing to be
                            // certain the client doesn't send anything out-of-order.
                            if (ridVal != m_clientRID + 1)
                            {
                                m_clientWellBehaved = false;
                                sendTerminate();
                            }
                            else
                            {
                                m_clientRID = ridVal;
                            }
                        }
                        else
                        {
                            // Handle session response
                            m_clientRID = ridVal;

                            element->getAttribute("wait", m_clientWait);
                            element->getAttribute("hold", m_clientHold);
                            element->getAttribute("newkey", m_prevKey);

                            queueResponse(createSessionResponse(bodyDoc, respDoc));
                        }
                    }
                }
            }
            catch (const rapidxml::parse_error &)
            {}

        }

        void testKey(const string &key)
        {
            SecureBuffer currentSHA(SHA_DIGEST_LENGTH);
            SHA_CTX ctx = {0};

            SHA1_Init(&ctx);
            SHA1_Update(&ctx, (const void *)&key[0], key.size());
            SHA1_Final(currentSHA, &ctx);

            string hexStr = currentSHA.hexString();

            transform(hexStr.begin(), hexStr.end(), hexStr.begin(), ::tolower);
            if (hexStr != m_prevKey)
            {
                m_clientWellBehaved = false;
            }
        }

        void sendTerminate()
        {

        }

        void queueResponse(XMLElement::Ptr element)
        {
            if (element)
            {
                lock_guard<recursive_mutex> locK(m_mutex);
                m_responses.push_back(element->xml());
            }
        }

        XMLElement::Ptr createSessionResponse(XMLDocument::Ptr requestDoc,
                                              XMLDocument::Ptr responseDoc)
        {
            XMLElement::Ptr resp;
            if (requestDoc && responseDoc)
            {
                resp = responseDoc->createElement("body");
                if (resp)
                {
                    resp->setAttribute("ver", "1.11");

                    resp->setAttribute("sid", "testsid");
                    resp->setAttribute("xmlns", "http://jabber.org/protocol/httpbind");
                    resp->setAttribute("wait", m_clientWait);
                    resp->setAttribute("requests", m_clientHold + 1);
                    resp->setAttribute("inactivity", "1");
                    resp->setAttribute("polling", "2");
                    resp->setAttribute("from", "DummyTestServer");
                }

            }
            return resp;
        }

        string nextResponse()
        {
            lock_guard<recursive_mutex> lock(m_mutex);
            string nextResp;
            if (!m_responses.empty())
            {
                nextResp = m_responses.front();
                m_responses.pop_front();
            }
            return nextResp;
        }


        class DummyServerConnection: public IHttpConnection
        {
            public:
                DummyServerConnection(shared_ptr<DummyServer> owner): m_owner(owner)
                {
                }

                virtual void close() override
                {
                }

                virtual void postHttp(const list<string> &headers, const string &body) override
                {
                    shared_ptr<DummyServer> owner = m_owner.lock();
                    if (owner)
                    {
                        owner->handleHttp(headers, body);
                    }
                }

                virtual void performSynchronousConnect() override
                {}

                virtual string response() const override
                {
                    shared_ptr<DummyServer> owner = m_owner.lock();
                    if (owner)
                    {
                        return owner->nextResponse();
                    }
                    return "";
                }
            private:
                weak_ptr<DummyServer> m_owner;
        };
    public:
        DummyServer():
            m_showHTTP(false), m_clientWellBehaved(true), m_bodyCount(0),
            m_clientWait(60), m_clientHold(1) {}
        ~DummyServer() {}

        bool clientWasWellBehaved() const { return m_clientWellBehaved; }
        size_t bodyCount() const { return m_bodyCount; }

        shared_ptr<IHttpConnection> connectDummyServer()
        {
            return make_shared<DummyServerConnection>(shared_from_this());
        }
};



shared_ptr<IBOSHConnection> connectDummyServer(const BOSHConfig &config,
        shared_ptr<DummyServer> simServer,
        shared_ptr<ConnectionManager> manager)
{
    shared_ptr<IBOSHConnection> boshConnection;

    if (manager && simServer)
    {
        auto connection = simServer->connectDummyServer();

        auto promiseConnection = make_shared<promise<shared_ptr<IBOSHConnection>>>();
        auto connectionFuture = promiseConnection->get_future();

        manager->initiateSession(config, static_pointer_cast<IHttpConnection>(connection),
                                 promiseConnection);

        try
        {
            boshConnection = connectionFuture.get();
        }
        catch (...) {}
    }
    return boshConnection;
}


TEST(BOSH, BoshKeyGen)
{
    auto simServer = make_shared<DummyServer>();
    auto manager = ConnectionManager::create();

    BOSHConfig config("dummyserver");
    config.setUseKeys(true);

    shared_ptr<IBOSHConnection> boshConnection;
    ASSERT_NO_THROW( boshConnection = connectDummyServer(config, simServer, manager));
    ASSERT_NE(boshConnection, nullptr);

    // Send enough payloads to generate at least one rollover.
    const size_t rollover = static_cast<ITestConnectionManager *>
                            (manager.get())->keyRolloverCount("testsid");
    EXPECT_GT(rollover, 0UL);

    size_t index = rollover * 2;
    const string testStr = "<dummypayload/>";
    while (index-- > 0)
    {
        auto doc = XMLDocument::createEmptyDocument();
        ASSERT_NE(doc, nullptr);
        EXPECT_NO_THROW(doc->parse(testStr));
        ASSERT_NE(doc->documentElement(), nullptr);
        boshConnection->sendRequest(doc->documentElement());
    }

    auto startTime = chrono::system_clock::now();
    while (simServer->bodyCount() < rollover)
    {
        this_thread::sleep_for(chrono::milliseconds(1));
        ASSERT_LT(chrono::system_clock::now() - startTime, chrono::seconds(10));
    }
    cout << "ROLLOVER TEST COUNT: " << simServer->bodyCount() << endl;

    // NOTE: Keys must be okay for the well-behaved flag to be true.
    EXPECT_TRUE(simServer->clientWasWellBehaved());
}


TEST(BOSH, BoshClientInactivity)
{
    auto simServer = make_shared<DummyServer>();
    auto manager = ConnectionManager::create();

    BOSHConfig config("dummyserver");
    auto boshConnection = connectDummyServer(config, simServer, manager);
    ASSERT_NE(boshConnection, nullptr);

    // Let the inactivity timer run out a bit. We expect to see two inactivity polls
    // in this 3 second interval from the dummy server.
    this_thread::sleep_for(chrono::seconds(3));

    EXPECT_GT(simServer->bodyCount(), 1UL);
    EXPECT_TRUE(simServer->clientWasWellBehaved());
}


// TODO: Logging

#endif // DISABLE_SUPPORT_BOSH