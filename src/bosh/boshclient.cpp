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

/// @file boshclient.cpp

#include "stdafx.h"

#include "boshclient.h"
#include "httpclient.h"
#include "../common/bufferencrypt.h"
#include "../common/rand_helper.h"
#include <openssl/sha.h>

#include <algorithm>
#include <atomic>
#include <map>

#ifndef DISABLE_SUPPORT_BOSH

using namespace std;
using namespace std::chrono;
using namespace Iotivity::XML;

#ifdef max
#undef max
#endif

typedef uint64_t RID;


// Most recent supported BOSH specification version. This is the specification version
// used to construct the code, but there may be issues with earlier verions that need
// to be addressed as found.
const string CLIENT_BOSH_VER = "1.11";


// MUST: The absolute maximum request ID allowed for a session.
const RID MAX_RID = 9007199254740991; // 2^53 -1
const uint64_t RID_UPPER_SEGEMENT_LENGTH = 2147483648;

chrono::milliseconds PRE_WAKE_INTERVAL = milliseconds(0);
const size_t DEFAULT_MAX_SERVER_WAIT = 60;


const list<string> EMPTY_HEADERS;

namespace Iotivity
{
    namespace Xmpp
    {
        //////////
        BOSHConfig::BOSHConfig():
            m_host(), m_useKeys(false), m_maxServerWait(DEFAULT_MAX_SERVER_WAIT)
        {}
        BOSHConfig::BOSHConfig(const string &host):
            m_host(host), m_useKeys(false), m_maxServerWait(DEFAULT_MAX_SERVER_WAIT)
        {}
        BOSHConfig::BOSHConfig(BOSHConfig &&bc)
        {
            m_host = move(bc.m_host);
            m_useKeys = move(bc.m_useKeys);
            m_maxServerWait = move(bc.m_maxServerWait);
        }
        BOSHConfig::~BOSHConfig() {}


        //////////

        /// @cond HIDDEN_SYMBOLS
        class BOSHSession
        {
            public:
                BOSHSession(const BOSHConfig &config, shared_ptr<IHttpConnection> httpConnection):
                    m_mutex(), m_httpConnection(httpConnection), m_rid(0), m_config(config),
                    m_serverBOSHVer(), m_sid(), m_serverWait(), m_shortestPollingInterval(),
                    m_inactivity(), m_requests(0), /*m_nextClientRid(0), m_lastServerRid(0),*/
                    m_serverHold(0), m_to(), m_acceptEncodings(), m_ack(0), m_maxPause(),
                    m_charSets(), m_from(), m_activeStream(), m_pendingRequests(),
                    m_queuedRequests(), m_nextInactivityTimeout(), m_nextPollOkay(system_clock::now()),
                    m_outstandingRequests(0), m_keyCache()
                {
                    m_rid = generateFirstRID();
                }

                BOSHSession(const BOSHSession &) = delete;
                ~BOSHSession() {}

                BOSHSession &operator=(const BOSHSession &bs) = delete;

                void switchHttpConnection(shared_ptr<IHttpConnection> httpConnection)
                {
                    lock_guard<recursive_mutex> lock(m_mutex);
                    m_httpConnection = httpConnection;
                }

                void resetInactivity()
                {
                    lock_guard<recursive_mutex> lock(m_mutex);
                    m_nextInactivityTimeout = system_clock::now() + m_inactivity;
                }

                system_clock::time_point nextPollOkayAt()
                {
                    lock_guard<recursive_mutex> lock(m_mutex);
                    return m_nextPollOkay;
                }

                void markPoll()
                {
                    lock_guard<recursive_mutex> lock(m_mutex);
                    m_nextPollOkay = system_clock::now() + m_shortestPollingInterval;
                }

                system_clock::time_point nextInactivityTime() const
                {
                    return m_nextInactivityTimeout - PRE_WAKE_INTERVAL;
                }

                void populateSession(XMLElement::Ptr sessionResponse)
                {
                    if (sessionResponse)
                    {
                        uint32_t waitInterval = 0;
                        // MUST: SID
                        if (!sessionResponse->getAttribute("sid", m_sid))
                        {
                            throw connect_error(connect_error::ecUnknownSID);
                        }
                        // MUST: Max seconds allowed to wait before responding to any request
                        if (sessionResponse->getAttribute("wait", waitInterval))
                        {
                            m_serverWait = seconds(waitInterval);
                        }
                        else
                        {
                            throw connect_error(connect_error::ecWaitMissing);
                        }
                        // MUST: Max number of requests outstanding (RECOMMENDED hold+1)
                        if (!sessionResponse->getAttribute("requests", m_requests))
                        {
                            throw connect_error(connect_error::ecRequestsMissing);
                        }

                        // SHOULD: Server highest BOSH supported version
                        sessionResponse->getAttribute("ver", m_serverBOSHVer);
                        // SHOULD: Shortest server polling interval in seconds
                        uint32_t shortestPollingInterval = 0;
                        if (sessionResponse->getAttribute("polling", shortestPollingInterval))
                        {
                            m_shortestPollingInterval = seconds(shortestPollingInterval);
                        }
                        // SHOULD: Longest valid inactivity interval in seconds
                        uint32_t inactivityInterval = 0;
                        if (sessionResponse->getAttribute("inactivity", inactivityInterval))
                        {
                            m_inactivity = seconds(inactivityInterval);
                        }
                        else
                        {
                            m_inactivity = seconds::max();
                        }
                        // SHOULD: Max number of requests the server will keep waiting
                        sessionResponse->getAttribute("hold", m_serverHold);
                        // SHOULD: Backend server to which the client is connecting
                        sessionResponse->getAttribute("to", m_to);
                        // MAY: Content encodings accepted by the server
                        sessionResponse->getAttribute("accept", m_acceptEncodings);
                        // MAY: Ack RID
                        sessionResponse->getAttribute("ack", m_ack);
                        // MAY: max number of pause seconds server may request
                        uint32_t maxPauseInterval = 0;
                        if (sessionResponse->getAttribute("maxpause", maxPauseInterval))
                        {
                            m_maxPause = seconds(maxPauseInterval);
                        }
                        // MAY: server supported character sets
                        sessionResponse->getAttribute("charsets", m_charSets);
                        // MAY: forwarded server identity
                        sessionResponse->getAttribute("from", m_from);

                        // MAY: server supports streams
                        sessionResponse->getAttribute("stream", m_activeStream);

                        // NOTE: authid is obsolete and not supported by this client.


                        resetInactivity();
                    }
                }

                const ConnectionManager::SID &SID() const { return m_sid; }

                shared_ptr<IHttpConnection> connection() const
                {
                    lock_guard<recursive_mutex> lock(m_mutex);
                    return m_httpConnection;
                }

                XMLElement::Ptr createRequestSession(XMLDocument::Ptr doc)
                {
                    XMLElement::Ptr request = createRequest(doc);
                    if (request)
                    {
                        // TODO: Get Jabber ID for XMPP session for the "from" attribute.

                        // SHOULD: target domain
                        request->setAttribute("to", m_config.host());
                        // SHOULD: default XML language
                        request->setAttribute("xml:lang", "en");
                        // SHOULD: version of the BOSH protocol
                        request->setAttribute("ver", CLIENT_BOSH_VER);
                        // SHOULD: longest time allowed to wait berfore responding to a request
                        request->setAttribute("wait", m_config.maxWaitForServerResponse().count());
                        // SHOULD: maximum requests the manager may keep waiting
                        request->setAttribute("hold", 1);

                        // To A Proxy Connection Manager: SHOULD
                        //request->setAttribute("route", "");
                        // MAY: jabberID of initiator
                        //request->setAttribute("from", jabberID);
                        // MAY: client uses acknowledgements
                        //request->setAttribute("ack", "1");
                        // MAY: Override the acceptable content type returned by the server
                        //request->setAttribute("content", "text/xml; charset=utf-8");

                        // XMPP specific fields.
                        request->setAttribute("xmlns:xmpp", "urn:xmpp:xbosh");
                        request->setAttribute("xmpp:version", "1.0");
                    }
                    return request;
                }

                XMLElement::Ptr createPayload(XMLDocument::Ptr doc,
                                              const list<XMLElement::Ptr> &payloads)
                {
                    XMLElement::Ptr request = createRequest(doc);
                    if (request)
                    {
                        // MUST: SID
                        request->setAttribute("sid", m_sid);

                        // If payloads is empty, this is a query for any pending responses
                        // so don't checkout for payloads.empty()
                        for (const auto &payload : payloads)
                        {
                            XMLNode::Ptr importedNode = doc->importNode(*payload.get());
                            if (importedNode)
                            {
                                request->appendChild(importedNode);
                            }
                        }
                    }
                    return request;
                }

                XMLElement::Ptr createAck(XMLDocument::Ptr doc, RID ackRID)
                {
                    XMLElement::Ptr ack;
                    if (doc)
                    {
                        ack = doc->createElement("body");

                        if (ack)
                        {

                            // MUST: RID increases monotonically
                            ack->setAttribute("ack", ackRID);
                            injectKey(ack);
                            ack->setAttribute("xmlns", "http://jabber.org/protocol/httpbind");
                        }
                    }
                    return ack;
                }

                XMLElement::Ptr createTerminate(XMLDocument::Ptr doc,
                                                const list<XMLElement::Ptr> &payloads,
                                                const std::string &condition = "")
                {
                    XMLElement::Ptr terminate = createPayload(doc, payloads);
                    if (terminate)
                    {
                        terminate->setAttribute("type", "terminate");
                        if (!condition.empty())
                        {
                            terminate->setAttribute("condition", condition);
                        }
                    }
                    return terminate;
                }

                void queueSendRequest(XMLElement::Ptr request)
                {
                    lock_guard<recursive_mutex> lock(m_mutex);
                    m_queuedRequests.emplace_back(move(request));
                }

                bool hasQueuedRequests() const
                {
                    lock_guard<recursive_mutex> lock(m_mutex);
                    return m_queuedRequests.size() > 0;
                }

                list<XMLElement::Ptr> popQueuedRequests()
                {
                    lock_guard<recursive_mutex> lock(m_mutex);
                    return move(m_queuedRequests);
                }

                size_t outstandingRequestCount()
                {
                    return m_outstandingRequests;
                }

                void incrementOutstandingRequests()
                {
                    ++m_outstandingRequests;
                }

                // For unit tests only. This is not to be made available to any external process.
                size_t keyRolloverCount() const
                {
                    return m_keyCache.size();
                }

            protected:
                XMLElement::Ptr createRequest(XML::XMLDocument::Ptr doc, const string &tag = "body")
                {
                    XMLElement::Ptr request;
                    if (doc)
                    {
                        request = doc->createElement(tag);

                        if (request)
                        {
                            // MUST: RID increases monotonically
                            request->setAttribute("rid", getNextRID());
                            injectKey(request);
                            request->setAttribute("xmlns", "http://jabber.org/protocol/httpbind");
                        }
                    }
                    return request;
                }

                RID generateFirstRID()
                {
                    uniform_int_distribution<RID> rngSelector(1, numeric_limits<RID>::max() -
                            MAX_RID - RID_UPPER_SEGEMENT_LENGTH);
                    return rngSelector(rand_helper::rng());
                }

                RID getNextRID()
                {
                    return ++m_rid;
                }

                virtual string generateKeys()
                {
                    mt19937 &rand = rand_helper::rng();
                    const size_t SEED_BUFFER_SIZE = 1024;

                    // Create random seed buffer
                    SecureBuffer seedBuf(SEED_BUFFER_SIZE);
                    if (seedBuf.size() == SEED_BUFFER_SIZE)
                    {
                        for (size_t i = 0; i < seedBuf.size(); ++i)
                        {
                            uniform_int_distribution<int> rngSelector(0, numeric_limits<int>::max());

                            ((uint8_t *)seedBuf)[i] = static_cast<uint8_t>(rngSelector(rand));
                        }
                    }

                    // NOTE: We are caching the computed SHA values rather than recomputing them.
                    //       This tradeoff means we will use more memory, but take less time.
                    //       The amortized time savings will be small, but the overall time may be
                    //       significant. This balance can be revisited if the choice is
                    //       inappropriate for a given platform.
                    size_t keyCount = uniform_int_distribution<size_t>(2, 512)(rand);

                    SecureBuffer currentSHA(SHA_DIGEST_LENGTH);

                    if (currentSHA.size())
                    {
                        SHA_CTX ctx = {0};

                        // NOTE: The referenced BOSH standard requires this to be SHA-1. Do not
                        //       change this unless the BOSH (XEP-0124) standard is updated.
                        SHA1_Init(&ctx);
                        SHA1_Update(&ctx, (const void *)seedBuf, seedBuf.size());
                        SHA1_Final(currentSHA, &ctx);

                        lock_guard<recursive_mutex> lock(m_mutex);
                        for (size_t i = 0; i < keyCount; ++i)
                        {
                            string hexStr = currentSHA.hexString();

                            // Despite language to the contrary in the XMPP spec, these hex
                            // strings must be lowercase for the hashes to match server
                            // expectations (tested against ejabberd).
                            transform(hexStr.begin(), hexStr.end(), hexStr.begin(), ::tolower);
                            m_keyCache.push_back(hexStr);


                            // NOTE: The refernced BOSH standard requires this to be SHA-1. Do not
                            //       change this unless the BOSH (XEP-0124) standard is updated.
                            SHA1_Init(&ctx);
                            SHA1_Update(&ctx, (const void *)&hexStr[0], hexStr.size());
                            SHA1_Final(currentSHA, &ctx);
                        }
                    }

                    bool newKeys;
                    return nextKey(newKeys);
                }

                virtual string nextKey(bool &newKeysNeeded)
                {
                    string currentKey;
                    lock_guard<recursive_mutex> lock(m_mutex);
                    newKeysNeeded = m_keyCache.size() < 2;
                    if (!m_keyCache.empty())
                    {
                        currentKey = m_keyCache.back();
                        m_keyCache.pop_back();
                    }
                    return currentKey;
                }

                void injectKey(XMLElement::Ptr &element)
                {
                    if (m_config.usingKeys() && element)
                    {
                        bool newKeysNeeded = false;
                        string key = nextKey(newKeysNeeded);
                        if (key.size())
                        {
                            element->setAttribute("key", key);
                        }
                        if (newKeysNeeded)
                        {
                            element->setAttribute("newkey", generateKeys());
                        }
                    }
                }

            private:
                mutable recursive_mutex m_mutex;
                shared_ptr<IHttpConnection> m_httpConnection;
                atomic<RID> m_rid; // request ID
                BOSHConfig m_config;
                string m_serverBOSHVer;
                ConnectionManager::SID m_sid;
                seconds m_serverWait;
                seconds m_shortestPollingInterval;
                seconds m_inactivity;
                uint32_t m_requests;
  //              RID m_nextClientRid;
  //              RID m_lastServerRid;
                uint32_t m_serverHold;
                string m_to;
                string m_acceptEncodings;
                RID m_ack;
                seconds m_maxPause;
                string m_charSets;
                string m_from;
                string m_activeStream;

                map<RID, XMLElement::Ptr> m_pendingRequests;
                list<XMLElement::Ptr> m_queuedRequests;
                system_clock::time_point m_nextInactivityTimeout;
                system_clock::time_point m_nextPollOkay;

                atomic<size_t> m_outstandingRequests;

                // TODO: Add key feature
                list<string> m_keyCache;
        };
        /// @endcond

        //////////
        // A thin through-layer between the IConnection interface and the connection manager.
        /// @cond HIDDEN_SYMBOLS
        class BOSHConnection: public IBOSHConnection
        {
            public:
                BOSHConnection(shared_ptr<ConnectionManager> owner, ConnectionManager::SID sid):
                    m_mutex(), m_owner(owner), m_sid(sid) {}

                virtual void close() override
                {
                    shared_ptr<ConnectionManager> owner = m_owner.lock();
                    if (owner)
                    {
                        owner->terminateSession(m_sid);
                    }
                }

                virtual void sendRequest(XMLElement::Ptr request) override
                {
                    shared_ptr<ConnectionManager> owner = m_owner.lock();
                    if (owner)
                    {
                        owner->sendRequest(m_sid, move(request));
                    }
                }

            private:
                recursive_mutex m_mutex;
                weak_ptr<ConnectionManager> m_owner;
                ConnectionManager::SID m_sid;
        };
        /// @endcond


        //////////
        shared_ptr<ConnectionManager> ConnectionManager::create()
        {
            class temp_derived: public ConnectionManager {};
            return make_shared<temp_derived>();
        }

        ConnectionManager::ConnectionManager():
            m_mutex(), m_shutdown(false), m_sessionsBySID(), m_runner(*this)
        {
        }

        ConnectionManager::~ConnectionManager()
        {
            m_shutdown = true;
            m_runner.shutdown();
        }

        size_t ConnectionManager::keyRolloverCount(const std::string &sid) const
        {
            lock_guard<recursive_mutex> lock(m_mutex);
            const auto f = m_sessionsBySID.find(sid);
            if (f != m_sessionsBySID.end())
            {
                shared_ptr<BOSHSession> session = f->second;
                return session->keyRolloverCount();
            }
            return 0;
        }

        void ConnectionManager::initiateSession(const BOSHConfig &config,
                                                shared_ptr<IHttpConnection> connection,
                                                BOSHConnectionPromise boshConnection)
        {
            if (connection && boshConnection)
            {
                try
                {
                    auto initiateRequestSessionAction =
                        [this, connection, boshConnection, config](SessionContext &)
                    {
                        try
                        {
                            auto session = make_shared<BOSHSession>(config, connection);

                            XMLElement::Ptr response;
                            sendSynchronousRequest(connection,
                                                   [&session](XMLDocument::Ptr doc)
                            {
                                return session->createRequestSession(doc);
                            },
                            response);

                            if (response)
                            {
                                ConnectionManager::SID sid;
                                if (response->getAttribute("sid", sid))
                                {
                                    lock_guard<recursive_mutex> lock(m_mutex);
                                    if (m_sessionsBySID.find(sid) == m_sessionsBySID.end())
                                    {
                                        session->populateSession(move(response));
                                        m_sessionsBySID[sid] = session;

                                        shared_ptr<BOSHConnection> connection =
                                            make_shared<BOSHConnection>(shared_from_this(), sid);

                                        boshConnection->set_value(connection);
                                    }
                                    else
                                    {
                                        throw connect_error(connect_error::ecSIDReused);
                                    }
                                }
                                else
                                {
                                    throw connect_error(connect_error::ecUnknownSID);
                                }
                            }
                        }
                        // TODO: make connect_error std::exception derived
                        catch (const connect_error &)
                        {
                            boshConnection->set_exception(current_exception());
                        }
                        catch (const exception &)
                        {
                            boshConnection->set_exception(current_exception());
                        }
                    };

                    m_runner.getQueue(connection)->push(Runner::make_action_from(
                                                            initiateRequestSessionAction));
                }
                catch (const exception &)
                {
                    boshConnection->set_exception(current_exception());
                }
            }
            else
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
        }

        void ConnectionManager::terminateSession(const SID &sid, const string &condition)
        {
            try
            {
                lock_guard<recursive_mutex> lock(m_mutex);
                const auto f = m_sessionsBySID.find(sid);
                if (f != m_sessionsBySID.end())
                {
                    auto session = f->second;
                    auto terminateAction = [this, session, condition](SessionContext &)
                    {
                        try
                        {
                            XMLElement::Ptr response;
                            sendSynchronousRequest(session->connection(),
                                                   [&session, &condition](XMLDocument::Ptr doc)
                            {
                                list<XMLElement::Ptr> payloads;
                                return session->createTerminate(doc, payloads,
                                                                condition);
                            },
                            response);
                        }
                        catch (const exception &)
                        {}

                    };
                    m_runner.getQueue(session->connection())->push(Runner::make_action_from(
                                terminateAction));
                }
                else
                {
                    throw connect_error(connect_error::ecUnknownSID);
                }
            }
            catch (const connect_error &ce)
            {
                throw ce;
            }
            catch (const exception &)
            {}
        }

        void ConnectionManager::sendRequest(const SID &sid, XML::XMLElement::Ptr request)
        {
            lock_guard<recursive_mutex> lock(m_mutex);
            const auto f = m_sessionsBySID.find(sid);
            if (f != m_sessionsBySID.end())
            {
                auto session = f->second;
                // C++11 doesn't allow a move in a lambda capture so we're cheating.
                // sendAction is effectively taking ownership of the pointer.
                XML::XMLElement *requestPtr = request.release();
                auto sendAction =
                    [session, requestPtr](SessionContext &)
                {
                    session->queueSendRequest(XMLElement::Ptr(requestPtr));
                };
                m_runner.getQueue(session->connection())->push(Runner::make_action_from(
                            sendAction));

            }
        }

        void ConnectionManager::sendSynchronousRequest(
            shared_ptr<IHttpConnection> connection, XML::XMLElement::Ptr request,
            XML::XMLElement::Ptr &response)
        {
            if (request && connection)
            {
                list<string> headers;
                this->populateDefaultHeaders(headers);
                connection->postHttp(headers, request->xml());

                connection->performSynchronousConnect();
                try
                {
                    XMLDocument::Ptr respDoc = XMLDocument::createEmptyDocument();
                    if (respDoc)
                    {
                        respDoc->parse(connection->response());
                        response = respDoc->documentElement();
                    }
                    else
                    {
                        throw connect_error(LocalError(connect_error::ecOutOfMemory));
                    }
                }
                catch (const rapidxml::parse_error &)
                {
                    throw connect_error(connect_error::ecXMLParserError);
                }
            }
            else
            {
                throw connect_error(LocalError(connect_error::ecInvalidParameter));
            }
        }

        void ConnectionManager::populateDefaultHeaders(list<string> &headers)
        {
            headers.push_back("Content-Type: text/xml; charset=utf-8");
            headers.push_back("Accept:");

            // TODO: Determine if we can get gunzip in place in time...
            //headers.push_back("Accept-Encoding: gzip, deflate");
        }

        std::thread ConnectionManager::Runner::createActionThread(shared_ptr<runner_queue> queue,
                shared_ptr<IHttpConnection> connection)
        {
            // The following thread is the primary message pump for BOSH connections
            // over a single HTTP connection. It wakes periodically to handle required
            // inactivity timeouts but normally remains dormant until sent a task
            // by the connection manager. Note that the majority of the behaviors
            // of the thread are encapsulated in these tasks. It is essential when
            // writing tasks for this thread to use no capture variables passed by reference.
            return thread([this, queue, connection]()
            {
                milliseconds nextWake = milliseconds(100);
                while (!queue->isClosed())
                {
                    shared_ptr<runner_action> nextAction;
                    if (queue->pop(nextWake, nextAction))
                    {
                        if (nextAction)
                        {
                            struct CurrentSessionContext: public SessionContext
                            {} sessionContext;

                            try
                            {
                                (*nextAction)(sessionContext);
                            }
                            catch (...)
                            {
                                // TODO: Add logging?
                            }
                        }
                    }

                    system_clock::time_point now = system_clock::now();
                    // TODO: periodic activities
                    for (auto i : m_owner.m_sessionsBySID)
                    {
                        shared_ptr<BOSHSession> session = i.second;
                        if (session->connection() == connection)
                        {
                            auto nextWakeTime = i.second->nextInactivityTime();
                            if (session->hasQueuedRequests() || nextWakeTime <= now)
                            {
                                XMLElement::Ptr response;
                                try
                                {
                                    m_owner.sendSynchronousRequest(session->connection(),
                                                                   [&session](XMLDocument::Ptr doc)
                                    {
                                        list<XMLElement::Ptr> payloads;
                                        payloads = session->popQueuedRequests();
                                        return session->createPayload(doc, payloads);
                                    },
                                    response);

                                    session->resetInactivity();
                                    session->markPoll();

                                    session->incrementOutstandingRequests();
                                }
                                catch (const connect_error &)
                                {

                                }

                                nextWake = milliseconds(0);
                            }
                            else
                            {
                                auto wakeInterval = nextWakeTime - now;
                                if (wakeInterval < nextWake)
                                {
                                    nextWake = duration_cast<milliseconds>(wakeInterval);
                                }
                            }

                        }
                    }
                }
            });
        }

    }
}

#endif // DISABLE_SUPPORT_BOSH
