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

/// @file boshclient.h

#pragma once


#include "../include/xmpp_feature_flags.h"
#include "../xml/portabledom.h"
#include "../common/actions.h"
#include "../common/stcqueue.h"
#include "../connect/connecterror.h"
#include <memory>
#include <map>
#include <future>

#ifndef DISABLE_SUPPORT_BOSH

/// @defgroup BOSH XMPP-BOSH Client Connectivity

namespace Iotivity
{
    namespace Xmpp
    {
        class IHttpConnection;

        /// @brief Base interface for the BOSH connection manager
        /// @interface IConnectionManager
        /// @ingroup BOSH
        class IConnectionManager
        {
            public:
                virtual ~IConnectionManager() {}
        };

        /// @brief Base interface for all BOSH connections.
        /// @interface IBOSHConnection
        /// @ingroup BOSH
        class IBOSHConnection
        {
            public:
                virtual ~IBOSHConnection() {}

                virtual void close() = 0;
                virtual void sendRequest(XML::XMLElement::Ptr request) = 0;
        };

        /// @cond HIDDEN_SYMBOLS
        ///
        /// Unit-test interface for the BOSH ConnectionManager.
        /// @note This is not intended to be used by applications.
        class ITestConnectionManager
        {
            public:
                virtual ~ITestConnectionManager() {}
                virtual size_t keyRolloverCount(const std::string &sid) const = 0;
        };
        /// @endcond

        /// @cond HIDDEN_SYMBOLS
        /// Unit-test interface for the BOSH sessions.
        ///
        /// @note This is not intended to be used by applications and is subject to change
        /// without notice.
        class ITestBOSHSession
        {
            public:
                virtual ~ITestBOSHSession() {}
        };
        /// @endcond

        /// @brief BOSH Connection Configuration
        /// @ingroup BOSH
        class BOSHConfig
        {
            public:
                BOSHConfig();
                BOSHConfig(const std::string &host);
                BOSHConfig(const BOSHConfig &) = default;
                BOSHConfig(BOSHConfig &&);
                ~BOSHConfig();

                BOSHConfig &operator=(const BOSHConfig &) = default;

                bool usingKeys() const { return m_useKeys; }
                std::string host() const { return m_host; }
                std::chrono::seconds maxWaitForServerResponse() const { return m_maxServerWait; }

                void setUseKeys(bool useKeys) { m_useKeys = useKeys; }
                void setMaxWaitForServerResponse(const std::chrono::seconds &);

            private:
                std::string m_host;
                bool m_useKeys;
                std::chrono::seconds m_maxServerWait;
        };

        class BOSHSession;


        /// @brief Context use for Actions running in the BOSH connection manager thread. This
        /// may provide detailed parameters to actions that require state.
        struct SessionContext
        {
            virtual ~SessionContext() {}
        };


        /// @brief The local BOSH connection manager.
        ///
        /// This connection manager manages multiple BOSH
        /// connections. It is possible, but not necessary, to run multiple ConnectionManager
        /// instances in a process. This connection manager is not intended to act as a server
        /// for a remote BOSH connection, so do not attempt to use it as a router without
        /// updating the implementation.
        ///
        /// @ingroup BOSH
        class ConnectionManager: public IConnectionManager, public ITestConnectionManager,
            public std::enable_shared_from_this<ConnectionManager>
        {
            public:
                typedef std::string SID;

            public:
                static std::shared_ptr<ConnectionManager> create();

                virtual ~ConnectionManager();

                typedef std::shared_ptr<std::promise<std::shared_ptr<IBOSHConnection>>>
                BOSHConnectionPromise;

                /// Initiate a BOSH session.
                /// @param config The configuration parameters of the remote BOSH server connection.
                /// @param connection A shared pointer to any connection which provides direct
                ///                   access to a remote BOSH connection manager.
                /// @param boshConnection A promise that will get a value if a connection is
                ///                       successfully established to the remote connection manager,
                ///                       otherwise it will throw an exception.
                /// @return Returns success iff session initiation could begin. If non-success is
                //          returned, do not wait on the boshConnection promise.
                virtual void initiateSession(const BOSHConfig &config,
                                             std::shared_ptr<IHttpConnection> connection,
                                             BOSHConnectionPromise boshConnection);

                void terminateSession(const SID &sid, const std::string &condition = "");
                void sendRequest(const SID &sid, XML::XMLElement::Ptr request);

            protected:
                ConnectionManager();

                void populateDefaultHeaders(std::list<std::string> &headers);

                void sendSynchronousRequest(std::shared_ptr<IHttpConnection> connection,
                                            XML::XMLElement::Ptr request,
                                            XML::XMLElement::Ptr &response);

                template <typename RequestFunc_>
                void sendSynchronousRequest(std::shared_ptr<IHttpConnection> connection,
                                            RequestFunc_ buildRequest,
                                            XML::XMLElement::Ptr &response)
                {
                    using namespace XML;
                    XMLDocument::Ptr reqDoc = XMLDocument::createEmptyDocument();
                    if (reqDoc)
                    {
                        XMLElement::Ptr sessionRequest = buildRequest(reqDoc);
                        if (sessionRequest)
                        {
                            reqDoc->appendChild(sessionRequest);
                            this->sendSynchronousRequest(connection, move(sessionRequest), response);
                        }
                        else
                        {
                            throw connect_error(LocalError(connect_error::ecOutOfMemory));
                        }
                    }
                }

                /// @brief Internal action runner for the BOSH connection manager.
                struct Runner: public ActionRunner<std::shared_ptr<IHttpConnection>, SessionContext>
                {
                        Runner(ConnectionManager &owner): m_owner(owner) {}

                    protected:
                        virtual std::thread createActionThread(std::shared_ptr<runner_queue> queue,
                                                               std::shared_ptr<IHttpConnection> connection) override;
                    private:
                        ConnectionManager &m_owner;
                };

                virtual size_t keyRolloverCount(const std::string &sid) const override;

            private:
                typedef std::map<SID, std::shared_ptr<BOSHSession>> SessionMap;

                mutable std::recursive_mutex m_mutex;
                bool m_shutdown;
                SessionMap m_sessionsBySID;
                Runner m_runner;
        };
    }
}

#endif // DISABLE_SUPPORT_BOSH