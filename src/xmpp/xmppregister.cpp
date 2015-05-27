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

/// @file xmppregister.cpp

#include "stdafx.h"

#include "xmppregister.h"

#include "../connect/connecterror.h"


#ifndef DISABLE_SUPPORT_XEP0077

using namespace std;
using namespace Iotivity::XML;

namespace Iotivity
{
    namespace Xmpp
    {
        static const string XMPP_REGISTER_QUERY_NAMESPACE = "jabber:iq:register";

        struct InBandParamsImpl
        {
            InBandParamsImpl(): m_registrationParams() {}
            InBandParamsImpl(const InBandParamsImpl &p):
                m_registrationParams(p.m_registrationParams)
            {}

            std::map<std::string, std::string> m_registrationParams;
        };

        void InBandParamsImplDelete::operator()(InBandParamsImpl *p)
        {
            delete p;
        }


        //////////
        shared_ptr<InBandRegistration::Params> InBandRegistration::Params::create()
        {
            return shared_ptr<Params>(new Params);
        }

        InBandRegistration::Params::Params():
            p_(new InBandParamsImpl())
        {}

        InBandRegistration::Params::Params(const Params &params):
            p_(new InBandParamsImpl(*params.p_))
        {}

        bool InBandRegistration::Params::supportsExtension(const string &extensionName) const
        {
            return extensionName == InBandRegistration::extensionName();
        }

        void InBandRegistration::Params::setRegistrationParam(const string &fieldName, const string &value)
        {
            p_->m_registrationParams[fieldName] = value;
        }

        string InBandRegistration::Params::registrationParam(const string &fieldName) const
        {
            const auto f = p_->m_registrationParams.find(fieldName);
            return f != p_->m_registrationParams.end() ? f->second : "";
        }


        //////////
        InBandRegistration::InBandRegistration(std::shared_ptr<IXmppStream> overStream):
            XmppExtension(overStream), m_config()
        {
        }

        InBandRegistration::~InBandRegistration()
        {
            // Called here so any captured this is not stale when the queries halt.
            haltSafeQueries();
        }

        void InBandRegistration::assignConfiguration(std::shared_ptr<IExtensionParams> config)
        {
            if (config && config->supportsExtension(InBandRegistration::extensionName()))
            {
                m_config = static_pointer_cast<Params>(config);
            }
        }


        void InBandRegistration::registerUser(RegistrationCallback callback)
        {
            registerUser(m_config ? *m_config : Params(), callback);
        }

        void InBandRegistration::registerUser(const Params &registrationParams,
                                              RegistrationCallback callback)
        {
            {
                lock_guard<recursive_mutex> lock(mutex());
                if (m_currentRegistration)
                {
                    throw connect_error(connect_error::ecRegistrationAlreadyRunning);
                }
                m_currentRegistration = callback;
            }
            XMLElement::Ptr request = constructIQ("get");
            XMLElement::Ptr query = request->owner()->createElement("query");
            query->setAttribute("xmlns", XMPP_REGISTER_QUERY_NAMESPACE);
            request->appendChild(query);

            sendSafeQuery(move(request),
                          [this, registrationParams, callback]
                          (const connect_error & ce, XMLElement::Ptr response)
            {
                if (!ce.succeeded())
                {
                    callback(ce);
                    lock_guard<recursive_mutex> locK(mutex());
                    m_currentRegistration = RegistrationCallback();
                    return;
                }

                connect_error result = testAndProcessErrorResponse(response);
                if (!result.succeeded())
                {
                    callback(result);
                    lock_guard<recursive_mutex> locK(mutex());
                    m_currentRegistration = RegistrationCallback();
                    return;
                }

                processRegistration(registrationParams, callback, response);

            });
        }

        void InBandRegistration::processRegistration(const Params &params,
                RegistrationCallback callback,
                XMLElement::Ptr &response)
        {
            // Restart the query. Populate with registration parameters. Set.
            auto request = constructIQ("set");
            auto query = request->owner()->createElement("query");
            query->setAttribute("xmlns", XMPP_REGISTER_QUERY_NAMESPACE);
            request->appendChild(query);

            for (const auto &i : response->elements())
            {
                string xmlns;
                if (i->name() == "query" && i->getAttribute("xmlns", xmlns) &&
                    xmlns == XMPP_REGISTER_QUERY_NAMESPACE)
                {
                    for (const auto &j : i->elements())
                    {
                        if (j->name() == "registered")
                        {
                            // Already registered.
                            callback(connect_error::SUCCESS);
                            lock_guard<recursive_mutex> locK(mutex());
                            m_currentRegistration = RegistrationCallback();
                            return;
                        }
                        else if (j->name() != "instructions")
                        {
                            auto val = params.registrationParam(j->name());
                            if (val.size() > 0)
                            {
                                auto paramElement = request->owner()->createElement(j->name());
                                paramElement->setValue(val);
                                query->appendChild(paramElement);
                            }
                        }
                    }
                }
                else
                {
                    callback(connect_error::ecInvalidRegistration);
                    lock_guard<recursive_mutex> locK(mutex());
                    m_currentRegistration = RegistrationCallback();
                    return;
                }
            }

            // Continue the query
            sendSafeQuery(move(request),
                          [this, callback](const connect_error & ce, XMLElement::Ptr response)
            {
                if (!ce.succeeded())
                {
                    callback(ce);
                    lock_guard<recursive_mutex> locK(mutex());
                    m_currentRegistration = RegistrationCallback();
                    return;
                }

                callback(testAndProcessErrorResponse(response));
                lock_guard<recursive_mutex> locK(mutex());
                m_currentRegistration = RegistrationCallback();
            });
        }
    }
}

#endif // DISABLE_SUPPORT_XEP0077
