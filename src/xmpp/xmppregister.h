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

/// @file xmppregister.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "xmppextension.h"

#include <map>

// @file xmppregister.h
// XEP-0077 [In-Band Registration]

#ifndef DISABLE_SUPPORT_XEP0077

namespace Iotivity
{
    namespace Xmpp
    {
        class connect_error;

        // XEP-0077 In-Band Registration
        class InBandRegistration: public XmppExtension
        {
            public:
                class Params: public IExtensionParams
                {
                    public:
                        Params() = default;
                        static std::shared_ptr<Params> create();

                        virtual bool supportsExtension(const std::string &extensionName) const override;

                        void setRegistrationParam(const std::string &fieldName, const std::string &value);
                        std::string registrationParam(const std::string &fieldName) const;
                    private:
                        std::map<std::string, std::string> m_registrationParams;
                };
            public:
                InBandRegistration(std::shared_ptr<IXmppStream> overStream);
                virtual ~InBandRegistration() override;

                static std::string extensionName() { return "XEP0077"; }
                virtual std::string getExtensionName() const override
                {
                    return InBandRegistration::extensionName();
                }

                virtual void assignConfiguration(std::shared_ptr<IExtensionParams> config) override;

                typedef std::function<void(const connect_error &)> RegistrationCallback;
                // Register using the default assigned parameters (for registration during
                // stream negotation)
                void registerUser(RegistrationCallback callback);
                void registerUser(const Params &registrationParams, RegistrationCallback callback);
                //void unregisterUser(

            protected:
                void processRegistration(const Params &params, RegistrationCallback callback,
                                         XML::XMLElement::Ptr &response);
            private:
                RegistrationCallback m_currentRegistration;
                std::shared_ptr<Params> m_config;
        };
    }
}

#endif // DISABLE_SUPPORT_XEP0077
