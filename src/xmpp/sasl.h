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

/// @file sasl.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "../common/bufferencrypt.h"
#include "xmppinterfaces.h"

#include "../include/ccfxmpp.h"

#include <string>
#include <functional>
#include <list>
#include <memory>
#include <map>
#include <mutex>

#ifdef _WIN32
XMPP_TEMPLATE template class XMPP_API std::basic_string<char, std::char_traits<char>,
        std::allocator<char>>;
#endif


namespace Iotivity
{
    namespace Xmpp
    {

        /// @brief Result of a SASL authorization attempt. Provides state information for
        /// an ongoing SASL challenge/response session.
        struct SaslResult
        {
                enum AuthResult
                {
                    Challenge,
                    Response,
                    Abort,
                    Success,
                    Failure
                };

                SaslResult(AuthResult result): m_result(result) {}
                SaslResult(const SaslResult &) = default;

                AuthResult result() const { return m_result; }

            private:
                AuthResult m_result;
        };

        /// @brief Factory class which constructs SASL mechanisms given the name of the mechanism
        /// provides by XMPP stream establishment.
        ///
        /// Mechanisms to be used by an XMPP stream must be registered with the SaslFactory
        /// prior to the establishment of an XMPP stream. All SASL mechanism defined in this
        /// header file are auto-registered as part of the factory construction process.
        class SaslFactory
        {
            public:

                // Priority to register with to ensure mechanism comes before any
                // existing default SASLs.
                static const size_t LOWEST_SASL_PRIORITY = 0;
                static const size_t HIGHEST_BUILT_IN_SASL_PRIORITY = 128;
                static const size_t HIGHEST_SASL_PRIORITY = ~0UL;

                typedef std::function<std::shared_ptr<ISaslMechanism>(const std::string &)>
                ConstructSaslMechanism;

                static std::list<std::string> defaultSaslOrder();
                static std::shared_ptr<ISaslMechanism> createSaslMechanism(const std::string &name);
                static void registerSaslMechanism(const std::string &name, size_t priority,
                                                  ConstructSaslMechanism constructorFunc);

                static std::list<std::string> restrictToKnownMechanisms(
                    const std::list<std::string> &mechanisms);

                static std::string selectMechanism(const std::list<std::string> &clientMechanisms,
                                                   const std::list<std::string> &serverMechanisms);

            private:
                SaslFactory();
                SaslFactory(const SaslFactory &) = delete;
                SaslFactory &operator=(const SaslFactory &) = delete;

                static SaslFactory &factory();
                void doRegisterSaslMechanism(const std::string &name, size_t priority,
                                             ConstructSaslMechanism constructorFunc);

                // NOTE: recursive_mutex is more functionality than we really require, but
                //       to avoid using both recursive_mutex and mutex in the same code base,
                //       we are upgrading to recursive_mutex here.
                std::recursive_mutex m_mutex;
                typedef std::map<std::string, ConstructSaslMechanism> Constructors;
                Constructors m_constructors;

                typedef std::multimap<size_t, std::string> Priority;
                Priority m_priorities;
        };

        /// @brief Provides a default implementation of the ISaslUserPasswordParams interface.
        ///
        /// Provides user-name and password to a SASL mechanism that requires int.
        struct XMPP_API UserPasswordParams: public ISaslParams
        {
                virtual std::string authenticationIdentity() const override
                {
                    return m_authenticationIdentity;
                }

                virtual SecureBuffer password() const override
                {
                    return m_password;
                }

            protected:
                UserPasswordParams(const std::string &authenticationIdentity,
                                   const SecureBuffer &password):
                    m_authenticationIdentity(authenticationIdentity),
                    m_password(password)
                {}
            private:
                std::string m_authenticationIdentity; // Identity matching password
                SecureBuffer m_password;
        };



        /// @brief Provides the SASL mechanism 'PLAIN'. By default SaslPlain may not be
        ///        negotiated over an XMPP stream until TLS is already in place.
        ///
        /// @note See RFC4616 for details
        class SaslPlain: public ISaslMechanism
        {
            public:
                /// @brief Provides parameters to the SaslPlain SASL mechanism.
                ///
                /// Should be passed to an XMPPConfig object to provide SASL parameters to SaslPlain
                /// as needed.
                struct XMPP_API Params: public UserPasswordParams
                {
                        static std::shared_ptr<Params> create(const std::string &authenticationIdentity,
                                                              const SecureBuffer &password);

                        virtual bool supportsMechanism(const std::string &mechanism) const override
                        {
                            return mechanism == "PLAIN";
                        }

                        virtual void setAuthorizationIdentity(const std::string &identity)
                        {
                            m_authorizationIdentity = identity;
                        }

                        virtual std::string authorizationIdentity() const
                        {
                            return m_authorizationIdentity;
                        }
                    protected:
                        Params(const std::string &authenticationIdentity, const SecureBuffer &password):
                            UserPasswordParams(authenticationIdentity, password),
                            m_authorizationIdentity()
                        {}
                    private:
                        std::string m_authorizationIdentity; // Acting identity
                };

                virtual bool requiresAuthenticatedStream() const override { return true; }

                virtual void setParams(std::shared_ptr<ISaslParams> params) override;

                virtual SecureBuffer initiate() override;
                virtual SecureBuffer challenge() override;
                virtual void handleChallenge(const SecureBuffer &response,
                                             ResponseCallback callback) override;
                virtual void handleResponse(const SecureBuffer &response,
                                            ResponseCallback callback) override;
                virtual void handleSuccess(const SecureBuffer &response,
                                           ResponseCallback callback) override;
            private:
                std::shared_ptr<Params> m_params;
        };

        // OBSOLETE RFC6331
        //class SaslDigestMD5: public ISaslMechanism
        //{
        //public:
        //    virtual std::string name() const { return "DIGEST-MD5"; }
        //};


        // TODO:
        /// @brief Provides the SASL mechanism 'SCRAM-SHA-1'.
        ///
        /// @note See RFC5802 for details
        class SaslScramSha1: public ISaslMechanism
        {
            public:
                /// @brief Provides parameters to the SaslScramSha1 SCRAM-SHA-1 mechanism.
                ///
                /// Should be passed to an XMPPConfig object to provide SASL parameters to
                /// SaslScramSha1 as needed.
                struct XMPP_API Params: public UserPasswordParams
                {
                        static std::shared_ptr<Params> create(const std::string &authenticationIdentity,
                                                              const SecureBuffer &password);

                        bool supportsMechanism(const std::string &mechanism) const
                        {
                            return mechanism == "SCRAM-SHA-1";
                        }

                    protected:
                        Params(const std::string &authenticationIdentity, const SecureBuffer &password):
                            UserPasswordParams(authenticationIdentity, password)
                        {}
                };

                SaslScramSha1(): m_iterations(0) {}

                virtual bool requiresAuthenticatedStream() const override { return false; }

                virtual void setParams(std::shared_ptr<ISaslParams> params) override;

                virtual SecureBuffer initiate() override;
                virtual SecureBuffer challenge() override;
                virtual void handleChallenge(const SecureBuffer &response,
                                             ResponseCallback callback) override;
                virtual void handleResponse(const SecureBuffer &response,
                                            ResponseCallback callback) override;
                virtual void handleSuccess(const SecureBuffer &response,
                                           ResponseCallback callback) override;
            private:
                std::shared_ptr<Params> m_params;
                std::string m_serverNonce;
                std::string m_serverSalt;
                SecureBuffer m_challengeData;
                SecureBuffer m_serverSig;
                size_t m_iterations;
        };


        // The following SASL mechanisms are not offered by the current XMPP server but
        // may be implemented as required.
        // ANONYMOUS                    RFC4505
        // EXTERNAL                     RFC4422

        // 9798-M-DSA-SHA1              RFC3164
        // 9798-M-ECDSA-SHA1
        // 9798-M-RSA-SHA1-ENC
        // 9798-U-DSA-SHA1
        // 9798-U-ECDSA-SHA1
        // 9798-U-RSA-SHA1-ENC

        // EAP-AES128                   RFC7055
        // EAP-AES128-PLUS

        // GS2-*                        RFC5801
        // GS2-KRB5
        // GS2-KRB5-PLUS

        // GSSAPI                       RFC4752

        // KERBEROS_V5

        // OPENID20                     RFC6616

        // OTP                          RFC2444

        // SAML20                       RFC6595

        // SCRAM-*                      RFC5802
        // SCRAM-SHA-1-PLUS

        // SECURID                      RFC2808

        // X-OAUTH2                     https://developers.google.com/talk/jep_extensions/oauth
        //
        //<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl"
        //mechanism="X-OAUTH2"
        //auth:service="oauth2"
        //xmlns:auth="http://www.google.com/talk/protocol/auth">
        //base64("\0" + user_name + "\0" + oauth_token)
        //</auth>

        // Unit-TEST only.
        SecureBuffer testSaslPrep(const std::string &saslString, bool testEscape = false);
    }
}
