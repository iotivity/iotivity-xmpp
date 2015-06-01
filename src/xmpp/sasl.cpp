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

/// @file sasl.cpp

#include "stdafx.h"
#include "sasl.h"

#include "../connect/connecterror.h"
#include "../common/logstream.h"
#include "../common/str_helpers.h"

#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <algorithm>


static const size_t NONCE_LENGTH_IN_OCTETS = 16;   // Approx. a uuid_t. Can be increased.
//static const size_t MAX_ITERATION_COUNT =  // Possible DOS mitigation (TBD) Must be at least 4096

using namespace std;

namespace Iotivity
{
    namespace Xmpp
    {
        // Buffer clean up for SASL [RFC4013]

        //B.1 Commonly mapped to nothing
        //----- Start Table B.1 -----
        //00AD; ; Map to nothing
        //034F; ; Map to nothing
        //1806; ; Map to nothing
        //180B; ; Map to nothing
        //180C; ; Map to nothing
        //180D; ; Map to nothing
        //200B; ; Map to nothing
        //200C; ; Map to nothing
        //200D; ; Map to nothing
        //2060; ; Map to nothing
        //FE00; ; Map to nothing
        //FE01; ; Map to nothing
        //FE02; ; Map to nothing
        //FE03; ; Map to nothing
        //FE04; ; Map to nothing
        //FE05; ; Map to nothing
        //FE06; ; Map to nothing
        //FE07; ; Map to nothing
        //FE08; ; Map to nothing
        //FE09; ; Map to nothing
        //FE0A; ; Map to nothing
        //FE0B; ; Map to nothing
        //FE0C; ; Map to nothing
        //FE0D; ; Map to nothing
        //FE0E; ; Map to nothing
        //FE0F; ; Map to nothing
        //FEFF; ; Map to nothing
        //----- End Table B.1 -----
        // Prohibited By Spec.
        // Non-ASCII space characters [StringPrep, C.1.2]
        //----- Start Table C.1.2 -----
        //00A0; NO-BREAK SPACE
        //1680; OGHAM SPACE MARK
        //2000; EN QUAD
        //2001; EM QUAD
        //2002; EN SPACE
        //2003; EM SPACE
        //2004; THREE-PER-EM SPACE
        //2005; FOUR-PER-EM SPACE
        //2006; SIX-PER-EM SPACE
        //2007; FIGURE SPACE
        //2008; PUNCTUATION SPACE
        //2009; THIN SPACE
        //200A; HAIR SPACE
        //200B; ZERO WIDTH SPACE
        //202F; NARROW NO-BREAK SPACE
        //205F; MEDIUM MATHEMATICAL SPACE
        //3000; IDEOGRAPHIC SPACE
        //----- End Table C.1.2 -----
        // ASCII control characters [StringPrep, C.2.1]
        //----- Start Table C.2.1 -----
        //0000-001F; [CONTROL CHARACTERS]
        //007F; DELETE
        //----- End Table C.2.1 -----
        // Non-ASCII control characters [StringPrep, C.2.2]
        //----- Start Table C.2.2 -----
        //0080-009F; [CONTROL CHARACTERS]
        //06DD; ARABIC END OF AYAH
        //070F; SYRIAC ABBREVIATION MARK
        //180E; MONGOLIAN VOWEL SEPARATOR
        //200C; ZERO WIDTH NON-JOINER
        //200D; ZERO WIDTH JOINER
        //2028; LINE SEPARATOR
        //2029; PARAGRAPH SEPARATOR
        //2060; WORD JOINER
        //2061; FUNCTION APPLICATION
        //2062; INVISIBLE TIMES
        //2063; INVISIBLE SEPARATOR
        //206A-206F; [CONTROL CHARACTERS]
        //FEFF; ZERO WIDTH NO-BREAK SPACE
        //FFF9-FFFC; [CONTROL CHARACTERS]
        //1D173-1D17A; [MUSICAL CONTROL CHARACTERS]
        //----- End Table C.2.2 -----
        // Private Use characters [StringPrep, C.3]
        //----- Start Table C.3 -----
        //E000-F8FF; [PRIVATE USE, PLANE 0]
        //F0000-FFFFD; [PRIVATE USE, PLANE 15]
        //100000-10FFFD; [PRIVATE USE, PLANE 16]
        //----- End Table C.3 -----
        // Non-character code points [StringPrep, C.4]
        //----- Start Table C.4 -----
        //FDD0-FDEF; [NONCHARACTER CODE POINTS]
        //FFFE-FFFF; [NONCHARACTER CODE POINTS]
        //1FFFE-1FFFF; [NONCHARACTER CODE POINTS]
        //2FFFE-2FFFF; [NONCHARACTER CODE POINTS]
        //3FFFE-3FFFF; [NONCHARACTER CODE POINTS]
        //4FFFE-4FFFF; [NONCHARACTER CODE POINTS]
        //5FFFE-5FFFF; [NONCHARACTER CODE POINTS]
        //6FFFE-6FFFF; [NONCHARACTER CODE POINTS]
        //7FFFE-7FFFF; [NONCHARACTER CODE POINTS]
        //8FFFE-8FFFF; [NONCHARACTER CODE POINTS]
        //9FFFE-9FFFF; [NONCHARACTER CODE POINTS]
        //AFFFE-AFFFF; [NONCHARACTER CODE POINTS]
        //BFFFE-BFFFF; [NONCHARACTER CODE POINTS]
        //CFFFE-CFFFF; [NONCHARACTER CODE POINTS]
        //DFFFE-DFFFF; [NONCHARACTER CODE POINTS]
        //EFFFE-EFFFF; [NONCHARACTER CODE POINTS]
        //FFFFE-FFFFF; [NONCHARACTER CODE POINTS]
        //10FFFE-10FFFF; [NONCHARACTER CODE POINTS]
        //----- End Table C.4 -----
        // Surrogate code points [StringPrep, C.5]
        //----- Start Table C.5 -----
        //D800-DFFF; [SURROGATE CODES]
        //----- End Table C.5 -----
        // Inappropriate for plain text characters [StringPrep, C.6]
        //----- Start Table C.6 -----
        //FFF9; INTERLINEAR ANNOTATION ANCHOR
        //FFFA; INTERLINEAR ANNOTATION SEPARATOR
        //FFFB; INTERLINEAR ANNOTATION TERMINATOR
        //FFFC; OBJECT REPLACEMENT CHARACTER
        //FFFD; REPLACEMENT CHARACTER
        //----- End Table C.6 -----
        // Inappropriate for canonical representation characters [StringPrep, C.7]
        //----- Start Table C.7 -----
        //2FF0-2FFB; [IDEOGRAPHIC DESCRIPTION CHARACTERS]
        //----- End Table C.7 -----
        // Change display properties or deprecated characters [StringPrep, C.8]
        //----- Start Table C.8 -----
        //0340; COMBINING GRAVE TONE MARK
        //0341; COMBINING ACUTE TONE MARK
        //200E; LEFT-TO-RIGHT MARK
        //200F; RIGHT-TO-LEFT MARK
        //202A; LEFT-TO-RIGHT EMBEDDING
        //202B; RIGHT-TO-LEFT EMBEDDING
        //202C; POP DIRECTIONAL FORMATTING
        //202D; LEFT-TO-RIGHT OVERRIDE
        //202E; RIGHT-TO-LEFT OVERRIDE
        //206A; INHIBIT SYMMETRIC SWAPPING
        //206B; ACTIVATE SYMMETRIC SWAPPING
        //206C; INHIBIT ARABIC FORM SHAPING
        //206D; ACTIVATE ARABIC FORM SHAPING
        //206E; NATIONAL DIGIT SHAPES
        //206F; NOMINAL DIGIT SHAPES
        //----- End Table C.8 -----
        // Tagging characters [StringPrep, C.9]
        //----- Start Table C.9 -----
        //E0001; LANGUAGE TAG
        //E0020-E007F; [TAGGING CHARACTERS]
        //----- End Table C.9 -----
        char32_t charMap(char32_t testChar)
        {
            // Since we have 120000+ code points that are invalid, we'll do this with a conditional
            // to minimize the footprint of the test in lieu of speed. We don't expect user
            // names or passwords to be extremely long strings, although automated passwords
            // may be 'lengthy'. Start with a rough idea of 'valid' so we can avoid most testing
            // for Western character sets. Invalidate ',' to fix issues with SCRAM SASL.
            if (testChar >= 0x0020 && testChar < 0x7F)
            {
                // Printable ASCII. Okay.
                return testChar;
            }
            if ((testChar >= 0x2000 && testChar <= 0x200B) ||
                testChar == 0x00A0 || testChar == 0x1680 || testChar == 0x202F ||
                testChar == 0x205F || testChar == 0x3000)
            {
                return 0x0020;
            }

            if ((/*testChar >= 0x0000 &&*/ testChar <= 0x001F) ||
                (testChar >= 0x0080 && testChar <= 0x009F) ||
                (testChar >= 0x202A && testChar <= 0x202E) ||
                (testChar >= 0x2060 && testChar <= 0x2063) ||
                (testChar >= 0x206A && testChar <= 0x206F) ||
                (testChar >= 0x0080 && testChar <= 0x009F) ||
                (testChar >= 0xFFF9 && testChar <= 0xFFFC) ||
                (testChar >= 0x1D173 && testChar <= 0x1D17A) ||
                (testChar >= 0xE000 && testChar <= 0xF8FF) ||
                (testChar >= 0xF0000 && testChar <= 0xFFFFD) ||
                (testChar >= 0x100000 && testChar <= 0x10FFFD) ||
                (testChar >= 0xFDD0 && testChar <= 0xFDEF) ||
                (testChar >= 0xFFF9 && testChar <= 0xFFFF) ||           // TODO: Replace with mask?
                (testChar >= 0x1FFFE && testChar <= 0x1FFFF) ||
                (testChar >= 0x2FFFE && testChar <= 0x2FFFF) ||
                (testChar >= 0x3FFFE && testChar <= 0x3FFFF) ||
                (testChar >= 0x4FFFE && testChar <= 0x4FFFF) ||
                (testChar >= 0x5FFFE && testChar <= 0x5FFFF) ||
                (testChar >= 0x6FFFE && testChar <= 0x6FFFF) ||
                (testChar >= 0x7FFFE && testChar <= 0x7FFFF) ||
                (testChar >= 0x8FFFE && testChar <= 0x8FFFF) ||
                (testChar >= 0x9FFFE && testChar <= 0x9FFFF) ||
                (testChar >= 0xAFFFE && testChar <= 0xAFFFF) ||
                (testChar >= 0xBFFFE && testChar <= 0xBFFFF) ||
                (testChar >= 0xCFFFE && testChar <= 0xCFFFF) ||
                (testChar >= 0xDFFFE && testChar <= 0xDFFFF) ||
                (testChar >= 0xEFFFE && testChar <= 0xEFFFF) ||
                (testChar >= 0xFFFF9 && testChar <= 0xFFFFF) ||
                (testChar >= 0x10FFFE && testChar <= 0x10FFFF) ||
                (testChar >= 0xD800 && testChar <= 0xDFFF) ||
                (testChar >= 0x2FF0 && testChar <= 0x2FFB) ||
                (testChar >= 0xE0020 && testChar <= 0xE007F) ||
                testChar == 0x007F || testChar == 0x06DD || testChar == 0x070F ||
                testChar == 0x180E || testChar == 0x200C || testChar == 0x200D ||
                testChar == 0x2028 || testChar == 0x2029 || testChar == 0xFEFF ||
                testChar == 0x0340 || testChar == 0x0341 || testChar == 0x200E ||
                testChar == 0x200F || testChar == 0xE0001 || testChar == 0x002C)
            {
                return 0x0;
            }
            return testChar;
        }

        enum class CommaFix
        {
            comma_remove,
            comma_escape,
            comma_equals_escape
        };

        SecureBuffer saslPrep(const SecureBuffer &saslBuf,
                              CommaFix commaFix = CommaFix::comma_remove)
        {
            SecureBuffer sanitizedBuffer;

            const char *nextIn = (const char *)saslBuf.get();
            const char *endCharIn = nextIn + saslBuf.size();

            // NOTE: We are not attempting to validate bidirectional characters here.
            //       There is a chance this could lead to inconsistent results between
            //       this client and another for user names or passwords, but these
            //       subtitutions are intended mainly to avoid injection issues.
            while (nextIn < endCharIn)
            {
                size_t charsConsumed = 0;
                char32_t outChar = str_helper::utf8ToUtf32(nextIn, endCharIn - nextIn,
                                   charsConsumed);

                if (charsConsumed == 0)
                {
                    throw runtime_error("saslPrep utf_8 parse error");
                }

                nextIn += charsConsumed;

                char32_t resultChar = charMap(outChar);
                if (resultChar != 0x00)
                {
                    char outBuf[8] = {0};

                    size_t charsWritten = 0;
                    if (resultChar == 0x2C && (commaFix == CommaFix::comma_escape ||
                                               commaFix == CommaFix::comma_equals_escape))
                    {
                        outBuf[0] = '=';
                        outBuf[1] = '2';
                        outBuf[2] = 'C';
                        charsWritten = 3;
                    }
                    else if (resultChar == 0x3D && (commaFix == CommaFix::comma_equals_escape))
                    {
                        outBuf[0] = '=';
                        outBuf[1] = '3';
                        outBuf[2] = 'D';
                        charsWritten = 3;
                    }
                    else
                    {
                        str_helper::utf32ToUtf8(resultChar, outBuf, sizeof(outBuf) / sizeof(outBuf[0]),
                                                charsWritten);

                        if (charsWritten == 0)
                        {
                            throw runtime_error("saslPrep utf_8 parse error");
                        }
                    }
                    sanitizedBuffer.write(outBuf, charsWritten);
                }
            }
            return sanitizedBuffer;
        }


        SecureBuffer saslPrep(const string &saslString, CommaFix commaFix = CommaFix::comma_remove)
        {
            return saslPrep(SecureBuffer(saslString.c_str(), saslString.size()), commaFix);
        }


        SecureBuffer testSaslPrep(const std::string &saslString, bool testEscape)
        {
            return saslPrep(saslString, testEscape ? CommaFix::comma_equals_escape :
                            CommaFix::comma_remove);
        }


        //////////
        SaslFactory::SaslFactory()
        {
            size_t currentPriority = HIGHEST_BUILT_IN_SASL_PRIORITY;

            // Register the defaults.
            doRegisterSaslMechanism("PLAIN", currentPriority--,
                                    [](const string &)
            {
                return make_shared<SaslPlain>();
            });

            doRegisterSaslMechanism("SCRAM-SHA-1", currentPriority--,
                                    [](const string &)
            {
                return make_shared<SaslScramSha1>();
            });
        }


        list<string> SaslFactory::defaultSaslOrder()
        {

            SaslFactory &f = factory();
            lock_guard<recursive_mutex> lock(f.m_mutex);

            list<string> order;
            for (const auto &i : f.m_priorities)
            {
                order.push_back(i.second);
            }
            return order;
        }

        shared_ptr<ISaslMechanism> SaslFactory::createSaslMechanism(const string &name)
        {
            SaslFactory &f = factory();

            lock_guard<recursive_mutex> lock(f.m_mutex);
            const auto i = f.m_constructors.find(name);
            if (i != f.m_constructors.end() && i->second)
            {
                return i->second(name);
            }
            return shared_ptr<ISaslMechanism>();
        }

        void SaslFactory::registerSaslMechanism(const string &name, size_t priority,
                                                ConstructSaslMechanism constructorFunc)
        {
            SaslFactory &f = factory();
            // NOTE: We are delegating to the member function so that we can use this
            //       behavior from the constructor safely.
            f.doRegisterSaslMechanism(name, priority, constructorFunc);
        }

        void SaslFactory::doRegisterSaslMechanism(const std::string &name, size_t priority,
                ConstructSaslMechanism constructorFunc)
        {
            lock_guard<recursive_mutex> lock(m_mutex);
            m_constructors[name] = constructorFunc;
            m_priorities.insert(Priority::value_type(priority, name));
        }

        list<string> SaslFactory::restrictToKnownMechanisms(const list<string> &mechanisms)
        {
            SaslFactory &f = factory();
            lock_guard<recursive_mutex> lock(f.m_mutex);

            list<string> order;
            copy_if(mechanisms.begin(), mechanisms.end(), back_inserter(order),
                    [&f](const string & name)
            {
                return f.m_constructors.find(name) != f.m_constructors.end();
            });

            return order;
        }

        string SaslFactory::selectMechanism(const list<string> &clientMechanisms,
                                            const list<string> &serverMechanisms)
        {
            string mechanism;
            for (const auto &i : clientMechanisms)
            {
                if (find(serverMechanisms.begin(), serverMechanisms.end(), i) !=
                    serverMechanisms.end())
                {
                    mechanism = i;
                    break;
                }
            }
            return mechanism;
        }


        // NOTE: We are not immediately concerned about thread-safety here since the
        //       initial mechanism registration is intended to run on the main thread.
        //       If this changes, this may need to be revisited.
        SaslFactory &SaslFactory::factory()
        {
            static SaslFactory f;
            return f;
        }


        //////////
        shared_ptr<SaslPlain::Params> SaslPlain::Params::create(
            const std::string &authenticationIdentity, const SecureBuffer &password)
        {
            return shared_ptr<Params>(new Params(authenticationIdentity, password));
        }

        void SaslPlain::setParams(shared_ptr<ISaslParams> params)
        {
            if (params && params->supportsMechanism("PLAIN"))
            {
                m_params = static_pointer_cast<Params>(params);
            }
            else
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
        }

        SecureBuffer SaslPlain::initiate()
        {
            SecureBuffer authData;

            if (m_params)
            {
                authData.write(saslPrep(m_params->authorizationIdentity()));
            }
            authData.write("", 1);
            if (m_params)
            {
                authData.write(saslPrep(m_params->authenticationIdentity()));
            }
            authData.write("", 1);
            if (m_params)
            {
                authData.write(saslPrep(m_params->password()));
            }
            return authData;
        }

        SecureBuffer SaslPlain::challenge()
        {
            SecureBuffer challengeData;
            return challengeData;
        }

        void SaslPlain::handleChallenge(const SecureBuffer &, ResponseCallback callback)
        {
            callback(SaslResult(SaslResult::Failure), SecureBuffer());
        }

        void SaslPlain::handleResponse(const SecureBuffer &, ResponseCallback callback)
        {
            callback(SaslResult(SaslResult::Failure), challenge());
        }

        void SaslPlain::handleSuccess(const SecureBuffer &, ResponseCallback callback)
        {
            callback(SaslResult(SaslResult::Success), SecureBuffer());
        }



        //////////
        shared_ptr<SaslScramSha1::Params> SaslScramSha1::Params::create(
            const std::string &authenticationIdentity, const SecureBuffer &password)
        {
            return shared_ptr<Params>(new Params(authenticationIdentity, password));
        }

        void SaslScramSha1::setParams(shared_ptr<ISaslParams> params)
        {
            if (params && params->supportsMechanism("SCRAM-SHA-1"))
            {
                m_params = static_pointer_cast<Params>(params);
            }
            else
            {
                throw connect_error(LocalError(LocalError::ecInvalidParameter));
            }
        }

        SecureBuffer SaslScramSha1::initiate()
        {
            // If this is updated, also update the c= parameter of the first response
            static const char s_channelBindingSupported[] = "n";
            SecureBuffer challengeData;

            // Channel binding support (RFC5801):
            // n - no support
            // y - supports, does not require server to
            // p - supports, requires server to
            challengeData.write(s_channelBindingSupported, sizeof(s_channelBindingSupported) - 1);

            // If this is updated, also update the c= parameter of the first response
            challengeData.write(",,", 2);
            size_t barePos = challengeData.position();
            challengeData.write("n=", 2);
            if (m_params)
            {
                challengeData.write(saslPrep(m_params->authenticationIdentity(),
                                             CommaFix::comma_equals_escape));
            }
            challengeData.write(",r=", 3);
            RandomBuffer initialNonce(NONCE_LENGTH_IN_OCTETS);
            SecureBuffer nonceAsStr;
            if (!initialNonce.base64Encode(nonceAsStr))
            {
                throw connect_error(connect_error::ecErrorEncodingNonce);
            }
            challengeData.write(nonceAsStr);
            m_challengeData.setBuffer(&challengeData[barePos], challengeData.size() - barePos);

            return challengeData;
        }

        SecureBuffer SaslScramSha1::challenge()
        {
            return SecureBuffer();
        }

        SecureBuffer HMAC_SHA1(const SecureBuffer &key, const SecureBuffer &message)
        {
            SecureBuffer hmac(SHA_DIGEST_LENGTH);
            auto digestLength = static_cast<unsigned int>(hmac.size());

            HMAC(EVP_sha1(), key, static_cast<int>(key.size()), message, message.size(),
                 &hmac[0], &digestLength);

            return hmac;
        }


        SecureBuffer SHA1(const SecureBuffer &src)
        {
            SecureBuffer sha(SHA_DIGEST_LENGTH);
            SHA_CTX ctx = {0};
            SHA1_Init(&ctx);
            SHA1_Update(&ctx, src, src.size());
            SHA1_Final(&sha[0], &ctx);
            return sha;
        }

        SecureBuffer HMACIterated(const SecureBuffer &pass, const SecureBuffer &salt,
                                  size_t iterations)
        {
            SecureBuffer hi, u;
            SecureBuffer saltExtended;
            saltExtended.write(salt);
            saltExtended.write("\x0\x0\x0\x1", 4);

            u = HMAC_SHA1(pass, saltExtended);
            hi = u;

            for (size_t i = 1; i < iterations; ++i)
            {
                u = HMAC_SHA1(pass, u);
                hi.xorWith(u);
            }
            return hi;
        }

        SecureBuffer computeProof(const SecureBuffer &pass, const SecureBuffer &salt,
                                  size_t iterations, const SecureBuffer &clientMessageBare,
                                  const SecureBuffer &serverMessageBare,
                                  const SecureBuffer &clientFinalMessageBare,
                                  SecureBuffer &serverSig)
        {

            static const SecureBuffer CLIENT_KEY_STR("Client Key", 10);
            static const SecureBuffer SERVER_KEY_STR("Server Key", 10);
            auto saltedPassword = HMACIterated(saslPrep(pass), salt, iterations);

            auto clientKey = HMAC_SHA1(saltedPassword, CLIENT_KEY_STR);
            auto serverKey = HMAC_SHA1(saltedPassword, SERVER_KEY_STR);

            SecureBuffer authMessage;
            authMessage.write(clientMessageBare);
            authMessage.write(",", 1);
            authMessage.write(serverMessageBare);
            authMessage.write(",", 1);
            authMessage.write(clientFinalMessageBare);

            SecureBuffer storedKey = SHA1(clientKey);
            auto clientSignature = HMAC_SHA1(storedKey, authMessage);
            serverSig = HMAC_SHA1(serverKey, authMessage);

            clientKey.xorWith(clientSignature);
            return clientKey;
        }

        void SaslScramSha1::handleChallenge(const SecureBuffer &buf,
                                            ResponseCallback callback)
        {
            string bufAsStr((const char *)buf.get(), buf.size());
            auto segments = str_helper::split(bufAsStr, ',');
            for (const auto &i : segments)
            {
                if (i.size() < 2)
                {
                    callback(SaslResult(SaslResult::Abort), SecureBuffer());
                    return;
                }
                char key = i[0];
                char delim = i[1];
                string val = i.substr(2);
                if (delim != '=')
                {
                    callback(SaslResult(SaslResult::Abort), SecureBuffer());
                    return;
                }

                switch (key)
                {
                    case 'r':
                        m_serverNonce = val;
                        break;
                    case 's':
                        m_serverSalt = val;
                        break;
                    case 'i':
                        m_iterations = strtoull(val.c_str(), nullptr, 10);
                        break;
                }
            }

            if (m_iterations == 0 || m_serverNonce.size() == 0 || m_serverSalt.size() == 0)
            {
                callback(SaslResult(SaslResult::Abort), SecureBuffer());
                return;
            }

            SecureBuffer responseData;

            responseData.write("c=biws", 6);    // 'biws'==base64Encode('n,,')
            responseData.write(",r=", 3);
            responseData.write(m_serverNonce.c_str(), m_serverNonce.size());

            if (m_params)
            {
                SecureBuffer serverSalt(m_serverSalt), decodedServerSalt;
                serverSalt.base64Decode(decodedServerSalt);
                SecureBuffer proof = computeProof(m_params->password(), decodedServerSalt,
                                                  m_iterations, m_challengeData, buf,
                                                  responseData, m_serverSig);
                SecureBuffer proofEncoded;
                proof.base64Encode(proofEncoded);

                responseData.write(",p=", 3);
                responseData.write(proofEncoded);
            }

            callback(SaslResult(SaslResult::Response), responseData);
        }

        void SaslScramSha1::handleResponse(const SecureBuffer &,
                                           ResponseCallback callback)
        {
            callback(SaslResult(SaslResult::Abort), SecureBuffer());
        }

        void SaslScramSha1::handleSuccess(const SecureBuffer &buf, ResponseCallback callback)
        {
            bool validated = false;
            SecureBuffer serverSigBase64;
            m_serverSig.base64Encode(serverSigBase64);

            string bufAsStr((const char *)buf.get(), buf.size());
            auto segments = str_helper::split(bufAsStr, ',');
            for (const auto &i : segments)
            {
                if (i.size() < 2)
                {
                    callback(SaslResult(SaslResult::Abort), SecureBuffer());
                    return;
                }
                char key = i[0];
                char delim = i[1];
                string val = i.substr(2);
                if (delim != '=')
                {
                    callback(SaslResult(SaslResult::Abort), SecureBuffer());
                    return;
                }

                if (key == 'v')
                {
                    string serverSigStr((const char *)serverSigBase64.get(),
                                        serverSigBase64.size());
                    validated = val == serverSigStr;
                }
            }

            if (validated)
            {
                callback(SaslResult(SaslResult::Success), SecureBuffer());
            }
            else
            {
                WITH_LOG_ERRORS
                (
                    dout << "Server failed to validate with correct server signature." <<
                    endl;
                )
                callback(SaslResult(SaslResult::Abort), SecureBuffer());
            }
        }
    }
}
