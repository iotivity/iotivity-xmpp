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

/// @file connecterror.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "../common/errorabstraction.h"

#include "../include/ccfxmpp.h"

#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
#include <asio/error_code.hpp>
#endif


#ifdef _WIN32
class XMPP_API std::error_code;
#endif

namespace Iotivity
{
    namespace Xmpp
    {
        /// @brief The error code class for errors resulting from asio, HTTP or XMPP connection
        ///        errors. Aggregates these error types into a single success/failure composite.
        class XMPP_API connect_error : public LocalError
        {
            public:
                enum ConnectErrorCode : int32_t
                {
                    ecSuccess = 0,
                    ecTLSNegotiationInProgress = -100,
                    ecServerClosedStream = -101,

                    ecNotSupported      = -1000, ///< Operation not supported (generally by connection)
                    ecXMLParserError    = -1001, ///< Invalid or malformed XML body payload
                    ecUnknownSID        = -1002, ///< SID on BOSH message response invalid or unknown
                    ecSIDReused         = -1003, ///< Attempt to start a new session with an active SID
                    ecWaitMissing       = -1004,
                    ecRequestsMissing   = -1005,
                    ecUnableToStartSession = -1006,
                    ecInvalidStream     = -1007,
                    ecHostNameTooLongForSOCKS5 = -1008,
                    ecInvalidPort = -1009,
                    ecUnknownSOCKS5AddressType = -1010,
                    ecUserNameTooLongForSOCKS5 = -1011,
                    ecPasswordTooLongForSOCKS5 = -1012,
                    ecSOCKS5InvalidUserNameOrPassword = -1013,
                    ecProxyTypeNotSupported = -1014,
                    ecTlsNegotationFailure = -1015,
                    ecSaslNegotationFailure = -1016,
                    ecSaslNegotationAborted = -1017,
                    ecNoSaslMechanism = -1018,
                    ecInsecureSaslOverInsecureStream = -1019,
                    ecSocketClosed = -1020,
                    ecRegistrationAlreadyRunning = -1021,
                    ecQueryIDAlreadySubmitted = -1022,
                    ecRequestFailed = -1023,
                    ecStreamInShutdown = -1024,
                    ecExtensionInShutdown = -1025,
                    ecInvalidRegistration = -1026,
                    ecUnableToBindUser = -1027,
                    ecSocketConnectError = -1028,           // Socket error. Not differentiated.
                    ecStanzaTranslationError = -1029,       // Conversion to non-standard stanza
                    // format failed.
                    ecStanzaTooLong = -1030,
                    ecStreamResourceNotBound = -1031,
                    ecAttemptToRestartBoundStream = -1032,
                    ecErrorEncodingNonce = -1033,
                    ecInvalidMessage = -1034

                };

            public:
                connect_error();
                connect_error(const LocalError &error);
                connect_error(const connect_error &error);
                connect_error(ConnectErrorCode errorCode);
                connect_error(int httpStatusCode, int httpStatusSubCode);
                connect_error(ECODE errorCode, ErrorType errorType);
#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
                connect_error(const asio::error_code &errorCode);
#endif
                //CloudError(const HTTPResult &httpResult);

                int httpStatusCode() const;
                int httpStatusSubCode() const;

#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
                asio::error_code ASIOError() const { return m_asioError; }
#endif

                bool operator==(ConnectErrorCode errorCode) const;
                bool operator!=(ConnectErrorCode errorCode) const
                { return !(operator==(errorCode)); }

                bool operator==(const connect_error &error) const;
                bool operator!=(const connect_error &error) const
                { return !connect_error::operator==(error); }

                /// Returns true if this error code represents success (i.e. no error condition).
                virtual bool succeeded() const override;

                connect_error &operator=(ConnectErrorCode errorCode);

                virtual std::string toString() const override;

                static ErrorType etConnectError();
                static ErrorType etCurlError();
                static ErrorType etHttpError();
                static ErrorType etSOCKS5Error();
                static ErrorType etASIOError();

            private:
                static ErrorType s_etConnectError; ///< Error code comes directly from ConnectErrorCode
                static ErrorType s_etCurlError; ///< Error code comes directly from CURL
                static ErrorType s_etHttpError; ///< Error code comes from HTTP response
                static ErrorType s_etSOCKS5Error; ///< Error code comes from SOCKS5 proxy
                static ErrorType s_etASIOError; ///< Error code comes from asio library

                // For etHttpError
                int m_httpSubCode;

#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
                // For etASIOError
                asio::error_code m_asioError;
#endif
        };


    }
}