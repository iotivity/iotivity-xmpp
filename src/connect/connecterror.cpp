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

/// @file connecterror.cpp

#include "stdafx.h"

#include "connecterror.h"
#include <curl/curl.h>
#include <string>
#include <sstream>

using namespace std;

namespace Iotivity
{
    namespace Xmpp
    {
        LocalError::ErrorType connect_error::s_etConnectError = LocalError::etUnknownError;
        LocalError::ErrorType connect_error::s_etCurlError = LocalError::etUnknownError;
        LocalError::ErrorType connect_error::s_etHttpError = LocalError::etUnknownError;
        LocalError::ErrorType connect_error::s_etSOCKS5Error = LocalError::etUnknownError;
        LocalError::ErrorType connect_error::s_etASIOError = LocalError::etUnknownError;

        connect_error::connect_error(): m_httpSubCode(0) {}

        connect_error::connect_error(const LocalError &error) :
            LocalError(error),
            m_httpSubCode(0)
        {}

        connect_error::connect_error(const connect_error &error) :
            LocalError(error),
            m_httpSubCode(error.m_httpSubCode)
        {}

        connect_error::connect_error(ConnectErrorCode errorCode) :
            LocalError(errorCode, etConnectError()),
            m_httpSubCode(0)
        {}

        connect_error::connect_error(int httpCode, int httpSubCode) :
            LocalError((ECODE)httpCode, etHttpError()),
            m_httpSubCode(httpSubCode)
        {}

        connect_error::connect_error(ECODE errorCode, ErrorType errorType) :
            LocalError(errorCode, errorType),
            m_httpSubCode(0)
        {}

#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
        connect_error::connect_error(const asio::error_code &ec):
            LocalError((ECODE)ec.value(), etASIOError()),
            m_asioError(ec)
        {}
#endif

        int connect_error::httpStatusCode() const
        {
            return errorType() == etHttpError() ? (int)errorCode() : 0;
        }

        int connect_error::httpStatusSubCode() const
        {
            return errorType() == etHttpError() ? m_httpSubCode : 0;
        }

        bool connect_error::operator==(ConnectErrorCode error) const
        {
            return errorType() == etConnectError() && errorCode() == error;
        }

        bool connect_error::operator==(const connect_error &error) const
        {
            return LocalError::operator==(error) &&
#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
                   (errorType() == etASIOError() ? m_asioError == error.m_asioError : true) &&
#endif
                   (errorType() == etHttpError() ? m_httpSubCode == error.m_httpSubCode : true);
        }

        bool connect_error::succeeded() const
        {
            return LocalError::succeeded() ||
                   (errorType() == etCurlError() && errorCode() == CURLE_OK) ||
                   (errorType() == etHttpError() && errorCode() >= 200 && errorCode() < 300) ||
#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
                   (errorType() == etASIOError() && !m_asioError) ||
                   (errorType() == etSOCKS5Error() && errorCode() == 0x00) ||
#endif
                   (errorType() == etConnectError() && (errorCode() == ecSuccess));
        }

        connect_error &connect_error::operator=(ConnectErrorCode errorCode)
        {
            setErrorCode(errorCode);
            setErrorType(etConnectError());
            return *this;
        }

        string connect_error::toString() const
        {
            ostringstream os;
            if (errorType() == etHttpError())
            {
                os << errorTypeName(errorType());
                os << "::";
                os << errorCode();
                os << "/";
                os << m_httpSubCode;
                //os<< "(";
                //os<< HTTPResult(Failed, (HTTPStatus)errorCode(), (HTTPStatus)m_httpSubCode).getText();
                //os<< ")";
                return os.str();
            }
#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
            else if (errorType() == etASIOError())
            {
                os << errorTypeName(errorType());
                os << "::" << m_asioError;
                return os.str();
            }
#endif
            else
            {
                return LocalError::toString();
            }
        }

        LocalError::ErrorType connect_error::etConnectError()
        {
            if (s_etConnectError == LocalError::etUnknownError)
            {
                s_etConnectError = LocalError::getNextAvailableErrorType("<connect_error>");
            }
            return s_etConnectError;
        }

        LocalError::ErrorType connect_error::etCurlError()
        {
            if (s_etCurlError == LocalError::etUnknownError)
            {
                s_etCurlError = LocalError::getNextAvailableErrorType("<CurlError>");
            }
            return s_etCurlError;
        }

        LocalError::ErrorType connect_error::etHttpError()
        {
            if (s_etHttpError == LocalError::etUnknownError)
            {
                s_etHttpError = LocalError::getNextAvailableErrorType("<HttpError>");
            }
            return s_etHttpError;
        }

        LocalError::ErrorType connect_error::etSOCKS5Error()
        {
            if (s_etSOCKS5Error == LocalError::etUnknownError)
            {
                s_etSOCKS5Error = LocalError::getNextAvailableErrorType("<SOCKS5Error>");
            }
            return s_etSOCKS5Error;
        }

        LocalError::ErrorType connect_error::etASIOError()
        {
            if (s_etASIOError == LocalError::etUnknownError)
            {
                s_etASIOError = LocalError::getNextAvailableErrorType("<ASIOError>");
            }
            return s_etASIOError;
        }
    }
}
