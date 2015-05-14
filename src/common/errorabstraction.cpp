//******************************************************************
//
// Copyright 2007-2014 Intel Mobile Communications GmbH All Rights Reserved.
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
//******************************************************************
// File name:
//     errorabstraction.cpp
//
// Description:
//     Implementation for IoTivity abstract error-handling base classes.
//
//
//
//*********************************************************************


#include "stdafx.h"

#include "errorabstraction.h"
#include "compatibility.h"
#include <sstream>

#ifndef __KLOCWORK__
# include "banned.h"
#endif

using namespace std;


namespace Iotivity
{

    //////////
    // AbstractErrorCondition
    //
    AbstractErrorCondition::~AbstractErrorCondition()
    {}

    bool AbstractErrorCondition::operator==(const AbstractErrorCondition &error) const
    {
        return errorCode() == error.errorCode();
    }


    //////////
    // LocalError
    //
    const LocalError LocalError::SUCCESS(LocalError::ecSuccess);

    /// The value of the last error-type code returned by getNextAvailableErrorType()
    static LocalError::ErrorType s_nextErrorType = LocalError::etMaxInternalErrorType;

    /// Synchronization object to protect access to s_nextErrorType
    static recursive_mutex s_nextErrorLock;

    /// Collection of error-code to name mappings.
    typedef std::map<LocalError::ErrorType, std::string> TypeNameMap;
    static TypeNameMap s_typeNames;

    LocalError::LocalError():
        m_errorType(etUnknownError),
        m_errorCode(0)
    {
    }

    LocalError::LocalError(const LocalError &error):
        m_errorType(error.m_errorType),
        m_errorCode(error.m_errorCode)
    {
        // If the incoming error is a success, but it didn't down-convert into
        // a success in this error condition object, then we need to cast it to
        // a LocalError success.
        if (error.succeeded() && !succeeded())
        {
            m_errorType = etLocalError;
            m_errorCode = ecSuccess;
        }
    }

    LocalError::LocalError(LocalError &&error)
    {
        m_errorType = std::move(error.m_errorType);
        m_errorCode = std::move(error.m_errorCode);

        // If the incoming error is a success, but it didn't down-convert into
        // a success in this error condition object, then we need to cast it to
        // a LocalError success.
        if (error.succeeded() && !succeeded())
        {
            m_errorType = etLocalError;
            m_errorCode = ecSuccess;
        }
    }

    LocalError::LocalError(LocalErrorCode errorCode):
        m_errorType(etLocalError),
        m_errorCode(errorCode)
    {
    }

    LocalError::LocalError(ECODE errorCode, ErrorType errorType):
        m_errorType(errorType),
        m_errorCode(errorCode)
    {
    }

    AbstractErrorCondition *LocalError::clone() const
    {
        return new LocalError(m_errorCode, m_errorType);
    }

    bool LocalError::operator==(const LocalError &error) const
    {
        return m_errorType == error.m_errorType && m_errorCode == error.m_errorCode;
    }

    bool LocalError::succeeded() const
    {
        // Note that a HRESULT of S_FALSE is still a succeeded condition
        return   (m_errorType == etLocalError   && m_errorCode == ecSuccess)      ||
                 (m_errorType == etHRESULT      && SUCCEEDED(m_errorCode))      ||
                 (m_errorType == etWindowsError && m_errorCode == ERROR_SUCCESS) ||
                 (m_errorType == etUNIXError    && m_errorCode == 0);
    }

    LocalError &LocalError::operator=(const LocalError &error)
    {
        m_errorType = error.m_errorType;
        m_errorCode = error.m_errorCode;

        // If the incoming error is a success, but it didn't down-convert into
        // a success in this error condition object, then we need to cast it to
        // a LocalError success.
        if (error.succeeded() && !succeeded())
        {
            m_errorType = etLocalError;
            m_errorCode = ecSuccess;
        }
        return *this;
    }

    LocalError &LocalError::operator=(LocalErrorCode errorCode)
    {
        m_errorType = etLocalError;
        m_errorCode = errorCode;
        return *this;
    }

    LocalError &LocalError::operator=(ECODE errorCode)
    {
        m_errorType = etHRESULT;
        m_errorCode = errorCode;
        return *this;
    }

    string LocalError::toString() const
    {
        ostringstream os;
        os << errorTypeName(m_errorType) << "::";
        if (succeeded())
        {
            os << "SUCCESS";
        }
        else
        {
            if (m_errorType == etHRESULT)
            {
                os << "0x";
                os << hex << m_errorCode;
            }
            else
            {
                os << m_errorCode;
            }
        }
        return os.str();
    }

    LocalError LocalError::getLastError()
    {
#if defined(_WIN32)
        return LocalError(::GetLastError(), etWindowsError);
#else
        return LocalError(errno, etUNIXError);
#endif
    }

    std::string LocalError::errorTypeName(ErrorType forType)
    {
        std::string errorName("<UNKNOWN>");
        lock_guard<recursive_mutex> lock(s_nextErrorLock);
        TypeNameMap::const_iterator f;
        switch (forType)
        {
            case etWindowsError:
                errorName = "<WIN32>";
                break;
            case etHRESULT:
                errorName = "<HRESULT>";
                break;
            case etLocalError:
                errorName = "<LocalError>";
                break;
            case etUNIXError:
                errorName = "<UNIX>";
                break;
            default:
                f = s_typeNames.find(forType);
                if (f != s_typeNames.end())
                {
                    errorName = f->second;
                }
                break;
        }
        return errorName;
    }

    LocalError::ErrorType LocalError::getNextAvailableErrorType(const std::string &typeName)
    {
        lock_guard<recursive_mutex> lock(s_nextErrorLock);
        LocalError::ErrorType nextErrorType = getNextAvailableErrorType();
        s_typeNames[nextErrorType] = typeName;
        return nextErrorType;
    }

    LocalError::ErrorType LocalError::getNextAvailableErrorType()
    {
        lock_guard<recursive_mutex> lock(s_nextErrorLock);
        s_nextErrorType = (ErrorType)(s_nextErrorType + 1);
        return s_nextErrorType;
    }
} // namespace Iotivity
