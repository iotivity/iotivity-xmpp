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
//     errorabstraction.h
//
// Description:
//     Header for IoTivity abstract error-handling base classes.
//
//
//
//*********************************************************************


#ifndef __ERRORABSTRACTION_H__
#define __ERRORABSTRACTION_H__

#include <mutex>
#include <deque>
#include <map>

#include "../include/ccfxmpp.h"

namespace Iotivity
{

    /// Error code (signed) used by Abstract Error Conditions
    typedef long ECODE;

    /// \brief Abstraction of an error condition to a success/failure
    ///        indication.
    ///
    /// An AbstractErrorCondition is a very basic notion of an error which
    /// results (eventually) in a simple condition of success or failure.
    /// Higher-level errors can be derived from this error condition which
    /// make use of more complex attributes to retain information about
    /// what error occurred or when it occurred.
    class XMPP_API AbstractErrorCondition
    {
        public:
            /// Destructor for more complex error conditions requiring memory
            /// allocation/deallocation.
            virtual ~AbstractErrorCondition();

            /// Comparison of error conditions is a required operation. By default
            /// a comparison is made using the errorCode property. Derived
            /// error conditions which include more data shouldn't rely on
            /// the default equality operator.
            /// \param error The AbstractionErrorCondition to compare with this
            ///              error condition.
            /// \return true if this error is equivalent to the passed-in error
            virtual bool operator==(const AbstractErrorCondition &error) const;

            /// The default inequality operator.
            /// \param error The AbstractionErrorCondition to compare with this
            ///              error condition.
            /// \return true if this error is not equivalent to the passed-in error
            bool operator!=(const AbstractErrorCondition &error) const
            { return !(operator==(error)); }

            /// Constructs a copy of this AbstractErrorCondition on the heap.
            /// This function is a required override for derived classes so that
            /// ChainedErrorCondition (and similar classes) can retain a collection
            /// of abstract error conditions and not have problems with the lifespan of
            /// those instances.
            /// \return An AbstractErrorCondition instance identical to this one.
            virtual AbstractErrorCondition *clone() const = 0;

            /// An error condition must be condensed to an error code. It is
            /// possible that certain derived instances may not be completely
            /// defined by this code, but the mapping from the error condition
            /// to this code must be a function (i.e. for an error condition
            /// A and an error condition B (of the same type),
            /// if A.errorCode()!=B.errorCode then A!=B)
            /// \return An ECODE representation of this error condition.
            virtual ECODE errorCode() const = 0;

            /// Returns true if this error condition indicates success. This
            /// must be interpreted differently for each derived error condition
            /// class.
            /// \return true if this error condition may be considered a success
            ///         code (in whatever interpretation is appropriate), false
            ///         otherwise. More subtle interpretations are
            virtual bool succeeded() const = 0;

            /// Returns a string representation (presumably interpretable by the user
            /// which represents the state of this abstract error condition).
            virtual std::string toString() const = 0;
    };


    /// \brief LocalError is a generic error class which stores multiple types of
    /// errors from different sources and converts them into a common notion of
    /// success/failure.
    ///
    /// A LocalError supports a single error condition code,
    /// but it also maintains information about the source of the error condition
    /// which can be used by external code to interpret the error in greater detail.
    /// LocalError can currently by sourced by three error types: Win32 error
    /// codes, COM interface HRESULTS and internal and intermediate layer errors.
    /// Error types derived from LocalError should extend it to include their own
    /// error-class handlers.
    /// \note When extending LocalError, be extremely cautious about adding
    ///       additional member variables. Many sections of code need to be
    ///       able to downconvert to the base LocalError which may result in
    ///       loss of information.
    class XMPP_API LocalError : public AbstractErrorCondition
    {
        public:
            /// The error type of a LocalError. The source of the error will
            /// determine the error type, which is used to determined the meaning
            /// of a given error code.
            enum ErrorType
            {
                etUnknownError,      ///< Error code unknown (usually the default error type)
                etWindowsError,      ///< Error code is a Win32 error code
                etHRESULT,           ///< Error code is an HRESULT
                etLocalError,        ///< Error code is from the base instance of the error class
                etUNIXError,
                // Add new basic error-code types here or above (if any are required). Errors
                // derived from LocalError should make use of getNextAvailableErrorType() rather
                // than modifying this ErrorType list.

                etMaxInternalErrorType  ///< The largest error type used by LocalError.
                ///< Extended errors will use higher-value error types
                ///< (see getNextAvailableErrorType())
            };

            /// The set of standard error codes which may be returned by a generic error instance,
            /// not including any extended errors which are of a type added by a derived instance
            /// of LocalError. This should only be extended with base-class-specific error
            /// codes.
            enum LocalErrorCode
            {
                ecSuccess          = 0,     ///< No Error
                ecInvalidParameter = 1,     ///< Invalid parameter passed to function (or out-of-range)
                ecNotImplemented   = 2,     ///< Function behavior not implemented
                ecOutOfMemory      = 3,     ///< General insufficient available heap error.
            };

        public:
            /// Construct a LocalError with the type etUnknownError and the error code 0.
            /// The default LocalError should never return true from a call to success().
            LocalError();
            /// Copy constructor.
            LocalError(const LocalError &error);
            /// Move constructor
            LocalError(LocalError &&error);
            /// Construct a LocalError from a LocalErrorCode.
            /// \param errorCode The error code to initialize the LocalError with. The error
            ///        type will be set to etLocalError automatically.
            LocalError(LocalErrorCode errorCode);
            /// Construct a LocalError from its error code and (optionally) its error
            /// type.
            /// \param errorCode The errorCode to assign to this LocalError. The
            ///        interpretation of the error code is dependent on the errorType
            /// \param errorType The type of error represented by errorCode. By default
            ///        the errorCode is a Bluetooth stack error
            LocalError(ECODE errorCode, ErrorType errorType = etHRESULT);

            /// A statically accessible alias for success.
            static const LocalError SUCCESS;


            /// Creates a copy of this LocalError on the heap (for use by extended error
            /// collection classes in ErrorAbstraction.h
            virtual AbstractErrorCondition *clone() const;
            /// Equality comparision on LocalError
            /// \param error The LocalError to compare with this instance.
            /// \return true if this LocalError instance is precisely equivalent to
            ///         error
            virtual bool operator==(const LocalError &error) const;
            virtual bool operator!=(const LocalError &error) const { return !(operator==(error)); }

            /// Returns true if this error code represents success (i.e. no error condition).
            /// Various different error representations are mapped differently into success codes,
            /// however succeeded generally means what one would expect it to for a given error type.
            /// \return true if this LocalError represents success, false otherwise
            virtual bool succeeded() const;
            /// Accessor for the error type of this LocalError
            /// \return The ErrorType of this LocalError
            ErrorType errorType() const
            {
                return m_errorType;
            }

            /// Returns the registered name of a given error type (if any).
            static std::string errorTypeName(ErrorType forType);

            /// Accessor for the error code of this LocalError. The interpretation of this
            /// value is dependent on the value of errorType().
            /// \return The error code of the LocalError.
            ECODE errorCode() const
            {
                return m_errorCode;
            }

            /// Copy assignment operator.
            /// \return Reference to this LocalError.
            LocalError &operator=(const LocalError &error);
            /// Assigns a LocalErrorCode error code value to this LocalError. The
            /// value of errorType will be assigned etLocalError.
            /// \param errorCode LocalErrorCode to assign to this LocalError
            /// \return Reference to this LocalError.
            LocalError &operator=(LocalErrorCode errorCode);
            /// Assigns a Bluetooth stack error code to this LocalError. The value
            /// of errorType will be assigned etStackError.
            /// \return Reference to this LocalError.
            LocalError &operator=(ECODE errorCode);

            /// Returns a string indicating a very basic numeric representation of
            /// the error condition that occurred (or success)
            virtual std::string toString() const;

            /// Gets the Windows GetLastError() error value as a LocalError error
            /// instance.
            /// \return A new instance of LocalError containing the result of
            ///         a call to GetLastError()
            static LocalError getLastError();

        protected:
            /// Error classes extending LocalError should make use of this
            /// static function to reserve a new error type. This function is thread-safe
            /// so it may be used to allocate new error types. Note that this method of
            /// error-code allocation does mean that the error type may not be consistent
            /// between code runs if error type classes are initialized in difffering orders
            /// this <b>must</b> be taken into account when interpreting error conditions.
            /// Assigns an error type name for displaying the error code's interpretation.
            static ErrorType getNextAvailableErrorType(const std::string &typeName);

            /// Error classes extending LocalError should make use of this
            /// static function to reserve a new error type. This function is thread-safe
            /// so it may be used to allocate new error types. Note that this method of
            /// error-code allocation does mean that the error type may not be consistent
            /// between code runs if error type classes are initialized in difffering orders
            /// this <b>must</b> be taken into account when interpreting error conditions.
            static ErrorType getNextAvailableErrorType();

            /// Assigns an ErrorType value to this LocalError instance. This is mainly
            /// for use by derived error instances.
            /// \param type The error type to assign to this error instance.
            void setErrorType(ErrorType type)
            {
                m_errorType = type;
            }

            /// Assigns an error code value to this LocalError instance. This is mainly
            /// for use by derived error instances.
            /// \param errorCode The error code to assign to this error instance.
            void setErrorCode(ECODE errorCode)
            {
                m_errorCode = errorCode;
            }

        private:
            /// The error type of this LocalError instance
            ErrorType m_errorType;
            /// The error code of this LocalError instance as interpreted by the
            /// current m_errorType.
            ECODE m_errorCode;
    };
} // namespace Iotivity

#endif // __ERRORABSTRACTION_H__
