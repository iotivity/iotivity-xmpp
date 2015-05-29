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

/// @file logstream.h

#pragma once

#include <stdint.h>

#include <ostream>
#include <functional>
#include <stack>


/// @def LOGSTREAM_INCLUDE_THREAD
/// Include thread ID on each log line
#define LOGSTREAM_INCLUDE_THREAD
//#undef LOGSTREAM_INCLUDE_THREAD

/// @def LOGSTREAM_INCLUDE_TIME
/// Include time stamp (ticks) on each log line
#define LOGSTREAM_INCLUDE_TIME
#undef LOGSTREAM_INCLUDE_TIME

/// @def LOGSTREAM_INCLUDE_FILE
/// Include file name on each log line [requires the dout macro]
#define LOGSTREAM_INCLUDE_FILE
#undef LOGSTREAM_INCLUDE_FILE

/// @def LOGSTREAM_INCLUDE_LINE
/// Include line number on each log line [requires the dout macro]
#define LOGSTREAM_INCLUDE_LINE
#undef LOGSTREAM_INCLUDE_LINE

#ifdef LOGSTREAM_ENABLE_DEFAULT_LOGGING
#define LOGSTREAM_ENABLE_LOGGING
#define LOGSTREAM_ENABLE_INFO
#define LOGSTREAM_ENABLE_WARNINGS
#define LOGSTREAM_ENABLE_ERRORS
#define LOGSTREAM_ENABLE_CRITICALS
#endif

#ifdef LOGSTREAM_ENABLE_DATA_LOGGING
#define LOGSTREAM_ENABLE_LOGGING
#define LOGSTREAM_ENABLE_READS
#define LOGSTREAM_ENABLE_WRITES
#define LOGSTREAM_ENABLE_ERRORS
#define LOGSTREAM_ENABLE_CRITICALS
#endif

#ifdef LOGSTREAM_ENABLE_ERROR_LOGGING
#define LOGSTREAM_ENABLE_ERRORS
#define LOGSTREAM_ENABLE_CRITICALS
#endif

#ifdef LOGSTREAM_ENABLE_ALL_LOGGING
#define LOGSTREAM_ENABLE_LOGGING
#define LOGSTREAM_ENABLE_ENTRYEXIT
#define LOGSTREAM_ENABLE_INFO
#define LOGSTREAM_ENABLE_READS
#define LOGSTREAM_ENABLE_WRITES
#define LOGSTREAM_ENABLE_WARNINGS
#define LOGSTREAM_ENABLE_ERRORS
#define LOGSTREAM_ENABLE_CRITICALS
#endif



// DEFAULT MACROS for ENABLING/DISABLING logging by gross severity.
#ifdef LOGSTREAM_ENABLE_LOGGING

#ifdef LOGSTREAM_ENABLE_ENTRYEXIT
#define WITH_LOG_ENTRYEXIT(x) {::Iotivity::dout.pushSeverity(\
                                                            ::Iotivity::log_severity::entryexit); \
                                       { x } \
                                       ::Iotivity::dout.popSeverity(); }
#else
#define WITH_LOG_ENTRYEXIT(x)
#endif

#ifdef LOGSTREAM_ENABLE_INFO
#define WITH_LOG_INFO(x) {::Iotivity::dout.pushSeverity(::Iotivity::log_severity::info); \
                                  { x } \
                                  ::Iotivity::dout.popSeverity(); }
#else
#define WITH_LOG_INFO(x)
#endif

#ifdef LOGSTREAM_ENABLE_READS
#define WITH_LOG_READS(x) {::Iotivity::dout.pushSeverity(\
                                                                ::Iotivity::log_severity::reads); \
                                   { x } \
                                   ::Iotivity::dout.popSeverity(); }
#else
#define WITH_LOG_READS(x)
#endif

#ifdef LOGSTREAM_ENABLE_WRITES
#define WITH_LOG_WRITES(x) {::Iotivity::dout.pushSeverity(\
                                                            ::Iotivity::log_severity::writes); \
                                    { x } \
                                    ::Iotivity::dout.popSeverity(); }
#else
#define WITH_LOG_WRITES(x)
#endif

#ifdef LOGSTREAM_ENABLE_WARNINGS
#define WITH_LOG_WARNINGS(x) {::Iotivity::dout.pushSeverity(\
                                                             ::Iotivity::log_severity::warnings); \
                                      { x } \
                                      ::Iotivity::dout.popSeverity(); }
#else
#define WITH_LOG_WARNINGS(x)
#endif

#ifdef LOGSTREAM_ENABLE_ERRORS
#define WITH_LOG_ERRORS(x) {::Iotivity::dout.pushSeverity(\
                                                            ::Iotivity::log_severity::errors); \
                                    { x } \
                                    ::Iotivity::dout.popSeverity(); }
#else
#define WITH_LOG_ERRORS(x)
#endif

#ifdef LOGSTREAM_ENABLE_CRITICALS
#define WITH_LOG_CRITICALS(x) {::Iotivity::dout.pushSeverity(\
                                                            ::Iotivity::log_severity::criticals); \
                                       { x } \
                                       ::Iotivity::dout.popSeverity(); }
#else
#define WITH_LOG_CRITICALS(x)
#endif


/// @defgroup LOGGING Stream output thread-safe logging.


namespace Iotivity
{
    class loghelper;
    class logstreambuf;

    /// @brief Provides global redirection of the output of the logstream streams.
    /// @ingroup LOGGING
    class streamlogredirect
    {
        public:
            typedef std::function<void(const std::string &logLine)> LoggingCallback;

            static void redirectLoggingToVoid();
            static void redirectLoggingToStream(std::ostream &);
            static void redirectLoggingToCallback(LoggingCallback callback);

        protected:
            static loghelper &helper();
            friend class logstreambuf;
            friend class logstream;
    };

    /// @brief basic_streambuf implementation in use by logstream.
    /// @ingroup LOGGING
    class logstreambuf: public std::basic_streambuf<char>
    {
        public:
        protected:
            virtual std::streamsize xsputn(const char *_Ptr, std::streamsize _Count) override;
            virtual std::basic_streambuf<char>::int_type
            overflow(std::basic_streambuf<char>::int_type c) override;
            virtual int sync() override;
    };


    enum class log_severity : uint32_t
    {
        entryexit       = 0x0001,
        info            = 0x0002,
        reads           = 0x0010,
        writes          = 0x0020,
        warnings        = 0x0100,
        errors          = 0x0200,
        criticals       = 0x1000
    };


    /// @brief A basic_ostream which may be used to safely output debugging logging on any
    ///        thread.
    ///
    /// logstream logging is output to nowhere unless redirected using the streamlogredirect
    /// methods. logstream logging is auto-tagged with additional parameters on each new line
    /// depending on the macros defined at the top of logstream.h
    /// @ingroup LOGGING
    class logstream: public std::basic_ostream<char>
    {
        public:
            logstream();

            void pushSeverity(log_severity severity);
            bool popSeverity();

            void file(const char fileName[]);
            void line(int lineNum);

        private:
            logstreambuf m_defaultBuffer;
    };

    // Default logstream for logging. See dout for use.
    extern logstream logstream_out_object;


    /// @ingroup LOGGING
    /// @{

#if defined(LOGSTREAM_INCLUDE_FILE) || defined(LOGSTREAM_INCLUDE_LINE)
    /// @cond HIDDEN_SYMBOLS
    struct dout_fl_helper
    {
            inline dout_fl_helper(const char file[], int line)
            {
#ifdef LOGSTREAM_INCLUDE_FILE
                logstream_out_object.file(file);
#endif
#ifdef LOGSTREAM_INCLUDE_LINE
                logstream_out_object.line(line);
#endif
            }
            inline logstream &operator()() const { return logstream_out_object; }
        private:
    };
    /// @endcond

    /// @def dout
    /// Macro to access the default static logstream instance. This provides file and
    /// line-number output if the that feature is enabled.
#define dout dout_fl_helper(__FILE__, __LINE__)()
#else
    /// @def dout
    /// Macro to access the default static logstream instance. This provides file and
    /// line-number output if the that feature is enabled.
#define dout logstream_out_object
#endif
    /// @}
}

#else

#define WITH_LOG_ENTRYEXIT(x)
#define WITH_LOG_INFO(x)
#define WITH_LOG_READS(x)
#define WITH_LOG_WRITES(x)
#define WITH_LOG_WARNINGS(x)
#define WITH_LOG_ERRORS(x)
#define WITH_LOG_CRITICALS(x)

#endif // LOGSTREAM_ENABLE_LOGGING