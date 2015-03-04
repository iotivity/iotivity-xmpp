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

/// @file logstream.cpp

#include "stdafx.h"

#include "logstream.h"
#include "../common//buffers.h"
#pragma warning(push)
#pragma warning(disable: 4996)
#include <asio/io_service.hpp>
#pragma warning(pop)

#include <iostream>
#include <sstream>

#include <thread>
#include <mutex>
#include <map>
#include <future>

using namespace std;
using namespace asio;



/// @addtogroup LOGGING
/// Configure logging to output to a callback:
/// @code
///
/// #include <common/logstream.h>
///
/// using namespace Iotivity;
///
/// // Call to ensure that the logging callback is not called past termination.
/// atexit(&streamlogredirect::redirectLoggingToVoid);
///
/// streamlogredirect::redirectLoggingToCallback([](const string &line)
///     {
///         doSomethingWithLogLine(line);
///     });
///
///
/// @endcode


/// @addtogroup LOGGING
/// Log using dout:
/// @code
///
/// #include <common/logstream.h>
///
/// using namespace Iotivity;
///
///
/// WITH_LOG_INFO
/// (
///     dout<< "Some Information to Inform About"<< endl;
/// )
///
/// WITH_LOG_WARNINGS
/// (
///     dout<< "Some Issue To Warn About"<< endl;
/// )
///
/// try
/// {
///     // Some code that may throw connect_error
/// }
/// catch (const connect_error &error_code)
/// {
///     // Supress warning if WITH_LOG_ERRORS macro compiles out
///     (void)error_code;
///     WITH_LOG_ERRORS
///     (
///         dout<< "Some Unhandled Error Case: "<<  error_code.toString()<< endl;
///     )
/// }
///
/// @endcode


#ifdef LOGSTREAM_ENABLE_LOGGING
namespace Iotivity
{

    logstream logstream_out_object;

    //////////
    /// @cond HIDDEN_SYMBOLS
    class loghelper
    {
        public:
            loghelper():
                m_buffers(), m_os(&std::cout), m_callback(), m_ioService(),
                m_work(m_ioService), m_complete()
            {
                thread([this]()
                {
                    while (!m_ioService.stopped())
                    {
                        try
                        {
                            m_ioService.run();
                        }
                        catch (...) {}
                        if (!m_ioService.stopped())
                        {
                            m_ioService.reset();
                        }
                    }
                    m_complete.set_value();
                }).detach();
            }

            ~loghelper()
            {
                flush();
                m_ioService.stop();
                m_complete.get_future().get();
            }

            void put(const char *str, streamsize count)
            {
                if (!loggingEnabled() || !count) return;

                lock_guard<recursive_mutex> lock(getMutex());
                const thread::id &&id = this_thread::get_id();
                StreamBuffer &b = m_buffers[id].m_buffer;
                size_t prevPos = b.position();
                b.write(str, count);
                scanAndWrite(b, prevPos);
            }

            void put(const char c)
            {
                if (!loggingEnabled()) return;

                lock_guard<recursive_mutex> lock(getMutex());
                StreamBuffer &b = m_buffers[this_thread::get_id()].m_buffer;
                b.write(&c, sizeof(c));
                if (c == '\n')
                {
                    writeSegment(&b[0], b.position() - 1);
                    b.resetSize();
                }
            }

            void assignRedirect()
            {
                lock_guard<recursive_mutex> lock(getMutex());
                m_os = nullptr;
                m_callback = streamlogredirect::LoggingCallback();
            }

            void assignRedirect(ostream &os)
            {
                lock_guard<recursive_mutex> lock(getMutex());
                m_os = &os;
            }

            void assignRedirect(streamlogredirect::LoggingCallback callback)
            {
                lock_guard<recursive_mutex> lock(getMutex());
                m_callback = callback;
            }

            void flush()
            {
                if (!m_ioService.stopped())
                {
                    try
                    {
                        promise<void> wait;
                        future<void> future = wait.get_future();
                        m_ioService.dispatch([&wait]()
                        {
                            promise<void> activeWait = move(wait);
                            activeWait.set_value();
                        });
                        future.wait();
                    }
                    catch (...)
                    {}
                }
            }

            void pushSeverity(log_severity severity)
            {
                lock_guard<recursive_mutex> lock(getMutex());
                m_buffers[this_thread::get_id()].m_severity.push(severity);
            }

            bool popSeverity()
            {
                lock_guard<recursive_mutex> lock(getMutex());
                stack<log_severity> &severity = m_buffers[this_thread::get_id()].m_severity;
                if (!severity.empty())
                {
                    severity.pop();
                    return true;
                }
                else
                {
                    return false;
                }
            }

            void file(const string &fileName)
            {
                lock_guard<recursive_mutex> lock(getMutex());
                m_buffers[this_thread::get_id()].m_file = fileName;
            }

            void line(const string &lineNum)
            {
                lock_guard<recursive_mutex> lock(getMutex());
                m_buffers[this_thread::get_id()].m_line = lineNum;
            }

        protected:
            static recursive_mutex &getMutex()
            {
                static recursive_mutex s_mutex;
                return s_mutex;
            }

            inline bool loggingEnabled()
            {
                return m_os || m_callback;
            }

            void scanAndWrite(StreamBuffer &buf, const size_t fromPos)
            {
                size_t activePos = fromPos, resetPos = 0;

                bool found;
                do
                {
                    found = false;
                    for (size_t i = activePos; i < buf.position(); ++i)
                    {
                        if (buf[i] == '\n')
                        {
                            writeSegment(&buf[activePos], i - activePos);
                            activePos = i + 1;
                            resetPos = activePos;
                            found = true;
                            break;
                        }
                    }
                }
                while (found && activePos < buf.position());
                buf.shiftTowardsOrigin(resetPos);
            }

            static string severityName(log_severity severity)
            {
                switch (severity)
                {
                    case log_severity::entryexit:
                        return "ENTRYEXIT";
                    case log_severity::info:
                        return "INFO";
                    case log_severity::reads:
                        return "READ";
                    case log_severity::writes:
                        return "WRITE";
                    case log_severity::warnings:
                        return "WARNING";
                    case log_severity::errors:
                        return "ERROR";
                    case log_severity::criticals:
                        return "CRITICAL";
                    default:
                        return "DEFAULT";
                }
            }

            void writeSegment(const unsigned char *str, size_t count)
            {
                thread::id thisID = this_thread::get_id();
                string tempStr((const char *)str, count);

                string priority = "INFO";

                auto &currentEntry = m_buffers[thisID];
                stack<log_severity> &severity = currentEntry.m_severity;
                string region = severity.empty() ? "DEFAULT" : severityName(severity.top());
                string fileAndLine, timeStamp;

#ifdef LOGSTREAM_INCLUDE_TIME
                auto now = chrono::high_resolution_clock::now();
                timeStamp = "{" + to_string(chrono::duration_cast<chrono::milliseconds>(
                                                now.time_since_epoch()).count()) + "}";
#endif
#ifdef LOGSTREAM_INCLUDE_FILE
                fileAndLine = "<" + currentEntry.m_file;
#ifdef LOGSTREAM_INCLUDE_LINE
                fileAndLine += "(#" + currentEntry.m_line + ")>";
#else
                fileAndLine += ">";
#endif
#else
#ifdef LOGSTREAM_INCLUDE_LINE
                fileAndLine = "<LINE #" + currentEntry.m_file + ">";
#endif
#endif

                m_ioService.dispatch(
                    [this, tempStr, thisID, region, priority, fileAndLine, timeStamp]()
                {
                    lock_guard<recursive_mutex> lock(getMutex());
                    if (m_callback)
                    {
                        ostringstream tempStream;
                        streamLine(tempStream, thisID, priority, region, tempStr,
                                   fileAndLine, timeStamp);
                        std::string &&outString = tempStream.str();
                        if (m_os)
                        {
                            (*m_os) << outString << endl;
                        }
                        m_callback(outString);
                    }
                    else if (m_os)
                    {
                        streamLine(*m_os, thisID, priority, region, tempStr, fileAndLine,
                                   timeStamp);
                        (*m_os) << endl;
                    }
                });
            }

            static void streamLine(ostream &os, const thread::id &thisID, const std::string &priority,
                                   const std::string &region, const std::string &str,
                                   const std::string &fileAndLine, const std::string &timeStamp)
            {
                (void)fileAndLine;
                (void)thisID;
                (void)timeStamp;

                os <<
#ifdef LOGSTREAM_INCLUDE_THREAD
                   "[" << thisID << "]" <<
#endif
#ifdef LOGSTREAM_INCLUDE_TIME
                   timeStamp <<
#endif
                   "(" << priority << "|" << region << ")" <<
#if defined(LOGSTREAM_INCLUDE_FILE) || defined(LOGSTREAM_INCLUDE_LINE)
                   fileAndLine <<
#endif
                   ": " << str;
            }

        private:
            struct ThreadLocalData
            {
                ThreadLocalData() = default;

                StreamBuffer m_buffer;
                stack<log_severity> m_severity;
                string m_file;
                string m_line;
            };

            typedef map<thread::id, ThreadLocalData> ThreadLocalBuffer;
            ThreadLocalBuffer m_buffers;

            ostream *m_os;
            streamlogredirect::LoggingCallback m_callback;

            asio::io_service m_ioService;
            asio::io_service::work m_work;
            promise<void> m_complete;
    };
    /// @endcond

    //////////
    void streamlogredirect::redirectLoggingToVoid()
    {
        helper().assignRedirect();
    }
    void streamlogredirect::redirectLoggingToStream(ostream &os)
    {
        helper().assignRedirect(os);
    }

    void streamlogredirect::redirectLoggingToCallback(LoggingCallback callback)
    {
        helper().assignRedirect(callback);
    }

    loghelper &streamlogredirect::helper()
    {
        static loghelper h;
        return h;
    }


    //////////
    logstream::logstream(): basic_ostream<char>(&m_defaultBuffer), m_defaultBuffer()
    {
    }

    void logstream::pushSeverity(log_severity severity)
    {
        streamlogredirect::helper().pushSeverity(severity);
    }

    bool logstream::popSeverity()
    {
        return streamlogredirect::helper().popSeverity();
    }

    void logstream::file(const char fileName[])
    {
        if (fileName)
        {
            streamlogredirect::helper().file(fileName);
        }
    }

    void logstream::line(int lineNum)
    {
        if (lineNum)
        {
            streamlogredirect::helper().line(to_string(lineNum));
        }
    }

    logstream &pushSeverity(logstream &os, log_severity severity)
    {
        os.pushSeverity(severity);
        return os;
    }

    logstream &popSeverity(logstream &os)
    {
        os.popSeverity();
        return os;
    }




    //////////
    streamsize logstreambuf::xsputn(const char *_Ptr, streamsize _Count)
    {
        streamlogredirect::helper().put(_Ptr, _Count);
        return _Count;
    }

    basic_streambuf<char>::int_type logstreambuf::overflow(basic_streambuf<char>::int_type c)
    {
        if (c != basic_streambuf<char>::traits_type::eof())
        {
            streamlogredirect::helper().put((char)c);
        }
        return c;
    }

    int logstreambuf::sync()
    {
        streamlogredirect::helper().flush();
        return 0;
    }
}

#endif // LOGSTREAM_ENABLE_LOGGING