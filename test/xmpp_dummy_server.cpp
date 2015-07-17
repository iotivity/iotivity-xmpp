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

/// @file xmpp_tests.cpp

#include "stdafx.h"
#include <gtest/gtest.h>

#include <common/buffers.h>
#include <xml/portabledom.h>
#include <common/str_helpers.h>
#include <xmpp/xmppclient.h>
#include <xmpp/sasl.h>
#include <common/bufferencrypt.h>
#include <connect/connecterror.h>

#include "xmpp_dummy_server.h"



#if !defined(__GNUC__) || __GNUC__>4 || (__GNUC__==4 && __GNUC_MINOR__>9)
#include <regex>
#define REGEX_SUPPORTED
#endif

extern "C"
{
#if !defined(_WIN32)
#ifdef WITH_SAFE
#include <safe_mem_lib.h>
#include <safe_str_lib.h>
#endif
#endif
}



using namespace std;
using namespace Iotivity;
using namespace Iotivity::Xmpp;
using namespace Iotivity::XML;


#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT


void DummyTCPConnect::close() {}
void DummyTCPConnect::connect(std::chrono::milliseconds &&timeout) {}
void DummyTCPConnect::send(const ByteBuffer &buf) {}
size_t DummyTCPConnect::receive(ByteBuffer &buf, asio::error_code &errorCode) { return 0; }
void DummyTCPConnect::async_receive(std::shared_ptr<ByteBuffer> buffer, ReceiveCallback f)
{
    if (!buffer)
    {
        throw connect_error(LocalError(LocalError::ecInvalidParameter));
    }
    f(connect_error::SUCCESS, buffer->size());
}

//////////
SegmentedDummyTCPConnect::SegmentedDummyTCPConnect(const SegmentArray &segments):
    m_segments(segments), m_currentIndex(0), m_matchFailures(0),
    m_promiseClosed(), m_closed(m_promiseClosed.get_future()), m_captures()
{}

void SegmentedDummyTCPConnect::close()
{
    m_promiseClosed.set_value();
}

void SegmentedDummyTCPConnect::send(const ByteBuffer &buf)
{
    static const char CLOSE_BUFFER_STR[] = "</stream:stream>";
    static const ByteBuffer CLOSE_BUFFER(CLOSE_BUFFER_STR, sizeof(CLOSE_BUFFER_STR) - 1);
    if (currentAction() == Segment::WaitForSend)
    {
        const string &currentData = m_segments.at(m_currentIndex).m_data;

        nextAction();

        // Allow "" to match any send data.
        if (currentData.size() != 0)
        {
            string tempStr((const char *)buf.get(), buf.size());
            if (tempStr != currentData)
            {
                ++m_matchFailures;
                cout << "SEND Failed to Match. Expected:" << endl;
                cout << currentData << endl;
                cout << "Received: " << endl;
                cout << tempStr << endl;
                EXPECT_NO_THROW(throw runtime_error("Expected Send Missing"));
            }
        }
    }
    else if (currentAction() == Segment::WaitForSendCapture)
    {
        const string &currentData = m_segments.at(m_currentIndex).m_data;

        nextAction();

        m_captures[currentData] = string((const char *)buf.get(), buf.size());
        cout << "CAPTURED: " << currentData << ":" << m_captures[currentData] << endl;
    }
    else if (buf != CLOSE_BUFFER && currentAction() != Segment::OutOfActions)
    {
        ++m_matchFailures;
        throw runtime_error("Data sent outside of WaitForSend segment");
    }
}

void SegmentedDummyTCPConnect::async_send(std::shared_ptr<ByteBuffer> buffer, SendCallback f)
{
    if (buffer)
    {
        send(*buffer);
        f(connect_error::SUCCESS, buffer->size());
    }
    else
    {
        f(connect_error(LocalError(LocalError::ecInvalidParameter)), 0);
    }
}

size_t SegmentedDummyTCPConnect::receive(ByteBuffer &, asio::error_code &)
{
    cout << "SIM READ" << endl;
    return 0;
}

void SegmentedDummyTCPConnect::async_receive(std::shared_ptr<ByteBuffer> buffer,
        ReceiveCallback f)
{
    if (!buffer)
    {
        throw connect_error(LocalError(LocalError::ecInvalidParameter));
    }

    if (currentAction() == Segment::PlayDataNow)
    {
        const string &currentData = m_segments.at(m_currentIndex).m_data;
        //cout<< "ASYNC_RECEIVE"<< currentData<< endl;
        if (buffer->size() < currentData.size())
        {
            // NOTE: This is not an issue with the tcp connection; the test simulation
            //       just needs to be able to fit its segments into the read buffers.
            //       If the read buffers get smaller, the segments will need to be
            //       smaller too, but this should not affect normal operation.
            throw runtime_error("Insufficient buffer for simulated read request");
        }
        memcpy(buffer->get(), currentData.c_str(), buffer->size());
        nextAction();
        f(connect_error::SUCCESS, currentData.size());
    }
    else if (currentAction() == Segment::ServerSubstitution)
    {

#ifdef REGEX_SUPPORTED
        string currentData = m_segments.at(m_currentIndex).m_data, copyData = currentData;
        const static regex s_substitutionFilter("\\$\\{([^\\}]+)\\}");

        for (auto i = sregex_iterator(copyData.begin(), copyData.end(), s_substitutionFilter);
             i != sregex_iterator(); ++i)
        {
            auto match = *i;
            bool foundExpression = false;
            auto fullMatchStr = match.str(), replaceStr = fullMatchStr;

            auto splitV = str_helper::split(match[1].str(), '.');
            list<string> split;
            copy(splitV.begin(), splitV.end(), back_inserter(split));

            if (!split.empty())
            {
                string tag = split.front();
                split.pop_front();

                const auto f = m_captures.find(tag);
                if (f != m_captures.end())
                {
                    string tagStanza = m_captures[tag];

                    auto doc = XMLDocument::createEmptyDocument();
                    doc->parse(tagStanza);
                    auto element = doc->documentElement();

                    if (element)
                    {
                        while (!split.empty())
                        {
                            if (element->name() == split.front())
                            {
                                split.pop_front();
                                if (split.empty()) break;
                            }

                            string attrTest;
                            if (element->getAttribute(split.front(), attrTest))
                            {
                                string last = split.front();
                                split.pop_front();
                                if (split.empty())
                                {
                                    // This is the attribute we are looking for
                                    foundExpression = true;
                                    replaceStr = attrTest;
                                    break;
                                }
                                else
                                {
                                    // Must not be an attribute. Keep looking
                                    split.push_front(last);
                                }
                            }

                            for (auto &i : element->elements())
                            {
                                if (i->name() == split.front())
                                {
                                    split.pop_front();
                                    element.reset(i.release());
                                    break;
                                }
                            }

                            if (split.empty()) break;
                            split.pop_front();
                        }
                    }

                    if (foundExpression)
                    {
                        auto f = currentData.find(fullMatchStr);
                        if (f != string::npos)
                        {
                            currentData.erase(f, fullMatchStr.size());
                            currentData.insert(f, replaceStr);
                        }
                    }

                }
                else
                {
                    cout << "WARNING: Test substitution variable " << tag <<
                         " did not match known parameters" << endl;
                }
            }
        }

        if (buffer->size() < currentData.size())
        {
            throw runtime_error("Insufficient buffer for simulated read request");
        }
        memcpy(buffer->get(), currentData.c_str(), buffer->size());
        nextAction();
        f(connect_error::SUCCESS, currentData.size());
#else
        cout << "WARNING: TEST UNUSABLE ON THIS PLATFORM; REGEX IS NOT SUPPORTED" << endl;
#endif

    }
    else
    {
        //cout<< "INVALID STREAM CURRENT STATE: "<< currentAction()<< endl;
        f(connect_error::ecInvalidStream, 0);
    }
}

void SegmentedDummyTCPConnect::negotiateTLS(TLSCallback callback)
{
    if (callback) callback(connect_error::SUCCESS);
}

Segment::Action SegmentedDummyTCPConnect::currentAction() const
{
    return m_currentIndex < m_segments.size() ?
           m_segments[m_currentIndex].m_action :
           Segment::OutOfActions;
}

void SegmentedDummyTCPConnect::nextAction()
{
    do
    {
        ++m_currentIndex;
    }
    while (currentAction() > Segment::FirstConfigAction &&
           currentAction() < Segment::LastConfigAction);
}



void SegmentRunner::run(const SegmentArray &segments)
{
    try
    {
        bool willCompleteNegotiation = true, willCompleteBind = false, exitWithStateIntact = false;
        list<string> SASLPreferences;
        for (const auto &s : segments)
        {
            switch (s.m_action)
            {
                case Segment::UpdateSASLPreferences:
                    SASLPreferences.push_back(s.m_data);
                    break;
                case Segment::IncompleteNegotation:
                    willCompleteNegotiation = false;
                    break;
                case Segment::WillCompleteBind:
                    willCompleteBind = true;
                    break;
                case Segment::ExitWithStateIntact:
                    exitWithStateIntact = true;
                    break;
                default:
                    break;
            }
        }

        auto remoteTcp = make_shared<SegmentedDummyTCPConnect>(segments);

        auto xmlConnection = make_shared<XmppConnection>(
                                 static_pointer_cast<IStreamConnection>(remoteTcp));

        auto streamPromise = make_shared<promise<shared_ptr<IXmppStream>>>();
        auto streamFuture = streamPromise->get_future();

        m_config.overrideSASLOrder(SASLPreferences);

        m_client = XmppClient::create();
        ASSERT_NO_THROW(m_client->initiateXMPP(m_config, xmlConnection, streamPromise));

        m_stream = streamFuture.get();
        EXPECT_NE(m_stream, nullptr);

        if (m_stream)
        {
            if (willCompleteNegotiation)
            {
#if __cplusplus>=201103L || defined(_WIN32)
                auto status = m_stream->whenNegotiated().wait_for(chrono::seconds(5));
                EXPECT_EQ(status, future_status::ready);

                if (willCompleteBind)
                {
                    auto status = m_stream->whenBound().wait_for(chrono::seconds(5));
                    EXPECT_EQ(status, future_status::ready);
                }
#else
                bool status = m_stream->whenNegotiated().wait_for(chrono::seconds(5));
                EXPECT_TRUE(status);

                if (willCompleteBind)
                {
                    bool status = m_stream->whenBound().wait_for(chrono::seconds(5));
                    EXPECT_TRUE(status);
                }
#endif
            }
            size_t sleepCount = 0;
            while (!remoteTcp->lastSegmentRan() && sleepCount < 1000)
            {
                ++sleepCount;
                this_thread::sleep_for(chrono::milliseconds(1));
            }

            if (!exitWithStateIntact)
            {
                EXPECT_NO_THROW(m_stream->close());

                remoteTcp->closed().wait();
            }
            EXPECT_EQ(remoteTcp->expressionMatchFailures(), 0UL);

            m_captures = remoteTcp->captures();
        }
    }
    catch (const enum Segment::Action &state)
    {
        if (state == Segment::ExitWithStateIntact)
        {
            cout << "EXIT WITH STATE INTACT" << endl;
        }
        else
        {
            EXPECT_NO_THROW(throw state);
        }
    }
    catch (const connect_error &ce)
    {
        EXPECT_NO_THROW(throw ce);
    }
    catch (const runtime_error &re)
    {
        EXPECT_NO_THROW(throw re);
    }
}

#endif // ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT

