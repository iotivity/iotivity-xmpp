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

#include <gtest/gtest.h>

#include <connect/streaminterfaces.h>
#include <xmpp/xmppinterfaces.h>
#include <xmpp/xmppconfig.h>
#include <asio/error_code.hpp>
#include <vector>
#include <future>


#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT

class DummyTCPConnect: public Iotivity::Xmpp::ITcpConnection
{
    public:
        virtual void close() override;
        virtual void connect(std::chrono::milliseconds &&timeout =
                                 std::chrono::milliseconds::max()) override;
        virtual void send(const Iotivity::ByteBuffer &buf) override;
        virtual size_t receive(Iotivity::ByteBuffer &buf, asio::error_code &errorCode) override;
        virtual void async_receive(std::shared_ptr<Iotivity::ByteBuffer> buffer,
                                   ReceiveCallback f) override;
};


struct Segment
{
    enum Action
    {
        PlayDataNow,
        WaitForSend,
        WaitForSendCapture,
        ServerSubstitution,

        FirstConfigAction,
        UpdateSASLPreferences,
        IncompleteNegotation,
        WillCompleteBind,
        ExitWithStateIntact,
        LastConfigAction,

        OutOfActions
    };

    std::string m_data;
    Action m_action;
};

typedef std::vector<Segment> SegmentArray;

class SegmentedDummyTCPConnect: public DummyTCPConnect
{
    public:
        SegmentedDummyTCPConnect(const SegmentArray &segments);

        virtual void close() override;
        virtual std::shared_future<void> &closed() { return m_closed; }

        virtual void send(const Iotivity::ByteBuffer &buf) override;
        virtual void async_send(std::shared_ptr<Iotivity::ByteBuffer> buffer, SendCallback f) override;
        virtual size_t receive(Iotivity::ByteBuffer &, asio::error_code &) override;
        virtual void async_receive(std::shared_ptr<Iotivity::ByteBuffer> buffer,
                                   ReceiveCallback f) override;
        virtual void negotiateTLS(TLSCallback callback) override;

        size_t expressionMatchFailures() const { return m_matchFailures; }

        bool lastSegmentRan() const { return currentAction() == Segment::OutOfActions; }

        typedef std::map<std::string, std::string> CaptureMap;
        CaptureMap captures() const { return m_captures; }

    protected:
        Segment::Action currentAction() const;
        void nextAction();

    private:
        SegmentArray m_segments;
        size_t m_currentIndex;
        size_t m_matchFailures;
        std::promise<void> m_promiseClosed;
        std::shared_future<void> m_closed;
        CaptureMap m_captures;
};


class SegmentRunner
{
    public:
        SegmentRunner(const Iotivity::Xmpp::XmppConfig &config): m_config(config) {}

        void run(const SegmentArray &segments);

        const SegmentedDummyTCPConnect::CaptureMap &captures() const { return m_captures; }
        SegmentedDummyTCPConnect::CaptureMap &captures() { return m_captures; }

        std::shared_ptr<Iotivity::Xmpp::IXmppStream> stream() const { return m_stream; }

    private:
        SegmentedDummyTCPConnect::CaptureMap m_captures;
        std::shared_ptr<Iotivity::Xmpp::IXmppStream> m_stream;
        Iotivity::Xmpp::XmppConfig m_config;
        std::shared_ptr<Iotivity::Xmpp::XmppClient> m_client;
};

#endif // ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
