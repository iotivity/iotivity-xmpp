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

/// @file streaminterfaces.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "../include/ccfxmpp.h"


#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT

#include <memory>
#include <chrono>
#include <functional>
#include <asio/error_code.hpp>


/// @defgroup TCPIP TCP/IP Connectivity and Data Streaming

namespace Iotivity
{
    class ByteBuffer;
    namespace Xmpp
    {

        class connect_error;
        class ProxyConfig;

        /// @brief Stream connection interface. Provides a stream through which bytes may be read
        /// and written synchronously or asynchronously.
        ///
        /// IStreamConnection also provides
        /// mandatory support for TLS encryption which may be started mid-stream.
        class XMPP_API IStreamConnection
        {
            public:
                virtual ~IStreamConnection() {}

                virtual void close() = 0;
                virtual void connect(std::chrono::milliseconds &&timeout =
                                         std::chrono::milliseconds::max()) = 0;
                virtual void send(const ByteBuffer &buf) = 0;
                virtual size_t receive(ByteBuffer &buf, asio::error_code &errorCode) = 0;

                typedef std::function<void(const connect_error &, size_t)> SendCallback;
                virtual void async_send(std::shared_ptr<ByteBuffer> buffer, SendCallback f) = 0;

                typedef std::function<void(const connect_error &, size_t)> ReceiveCallback;
                virtual void async_receive(std::shared_ptr<ByteBuffer> buffer,
                                           ReceiveCallback f) = 0;

                typedef std::function<void(const connect_error &)> TLSCallback;
                virtual void negotiateTLS(TLSCallback callback) = 0;
        };

        /// Interface specializing IStreamConnection to provide any required TCP/IP primitives.
        class XMPP_API ITcpConnection: public IStreamConnection
        {
            public:
        };
    }
}

#endif // DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
