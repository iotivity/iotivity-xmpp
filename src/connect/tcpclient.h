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

/// @file tcpclient.h

#pragma once

#include "../include/xmpp_feature_flags.h"


#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT

#include "connecterror.h"
#include "streaminterfaces.h"
#include "../include/ccfxmpp.h"

#pragma warning(push)
#pragma warning(disable: 4996)
#include <asio/ip/tcp.hpp>
#pragma warning(pop)

#include <memory>


namespace Iotivity
{
    namespace Xmpp
    {
        struct TcpConnectionImpl;
        /// @cond HIDDEN_SYMBOLS
        struct TcpConnectionImplDelete
        {
            void operator()(TcpConnectionImpl *p);
        };
        /// @endcond
    }
}



#ifdef _WIN32
XMPP_TEMPLATE template class XMPP_API std::unique_ptr<Iotivity::Xmpp::TcpConnectionImpl,
        Iotivity::Xmpp::TcpConnectionImplDelete>;
#endif


/// @defgroup TCPIP TCP/IP Connectivity and Data Streaming

namespace Iotivity
{
    class ByteBuffer;
    namespace Xmpp
    {

        class ProxyConfig;


        /// @brief Provides a TCP/IP connection using a standalone boost asio implementation.
        ///
        /// This connection may be used to provide a stream through which an IXmlConnection
        /// may transfer raw XMPP.
        /// @ingroup TCPIP
        class XMPP_API TcpConnection: public ITcpConnection
        {
            public:
                TcpConnection(const std::string &host, const std::string &port);
                TcpConnection(const std::string &host, const std::string &port,
                              const ProxyConfig &proxy);
                TcpConnection(const TcpConnection &) = delete;
                virtual ~TcpConnection() override;

                TcpConnection &operator=(const TcpConnection &) = delete;

                virtual void connect(std::chrono::milliseconds &&timeout =
                                         std::chrono::milliseconds::max()) override;

                virtual void close() override;
                virtual void send(const ByteBuffer &buf) override;
                virtual size_t receive(ByteBuffer &buf, asio::error_code &errorCode) override;
                virtual void async_receive(std::shared_ptr<ByteBuffer> buffer,
                                           ReceiveCallback callback) override;
                virtual void async_send(std::shared_ptr<ByteBuffer> buffer,
                                        SendCallback callback) override;

                virtual void negotiateTLS(TLSCallback callback) override;

            protected:
                asio::ip::tcp::socket &socket() const;

            private:
                void initTcpConnection();

                std::unique_ptr<TcpConnectionImpl, TcpConnectionImplDelete> p_;
        };


    }
}

#endif // DISABLE_SUPPORT_NATIVE_XMPP_CLIENT