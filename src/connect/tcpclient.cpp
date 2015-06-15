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

/// @file tcpclient.cpp

#include "stdafx.h"

#include "tcpclient.h"

#ifndef DISABLE_SUPPORT_NATIVE_XMPP_CLIENT

#include "proxy.h"

#include "../common/logstream.h"

#pragma warning(push)
#pragma warning(disable: 4996)
#include <asio/ssl/context.hpp>
#include <asio/ssl/stream.hpp>
#include <asio/buffer.hpp>
#include <asio/streambuf.hpp>
#include <asio/io_service.hpp>
#include <asio/steady_timer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/strand.hpp>
#pragma warning(pop)

#include <list>
#include <thread>
#include <future>
#include <iostream>


using namespace std;
using namespace asio;
using namespace asio::ip;

/// @addtogroup TCPIP
/// This is intended for use with an XMPP connection. See the XMPP Client module for details.
/// Create and connect a TCP client:
/// @code
///
/// #include <connect/tcpclient.h>
/// #include <connect/proxy.h>
///
/// using namespace Iotivity;
/// using namespace Iotivity::Xmpp;
///
/// ProxyConfig proxy(PROXY_HOST, PROXY_PORT, PROXY_TYPE);
///
/// auto remoteTcp = make_shared<TcpConnection>(HOST_NAME, HOST_PORT, proxy);
///
/// try
/// {
///     remoteTcp->connect();
/// }
/// catch (const connect_error &)
/// {
///     // Handle connection errors.
/// }
///
/// @endcode

namespace Iotivity
{
    namespace Xmpp
    {

#ifndef DISABLE_SUPPORT_SOCKS5
        // @cond HIDDEN_SYMBOLS
        // SOCKS5 Connection Implementation
        class SOCKS5Connect
        {
                static const uint8_t SOCKS_VER = 5;             // RFC 1928
                static const uint8_t USERNAMEPASSWORD_VER = 1;  // RFC 1929
                enum class Methods : uint8_t
                {
                    NoAuthentication    = 0x00,
                    GSSAPI              = 0x01,
                    UserNamePassword    = 0x02,
                    // 0x4-0x7f are assigned
                    // 0x80-0xFE are reserved for private methods
                    NoAcceptableMethods = 0xFF
                };
                enum class Commands : uint8_t
                {
                    Connect      = 0x01,
                    Bind         = 0x02,
                    UDPAssociate = 0x03
                };
                enum class AddressTypes : uint8_t
                {
                    IPV4        = 0x01,
                    DomainName  = 0x03,
                    IPV6        = 0x04
                };
                enum class SOCKSResponses : uint8_t
                {
                    Succeeded = 0x00,
                    GeneralFailure = 0x01,
                    NotAllowedByRuleset = 0x02,
                    NetworkUnreachable = 0x03,
                    HostUnreachable = 0x04,
                    ConnectionRefused = 0x05,
                    TTLExpired = 0x06,
                    CommandNotSupported = 0x07,
                    AddressTypeNotSupported = 0x08
                                              // 0x09 - 0xFF Unassigned and reserved
                };

            public:
                SOCKS5Connect(asio::io_service &ioService, const ProxyConfig &proxy):
                    m_ioService(ioService), m_config(proxy) {}

                SOCKS5Connect(asio::io_service &ioService, const string &host, const string &port):
                    m_ioService(ioService), m_config(ProxyConfig(host, port,
                                                         ProxyConfig::ProxyType::ProxySOCKS5))
                {}

                SOCKS5Connect(const SOCKS5Connect &) = delete;
                SOCKS5Connect &operator=(const SOCKS5Connect &) = delete;

                void connect(const string &host, const string &port, tcp::socket &remoteSocket)
                {
                    if (host.size() > 255)
                    {
                        throw connect_error(connect_error::ecHostNameTooLongForSOCKS5);
                    }

                    uint64_t tempVal = strtoull(port.c_str(), nullptr, 10);
                    if (tempVal > numeric_limits<uint16_t>::max())
                    {
                        throw connect_error(connect_error::ecInvalidPort);
                    }

                    if (m_config.userName().size() > 255)
                    {
                        throw connect_error(connect_error::ecUserNameTooLongForSOCKS5);
                    }
                    if (m_config.password().size() > 255)
                    {
                        throw connect_error(connect_error::ecPasswordTooLongForSOCKS5);
                    }


                    uint16_t portVal = static_cast<uint16_t>(tempVal);

                    try
                    {
                        tcp::resolver tcpResolve(m_ioService);
                        tcp::resolver::query socksQuery(m_config.host(), m_config.port());

                        auto socksResolve = tcpResolve.resolve(socksQuery);

                        tcp::socket localSocket(m_ioService);
                        localSocket.connect(*socksResolve);

                        list<Methods> methods;

                        // NOTE: Add new auth. methods here (or refactor to use an array or equiv.)
                        methods.push_back(Methods::NoAuthentication);

                        // NOTE: This is not added currently since WireShark's dissector won't follow
                        //       the SOCKS5 conversation if this shows up. This needs to be dealt
                        //       with, but only if SOCKS5 requires username/pass.
                        //methods.push_back(UserNamePassword);


                        // Send Version and Supported Methods
                        asio::streambuf verBuf;
                        ostream verReq(&verBuf);
                        verReq << (uint8_t)SOCKS_VER;
                        verReq << (uint8_t)methods.size();
                        for (auto method : methods)
                        {
                            verReq << (uint8_t)method;
                        }

                        localSocket.send(verBuf.data());

                        // Get server-selected method
                        uint8_t serverVer = 0;
                        Methods method = Methods::NoAcceptableMethods;

                        array<mutable_buffer, 2> methodBufs =
                        {{
                            buffer(&serverVer, sizeof(serverVer)),
                            buffer(&method, sizeof(method))
                        }};

                        localSocket.receive(methodBufs);

                        switch (method)
                        {
                            case Methods::NoAuthentication:
                                // No-op. Continue
                                break;
                            case Methods::GSSAPI:
                                // RFC 1961
                                // TODO: (As needed/if needed). Remove close if implemented.
                                localSocket.close();
                                break;
                            case Methods::UserNamePassword:
                                if (negotiateUserNamePassword(localSocket) != 0x00)
                                {
                                    localSocket.close();
                                    throw connect_error(connect_error::ecSOCKS5InvalidUserNameOrPassword);
                                }
                                break;
                            default:
                            case Methods::NoAcceptableMethods:
                                localSocket.close();
                                break;
                        }

                        // If we have not closed due to limited (no) support, continue the
                        // post-authentication negotiation.
                        if (localSocket.is_open())
                        {
                            // Send connect request
                            uint16_t networkPort =
                                asio::detail::socket_ops::host_to_network_short(portVal);

                            asio::streambuf reqBuf;
                            ostream establishReq(&reqBuf);
                            establishReq << SOCKS_VER;
                            establishReq << (uint8_t)Commands::Connect;
                            establishReq << (uint8_t)0x00;                 // reserved
                            establishReq << (uint8_t)AddressTypes::DomainName;
                            establishReq << (uint8_t)host.size();
                            establishReq << host;
                            establishReq.write((const char *)&networkPort,
                                               sizeof(networkPort));

                            localSocket.send(reqBuf.data());

                            auto reply = SOCKSResponses::GeneralFailure;
                            uint8_t reserved = 0x00;
                            auto addressType = AddressTypes::IPV4;
                            array<mutable_buffer, 4> respBufs =
                            {{
                                buffer(&serverVer, sizeof(serverVer)),
                                buffer(&reply, sizeof(reply)),
                                buffer(&reserved, sizeof(reserved)),
                                buffer(&addressType, sizeof(addressType))
                            }};

                            // Get reply (header)
                            localSocket.receive(respBufs);

                            connect_error result((ECODE)reply, connect_error::etSOCKS5Error());
                            if (!result.succeeded())
                            {
                                throw result;
                            }

                            // Get reply (remote address)
                            switch (addressType)
                            {
                                case AddressTypes::IPV4:
                                    {
                                        ip::address_v4::bytes_type ipv4Address = {{0}};
                                        uint16_t port = 0;
                                        array<mutable_buffer, 2> addressBufs =
                                        {{
                                            buffer(&ipv4Address, sizeof(ipv4Address)),
                                            buffer(&port, sizeof(port))
                                        }};

                                        localSocket.receive(addressBufs);
                                        port = asio::detail::socket_ops::network_to_host_short(port);

                                        WITH_LOG_INFO
                                        (
                                            auto endpoint = tcp::endpoint(ip::address_v4(ipv4Address),
                                                                          port);
                                            dout << "SOCKS5 IPV4 CONNECT: " << endpoint.address() << ":" <<
                                            port << endl;
                                        )
                                        remoteSocket = move(localSocket);
                                    }
                                    break;
                                case AddressTypes::DomainName:
                                    {
                                        uint8_t domainNameLength = 0;
                                        localSocket.receive(buffer(&domainNameLength,
                                                                   sizeof(domainNameLength)));
                                        uint16_t port = 0;
                                        string domainStr;
                                        char *domainName = nullptr;
                                        try
                                        {
                                            domainName = new char[domainNameLength];
                                            array<mutable_buffer, 2> addressBufs =
                                            {{
                                                buffer(domainName, domainNameLength),
                                                buffer(&port, sizeof(port))
                                            }};
                                            localSocket.receive(addressBufs);
                                            port = asio::detail::socket_ops::network_to_host_short(port);

                                            domainStr = string(&domainName[0], domainNameLength);
                                        }
                                        catch (...)
                                        {
                                            delete domainName;
                                            throw;
                                        }
                                        delete domainName;

                                        WITH_LOG_INFO
                                        (
                                            dout << "SOCKS5 DOMAIN CONNECT: " << domainStr << ":" <<
                                            port << endl;
                                        )

                                        tcp::resolver::query remoteQuery(domainStr, to_string(port));

                                        auto remoteResolve = tcpResolve.resolve(remoteQuery);
                                        remoteSocket = move(localSocket);
                                    }
                                    break;
                                case AddressTypes::IPV6:
                                    {
                                        ip::address_v6::bytes_type ipv6Address = {{0}};
                                        uint16_t port = 0;
                                        array<mutable_buffer, 2> addressBufs =
                                        {{
                                            buffer(&ipv6Address, sizeof(ipv6Address)),
                                            buffer(&port, sizeof(port))
                                        }};

                                        localSocket.receive(addressBufs);
                                        port = asio::detail::socket_ops::network_to_host_short(port);
                                        WITH_LOG_INFO
                                        (
                                            auto endpoint = tcp::endpoint(ip::address_v6(ipv6Address),
                                                                          port);
                                            dout << "SOCKS5 IPV6 CONNECT: " << endpoint.address() << ":" <<
                                            port << endl;
                                        )
                                        remoteSocket = move(localSocket);
                                    }
                                    break;
                                default:
                                    localSocket.close();
                                    throw connect_error(connect_error::ecUnknownSOCKS5AddressType);
                                    break;
                            }
                        }
                    }
                    catch (const connect_error &ce)
                    {
                        throw ce;
                    }
                    catch (const exception &e)
                    {
                        (void)e;
                        WITH_LOG_ERRORS
                        (
                            dout << "SOCKS5 Connect Exception: " << e.what() << endl;
                        )
                    }
                }

            protected:

                uint8_t negotiateUserNamePassword(tcp::socket &localSocket)
                {
                    // Ensure the password string is not kept in memory (ignoring any
                    // deficiencies of the socket implementation).
                    SecureBuffer upassBuffer;
                    const uint8_t ver = USERNAMEPASSWORD_VER;
                    const uint8_t ulen = static_cast<uint8_t>(m_config.userName().size());
                    const uint8_t passlen =
                        static_cast<uint8_t>(m_config.password().size());

                    upassBuffer.write(&ver, sizeof(ver));
                    upassBuffer.write(&ulen, sizeof(ulen));
                    upassBuffer.write(m_config.userName().c_str(),
                                      m_config.userName().size());
                    upassBuffer.write(&passlen, sizeof(passlen));
                    upassBuffer.write(m_config.password());

                    localSocket.send(buffer((const void *)upassBuffer,
                                            upassBuffer.size()));

                    uint8_t serverVer = 0;
                    uint8_t upassStatus = 0xFF;
                    array<mutable_buffer, 2> upassResponse =
                    {{
                        buffer(&serverVer, sizeof(serverVer)),
                        buffer(&upassStatus, sizeof(upassStatus))
                    }};

                    localSocket.receive(upassResponse);
                    return upassStatus;
                }


            private:
                io_service &m_ioService;
                ProxyConfig m_config;
        };
        /// @endcond
#endif


        //////////
        /// @cond HIDDEN_SYMBOLS
        struct TcpConnectionImpl
        {
            enum class TLSMode
            {
                PreNegotiation,
                InNegotation,
                Negotiated
            };

            TcpConnectionImpl(const string &host, const string &port, const ProxyConfig &proxy):
                m_mutex(), m_TLSMode(TLSMode::PreNegotiation), m_host(host), m_port(port),
                m_proxy(proxy), m_ioService(), m_sslStrand(m_ioService), m_ioServiceStopped(),
                m_work(m_ioService), m_sslContext(asio::ssl::context::tlsv12),
                m_sslSocket(m_ioService, m_sslContext),
                m_socket(m_sslSocket.next_layer()),
                m_socketTimeout(m_ioService), m_ioServiceThreadId(), m_inPreNegotationRead(),
                m_ioServiceThread()
            {
                m_inPreNegotationRead = 0;
            }

            mutable std::recursive_mutex m_mutex;
            TLSMode m_TLSMode;
            string m_host;
            string m_port;
            ProxyConfig m_proxy;
            io_service m_ioService;
            io_service::strand m_sslStrand;
            promise<void> m_ioServiceStopped;
            io_service::work m_work;
            ssl::context m_sslContext;
            ssl::stream<asio::ip::tcp::socket> m_sslSocket;
            ip::tcp::socket &m_socket;
            steady_timer m_socketTimeout;
            thread::id m_ioServiceThreadId;
            atomic_uint m_inPreNegotationRead;
            thread m_ioServiceThread;

            TLSMode mode() const
            {
                lock_guard<recursive_mutex> lock(m_mutex);
                return m_TLSMode;
            }

            void setMode(TLSMode mode)
            {
                lock_guard<recursive_mutex> lock(m_mutex);
                m_TLSMode = mode;
            }
        };
        /// @endcond

        void TcpConnectionImplDelete::operator()(TcpConnectionImpl *p) { delete p; }



        //////////
        TcpConnection::TcpConnection(const string &host, const string &port):
            p_(new TcpConnectionImpl(host, port, ProxyConfig()))
        {
            initTcpConnection();
        }

        TcpConnection::TcpConnection(const string &host, const string &port,
                                     const ProxyConfig &proxy):
            p_(new TcpConnectionImpl(host, port, proxy))
        {
            initTcpConnection();
        }

        void TcpConnection::initTcpConnection()
        {
            p_->m_sslContext.set_verify_mode(asio::ssl::context_base::verify_peer);
            p_->m_sslContext.set_verify_callback([](bool preverified, asio::ssl::verify_context &)
            {
                WITH_LOG_ENTRYEXIT
                (
                    dout << "VERIFY CALLBACK" << endl;
                )
                //ctx.native_handle().
                return preverified;
            });
            //p_->m_sslContext.set_options(

            p_->m_socketTimeout.expires_from_now(chrono::seconds::max());

            p_->m_ioServiceThread = thread([this]()
            {
                while (!p_->m_ioService.stopped())
                {
                    try
                    {
                        p_->m_ioService.run();
                    }
                    catch (const connect_error &ec)
                    {
                        (void)ec;
                        WITH_LOG_CRITICALS
                        (
                            dout << "EXCEPTION In TcpConnection " << ec.toString() << endl;
                        )
                    }
                    catch (const exception &ec)
                    {
                        (void)ec;
                        WITH_LOG_CRITICALS
                        (
                            dout << "EXCEPTION In TcpConnection " << ec.what() << endl;
                        )
                    }
                    catch (...)
                    {
                        WITH_LOG_CRITICALS
                        (
                            dout << "EXCEPTION In TcpConnection" << endl;
                        )
                    }
                    if (!p_->m_ioService.stopped())
                    {
                        p_->m_ioService.reset();
                    }
                }
                p_->m_ioServiceStopped.set_value();
            });

            p_->m_ioServiceThreadId = p_->m_ioServiceThread.get_id();
        }

        TcpConnection::~TcpConnection()
        {
            close();
            if (p_->m_ioServiceThread.joinable())
            {
                p_->m_ioServiceThread.join();
            }
        }


        void TcpConnection::close()
        {
            WITH_LOG_ENTRYEXIT
            (
                dout << "TCPConnection Close" << endl;
            )
            if (p_->mode() == TcpConnectionImpl::TLSMode::Negotiated)
            {
                try
                {
                    p_->m_socket.cancel();
                }
                catch (...) {}
            }
            try
            {
                if (!p_->m_socket.is_open())
                {
                    asio::error_code closeError;
                    p_->m_socket.close(closeError);
                }
            }
            catch (...) {}
            if (!p_->m_ioService.stopped())
            {
                p_->m_ioService.stop();
                if (this_thread::get_id() != p_->m_ioServiceThreadId)
                {
                    p_->m_ioServiceStopped.get_future().get();
                }
            }
        }

        void TcpConnection::connect(chrono::milliseconds &&timeout)
        {
            try
            {
                p_->m_socketTimeout.expires_from_now(timeout);

                if (p_->m_proxy.type() == ProxyConfig::ProxyType::ProxySOCKS5)
                {
#ifdef DISABLE_SUPPORT_SOCKS5
                    throw connect_error::ecProxyTypeNotSupported;
#else
                    SOCKS5Connect socks5(p_->m_ioService, p_->m_proxy);
                    socks5.connect(p_->m_host, p_->m_port, p_->m_socket);
#endif
                }
                else
                {
                    tcp::resolver tcpResolve(p_->m_ioService);
                    tcp::resolver::query urlQuery(p_->m_host, p_->m_port);

                    auto resolveIterator = tcpResolve.resolve(urlQuery);


                    p_->m_socket.connect(*resolveIterator);
                }

                p_->m_socketTimeout.expires_from_now(chrono::seconds::max());
            }
            catch (const connect_error &ce)
            {
                throw ce;
            }
            catch (const exception &e)
            {
                (void)e;
                WITH_LOG_ERRORS
                (
                    dout << e.what() << endl;
                )
            }
            catch (...)
            {}
        }

        // SSL will only handle partial writes (since it may need to negotiate during a write
        // but we need send and async_send to complete with all bytes written. Simulate this
        // behavior.
        void ssl_write_all(asio::ssl::stream<asio::ip::tcp::socket> &socket,
                           shared_ptr<ByteBuffer> tempBuffer, TcpConnection::SendCallback callback)
        {
            socket.async_write_some(buffer((void *)*tempBuffer, tempBuffer->size()),
                                    [&socket, tempBuffer, callback](const asio::error_code & ec, size_t bytes)
            {
                size_t bytesWritten = bytes;
                connect_error ce(ec);
                if (!ce.succeeded())
                {
                    if (callback) callback(ce, bytes);
                    return;
                }

                while (bytesWritten < tempBuffer->size())
                {
                    WITH_LOG_WRITES
                    (
                        string tempStr((const char *)((const uint8_t *)*tempBuffer + bytesWritten),
                                       (size_t)(tempBuffer->size() - bytesWritten));
                        dout << "DATAOUT: " << tempStr << endl;
                    )

                    asio::error_code writeError;
                    bytesWritten += socket.write_some(buffer((const uint8_t *)*tempBuffer +
                                                      bytesWritten,
                                                      tempBuffer->size() - bytesWritten),
                                                      writeError);



                    connect_error ce(writeError);
                    if (!ce.succeeded())
                    {
                        if (callback) callback(ce, bytes);
                        return;
                    }
                }

                if (callback) callback(connect_error::SUCCESS, bytesWritten);

            });
        }

        void TcpConnection::send(const ByteBuffer &buf)
        {
            WITH_LOG_ENTRYEXIT
            (
                dout << "SYNC SEND:" << (int)p_->mode() << " BYTES: " << buf.size() << endl;
            )

            if (!p_->m_sslStrand.get_io_service().stopped())
            {
                promise<void> sentPromise;
                future<void> sentFuture = sentPromise.get_future();

                p_->m_sslStrand.dispatch([this, &buf, &sentFuture, &sentPromise]()
                {
                    promise<void> localSentPromise = move(sentPromise);

                    asio::error_code ec;
                    size_t bytesSent = 0;
                    switch (p_->mode())
                    {
                        case TcpConnectionImpl::TLSMode::PreNegotiation:
                            bytesSent = p_->m_socket.send(buffer((const void *)buf, buf.size()), 0, ec);
                            break;
                        case TcpConnectionImpl::TLSMode::Negotiated:
                            bytesSent = asio::write(p_->m_sslSocket, buffer((const void *)buf, buf.size()),
                                                    ec);
                            break;
                        default:
                            break;
                    }
                    (void) bytesSent;
                    if (ec)
                    {
                        throw connect_error(ec);
                    }
                    localSentPromise.set_value();
                });
                sentFuture.get();
            }

            WITH_LOG_ENTRYEXIT
            (
                dout << "SYNC SEND END" << endl;
            )
        }

        size_t TcpConnection::receive(ByteBuffer &buf, asio::error_code &ec)
        {
            WITH_LOG_ENTRYEXIT
            (
                dout << "SYNC RECEIVE: " << (int)p_->mode() << endl;
            )

            size_t bytesReceived = 0;
            if (!p_->m_sslStrand.get_io_service().stopped())
            {
                promise<void> receivedPromise;
                future<void> receivedFuture = receivedPromise.get_future();

                p_->m_sslStrand.dispatch([this, &buf, &ec, &bytesReceived, &receivedPromise]()
                {
                    promise<void> localReceivedPromise = move(receivedPromise);
                    switch (p_->mode())
                    {
                        case TcpConnectionImpl::TLSMode::PreNegotiation:
                            bytesReceived = p_->m_socket.receive(buffer((void *)buf, buf.size()), 0, ec);
                            break;
                        case TcpConnectionImpl::TLSMode::Negotiated:
                            bytesReceived = p_->m_sslSocket.read_some(buffer((void *)buf, buf.size()), ec);
                            break;
                        default:
                            break;
                    }

                    if (ec == asio::error::operation_aborted)
                    {
                        p_->m_sslSocket.shutdown();
                    }
                    localReceivedPromise.set_value();
                });

                receivedFuture.get();
            }
            WITH_LOG_ENTRYEXIT
            (
                dout << "SYNC RECEIVE END" << endl;
            )

            return bytesReceived;
        }

        void TcpConnection::async_receive(shared_ptr<ByteBuffer> tempBuffer,
                                          ReceiveCallback callback)
        {
            WITH_LOG_ENTRYEXIT
            (
                dout << "ASYNC RECEIVE: " << (int)p_->mode() << endl;
            )

            if (p_->mode() == TcpConnectionImpl::TLSMode::InNegotation)
            {
                if (callback)
                {
                    callback(connect_error::ecTLSNegotiationInProgress, 0);
                }
            }
            if (tempBuffer)
            {
                if (!p_->m_sslStrand.get_io_service().stopped())
                {
                    p_->m_sslStrand.dispatch([this, callback, tempBuffer]()
                    {
                        switch (p_->mode())
                        {
                            case TcpConnectionImpl::TLSMode::PreNegotiation:
                                if (p_->m_inPreNegotationRead == 0)
                                {
                                    ++p_->m_inPreNegotationRead;
                                    p_->m_socket.async_read_some(buffer((void *)*tempBuffer, tempBuffer->size()),
                                                                 [this, callback, tempBuffer](const asio::error_code & ec, size_t bytes)
                                    {
                                        --p_->m_inPreNegotationRead;
                                        WITH_LOG_ENTRYEXIT
                                        (
                                            dout << "ASYNC BYTES READ: " << bytes << endl;
                                        )

                                        if (callback) callback(connect_error(ec), bytes);
                                    });
                                }
                                break;
                            case TcpConnectionImpl::TLSMode::Negotiated:
                                if (p_->m_sslSocket.next_layer().is_open())
                                {
                                    p_->m_sslSocket.async_read_some(buffer((void *)*tempBuffer, tempBuffer->size()),
                                                                    [this, callback, tempBuffer](const asio::error_code & ec, size_t bytes)
                                    {
                                        WITH_LOG_ENTRYEXIT
                                        (
                                            dout << "ASYNC NEGOTIATED BYTES READ: " << bytes << endl;
                                        )

                                        asio::error_code code = ec;
                                        if (code == asio::error::operation_aborted)
                                        {
                                            p_->m_sslSocket.shutdown(code);
                                        }
                                        if (callback) callback(connect_error(code), bytes);
                                    });
                                }
                                else
                                {
                                    if (callback) callback(connect_error::ecSocketClosed, 0);
                                }
                                break;
                            default:
                                break;
                        }
                    });
                }
                else
                {
                    if (callback) callback(connect_error::ecSocketClosed, 0);
                }
            }
            else
            {
                if (callback)
                {
                    callback(connect_error(LocalError(LocalError::ecInvalidParameter)), 0);
                }
            }
        }

        void TcpConnection::async_send(shared_ptr<ByteBuffer> tempBuffer,
                                       SendCallback callback)
        {
            WITH_LOG_ENTRYEXIT
            (
                dout << "ASYNC SEND:" << (int)p_->mode() << endl;
            )

            if (tempBuffer)
            {
                if (!p_->m_sslStrand.get_io_service().stopped())
                {
                    p_->m_sslStrand.dispatch([this, callback, tempBuffer]()
                    {
                        switch (p_->mode())
                        {
                            case TcpConnectionImpl::TLSMode::PreNegotiation:
                                p_->m_socket.async_send(buffer((void *)*tempBuffer, tempBuffer->size()),
                                                        [callback, tempBuffer](const asio::error_code & ec, size_t bytes)
                                {
                                    WITH_LOG_ENTRYEXIT
                                    (
                                        dout << "ASYNC BYTES Sent: " << bytes << endl;
                                    )

                                    if (callback) callback(connect_error(ec), bytes);
                                });
                                break;
                            case TcpConnectionImpl::TLSMode::Negotiated:
                                if (p_->m_sslSocket.next_layer().is_open())
                                {
                                    ssl_write_all(p_->m_sslSocket, tempBuffer, callback);
                                }
                                else
                                {
                                    if (callback) callback(connect_error::ecSocketClosed, 0);
                                }
                                break;
                            default:
                                break;
                        }
                    });
                }
                else
                {
                    if (callback) callback(connect_error::ecSocketClosed, 0);
                }
            }
            else
            {
                if (callback)
                {
                    callback(connect_error(LocalError(LocalError::ecInvalidParameter)), 0);
                }
            }
            WITH_LOG_ENTRYEXIT
            (
                dout << "ASYNC SEND END" << endl;
            )
        }

        void TcpConnection::negotiateTLS(TLSCallback callback)
        {
            WITH_LOG_ENTRYEXIT
            (
                dout << "NEGOTIATE TLS: " << (int)p_->mode() << endl;
            )
            p_->setMode(TcpConnectionImpl::TLSMode::InNegotation);
            WITH_LOG_ENTRYEXIT
            (
                dout << "NEGOTIATE TLS: " << (int)p_->mode() << endl;
            )

            p_->m_sslStrand.post([this, callback]()
            {
                WITH_LOG_ENTRYEXIT
                (
                    dout << "TLS READY HANDSHAKE" << endl;
                )

                //p_->m_sslStrand.wrap();

                asio::error_code e;
                p_->m_sslSocket.handshake(ssl::stream_base::client, e);

                if (e)
                {
                    WITH_LOG_ERRORS
                    (
                        dout << "SSL Negotiation Error " << e << endl;
                    )
                }
                p_->setMode(e ? TcpConnectionImpl::TLSMode::PreNegotiation :
                            TcpConnectionImpl::TLSMode::Negotiated);

                WITH_LOG_ENTRYEXIT
                (
                    dout << "TLS HANDSHAKE COMPLETE" << endl;
                )

                if (callback) callback(connect_error(e));

                WITH_LOG_ENTRYEXIT
                (
                    dout << "TLS REAdY HANDSHAKE END" << endl;
                )
            });
            WITH_LOG_ENTRYEXIT
            (
                dout << "NEGOTIATE TLS END" << endl;
            )
        }

        asio::ip::tcp::socket &TcpConnection::socket() const
        {
            return p_->m_sslSocket.next_layer();
        }
    }
}

#endif // DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
