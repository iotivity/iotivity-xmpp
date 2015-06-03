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

/// @file ra_xmpp.h

/// @defgroup RA RA (Remote Access) XMPP Abstraction Layer

#pragma once
#ifndef RA_XMPP_H__
#define RA_XMPP_H__

#include <stdlib.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C"
{
#endif


/// @addtogroup RA
/// @{

/// @brief The handle to an XMPP client instance.
typedef struct
{
    /// The underlying handle value. May be compared with NULL to test validity.
    const void     *abstract_handle;
} xmpp_handle_t;

/// @brief The handle to an initiating or active client connection to an XMPP server.
typedef struct
{
    /// The underlying handle value. May be compared with NULL to test validity.
    const void     *abstract_connection;
} xmpp_connection_handle_t;


/// @cond HIDDEN_SYMBOLS
typedef enum xmpp_status
{
    XMPP_UP,
    XMPP_DOWN
} xmpp_status_t;
/// @endcond


/// Error codes returned by the RA XMPP client wrapper library.
typedef enum xmpp_error_code
{
    XMPP_ERR_OK = 0,                    ///> Not an error. Returned on success.


    XMPP_ERR_CLIENT_DISCONNECTED = -1,  ///> Disconnected from an XMPP server successfully.
    ///> XMPP client initiated the disconnect.
    XMPP_ERR_SERVER_DISCONNECTED = -2,  ///> XMPP server disconnected successfully.
    ///> XMPP server initiated the disconnect or the
    ///> connection dropped.


    XMPP_ERR_FAIL = 1,                  ///> Default error. Generally indicates a coding error.
    XMPP_ERR_HOST_CONNECTION_FAILED,    ///> Connection to XMPP remote host failed.
    XMPP_ERR_STREAM_NOT_NEGOTIATED,     ///> Connection to host okay, but stream negotation failed

    XMPP_ERR_INTERNAL_ERROR,            ///> Internal error. Generally indicates non-recoverable error.
    XMPP_ERR_FEATURE_NOT_SUPPORTED,     ///> Request to use XMPP feature not supported by the stack.
    XMPP_ERR_BOSH_ERROR,                    ///> Error establishing BOSH connection
    XMPP_ERR_CONNECT_ERROR,                 ///> Error establishing XMPP connection
    XMPP_ERR_PROXY_CONNECT_ERROR,           ///> Error establishing proxy connection

    XMPP_ERR_AUTHENTICATION_FAILED,     ///> Authentication with the server failed.
    XMPP_ERR_TLS_NEGOTIATION_FAILED,    ///> TLS negotation with the server failed.
    XMPP_ERR_SASL_NEGOTIATION_FAILED,   ///> SASL negotation with the server failed.

    XMPP_ERR_INVALID_HANDLE,            ///> Invalid handle was passed to the interface.
    XMPP_ERR_INVALID_PARAMETER,         ///> Invalid parameter was passed to the interface.
    XMPP_ERR_INVALID_SERVER_STANZA,     ///> An XMPP stanza was received from the server which could not be parsed.

    XMPP_ERR_STREAM_CLOSING_NOT_AVAILABLE, ///> Stream is closing, extension feature is not available.
    XMPP_ERR_STREAM_ALREADY_CLOSED,     ///> Stream is already closed or closing.

    XMPP_ERR_REQUEST_ERROR_RESPONSE,    ///> Error received as a response from an XMPP request.

    XMPP_ERR_BOSH_NO_SUPPORT,           ///> Request to connect to a BOSH connection with no BOSH support.

    XMPP_ERR_INBAND_REGISTRATION_NO_SUPPORT,  ///> Request to do registration failed. Feature not supported.
    XMPP_ERR_INBAND_REGISTRATION_FAILURE,   ///> Attempt to perform in-band registration failed.

    XMPP_ERR_INVALID_MESSAGE_FORMAT,    ///> Message received from the server is in an unknown format.

} xmpp_error_code_t;


///////////////////////////////////////////////////////////////////////////////////////////////////
// Callback type declarations
///////////////////////////////////////////////////////////////////////////////////////////////////

/// Logging callback definition. (TBD) Not implemented at this time.
typedef void (* xmpp_log_func_t)(void *const param);

/// XMPP status function definition. (TBD) Not implemented at this time.
typedef void (* xmpp_status_func_t)(xmpp_status_t status);

/// @brief Callback called when a client connection is established to an XMPP server or an
/// attempt to establish a client connection fails.
///
/// @param param The pointer passed into the callback through xmpp_connection_callback_t param parameter.
/// @param result The result of the connection attempt. If result is XMPP_ERR_OK, the connection
///               handle will be a valid handle representing the client connection, otherwise
///               the connection handle will be NULL.
/// @param connection The handle representing the connection or NULL if the connection attempt
///                   failed. If multiple connection attemptes are running in parallel,
///                   parameterize on param to provide context describing which connection
///                   attempt's status is being signalled.
typedef void (* xmpp_connected_func_t)(void *const param, xmpp_error_code_t result,
                                       xmpp_connection_handle_t connection);

/// @brief Callback called when an existing client connection to an XMPP server is disconnected from
/// the server side or client side or drops.
///
/// @param param The pointer passed into the callback through xmpp_connection_callback_t parameter.
/// @param result Any error code which resulted in the disconnect occurring or one of
///               XMPP_ERR_OK, XMPP_ERR_CLIENT_DISCONNECTED or XMPP_ERR_SERVER_DISCONNECTED.
/// @param connection The handle to the connection that was disconnected. This connection handle
///                   will have been returned through a call to the xmpp_connected_func_t callback
///                   before the disconnected callback will occur.
typedef void (* xmpp_disconnected_func_t)(void *const param, xmpp_error_code_t result,
        xmpp_connection_handle_t connection);

///////////////////////////////////////////////////////////////////////////////////////////////////
// Callback closure declarations
///////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct xmpp_log_callback
{
    xmpp_log_func_t       on_log;
    void                 *param;
} xmpp_log_callback_t;


/// @brief Structure containing the callbacks and closure parameter for connecting and disconnected
///        an XMPP client connection to an XMPP server.
typedef struct xmpp_connection_callback
{
    /// Pointer to the function called when a connection attempt to an XMPP server either
    //  succeeds or fails.
    /// @note on_connected may be NULL only if the established connection never needs to be
    ///       explicitly closed. Access to the connection handle is through the on_connected
    ///       callback.
    xmpp_connected_func_t       on_connected;
    /// Pointer to the function called when an established connection drops or is explicitly
    /// disconnected.
    /// @note on_disconnected may be NULL if the caller does not care if the connection drops.
    xmpp_disconnected_func_t    on_disconnected;
    /// @brief The parameter passed back to on_connected and on_disconnected.
    void                       *param;
} xmpp_connection_callback_t;




///////////////////////////////////////////////////////////////////////////////////////////////////
// Support structures and init/destroy functions.
///////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct xmpp_context
{
    size_t                          cb;
    const xmpp_log_callback_t      *log_callback;
} xmpp_context_t;


/// @brief Initialize the context object used to configure the RA XMPP client interface.
///
/// xmpp_context_destroy must be called on the context object before program termination
/// but may be called any time after xmpp_context_t is used to initialize the XMPP client.
/// @param context Pointer to the xmpp_context_t structure to initialize.
void xmpp_context_init(xmpp_context_t *const context);

/// @brief Destroy the XMPP context object and clean up any resources reserved for it.
/// @param context Pointer to the xmpp_context_t structure to destroy.
void xmpp_context_destroy(xmpp_context_t *context);



/// The supported protocols used by the XMPP client abstraction. Not all underlying client
/// client implementations will necessarily support all protocols.
typedef enum xmpp_protocol
{
    /// XMPP direct connection (XML Stanza Stream).
    XMPP_PROTOCOL_XMPP = 0,
    /// XMPP through BOSH (HTTP Post Stanza Stream).
    XMPP_PROTOCOL_BOSH
} xmpp_protocol_t;

/// @brief The structure containing the properties describing the host address and XMPP domain of
/// a remote XMPP server connection.
///
/// It is recommended that xmpp_host_init be used instead of directly assigning the
/// parameters to the structure in case the allocation of the parameters must be controlled by
/// the underlying library.
typedef struct xmpp_host
{
    /// Size of the xmpp_host_t structure in octets.
    size_t                  cb;
    /// Pointer to a NULL-terminated string containing the host name of the remote XMPP server.
    char                   *host;
    /// IP port on the host server to which the client will connect.
    uint16_t                port;
    /// The XMPP domain name of the server to which the connection is to be established.
    char                   *xmpp_domain;
    /// The protocol being used to connect with the server.
    xmpp_protocol_t         protocol;
} xmpp_host_t;

/// @brief Initialize the structure containing information on the XMPP remote host address, domain
/// and protocol.
///
/// xmpp_host_destroy must be called on the host pointer before progranm termination
/// but may be called at any time after xmpp_host_t is used to initiate a connection to a remote
/// XMPP server.
/// @param host A pointer to the structure containing information about the host. The structure
///             will be initialized by the xmpp_host_init call.
/// @param host_name The NULL-terminated string containing the host name of the remote XMPP
///                  server as it would appear in a DNS host name resolution request.
/// @param port The 16-bit IP port on the host server to which the XMPP client will attempt to
///             connect.
/// @param xmpp_domain The XMPP domain name of the server to which the connection is to be
///                    established. In general the xmpp_domain must match the domain of the
///                    JID of the user that a connection is being establised on behalf of
///                    (e.g. "user_name@xmpp_domain").
/// @param protocol The protocol being used to communicate with the XMPP server. The host_name
///                 may need to be modified in order to support certain protocols (e.g. BOSH).
void xmpp_host_init(xmpp_host_t *const host, const char *const host_name,
                    uint16_t port, const char *const xmpp_domain,
                    xmpp_protocol_t protocol);

/// @brief Destroy the XMPP host object and clean up any resources reserved for it.
///
/// Do not use the pointer to host in a subsequent call to an xmpp client function after calling
/// xmpp_host_destroy. It is the responsibility of the caller to free any memory reserved to store
/// the xmpp_host_t structure.
///
/// @param host A pointer to the structure initialized by calling xmpp_host_init.
void xmpp_host_destroy(xmpp_host_t *host);


typedef enum InBandRegister
{
    XMPP_NO_IN_BAND_REGISTER,
    XMPP_TRY_IN_BAND_REGISTER,
    XMPP_REQUIRE_IN_BAND_REGISTER,
} InBandRegister_t;

typedef struct xmpp_identity
{
    size_t              cb;
    char               *user_name;
    char               *password;

    char               *user_jid;

    InBandRegister_t    inband_registration;
} xmpp_identity_t;

/// @brief Initialize the structure containing information on the XMPP client user identity.
///
/// xmpp_identity_destroy must be called on the identity pointer before progranm termination
/// but may be called at any time after xmpp_identity_t is used in intiating a connection to a
/// remote XMPP server.
///
/// @param identity A pointer to the structure containing information about the user. The structure
///                 will be initialized by the xmpp_identity_init call.
/// @param user_name A NULL-terminated string containing the UTF-8 encoded user name of the user
///                  logging in to the XMPP server. This is generally the first part of the user
///                  JID ("user_name@xmpp_domain/resource").
/// @param password A NULL-terminated string containing the UTF-8 password of the user logging
///                 in to the XMPP server. It is important to note that code points prohibited
///                 by the XMPP SASL specification may be removed from the string if passed
///                 in as part of the passsword (see XMPP SaslPrep for details).
/// @param user_jid The JID of the user (without resource) establishing a connection the XMPP
///                 server.
/// @param inband_register Determine whether to attempt in-band registration of the user-name
///                        and password where the client and the server supports it. Unless
///                        the server configuration is known to support in-band registration
///                        and the build of the client includes it, XMPP_NO_IN_BAND_REGISTER
///                        should be used preferentially.
void xmpp_identity_init(xmpp_identity_t *const identity, const char *const user_name,
                        const char *const password, const char *const user_jid,
                        InBandRegister_t inband_register);

/// @brief Destroy the XMPP client identity object and clean up any resources reserved for it.
///
/// @param identity A pointer to the structure initialized by calling xmpp_identity_init.
void xmpp_identity_destroy(xmpp_identity_t *identity);


typedef enum xmpp_proxy_type
{
    XMPP_PROXY_DIRECT_CONNECT = 0,
    XMPP_PROXY_SOCKS5
} xmpp_proxy_type_t;

typedef struct xmpp_proxy
{
    size_t                  cb;
    xmpp_proxy_type_t       proxy_type;
    char                   *proxy_host;
    uint16_t                proxy_port;
} xmpp_proxy_t;

void xmpp_proxy_init(xmpp_proxy_t *const proxy, const char *const host, uint16_t port,
                     xmpp_proxy_type_t proxy_type);

/// Destroy the XMPP proxy configuration object and clean up any resources reserved for it.
void xmpp_proxy_destroy(xmpp_proxy_t *proxy);



///////////////////////////////////////////////////////////////////////////////////////////////////
// Library function declarations.
///////////////////////////////////////////////////////////////////////////////////////////////////
// TODO: Get version (Check Version?)

/// @brief Start the xmpp client given a context containing any global settings required for the
/// instance.
///
/// It is recommended that multiple xmpp_startup calls not be made unless it is
/// known that the underlying implementation supports multiple simultaneous instances.
/// @param context Pointer to the initialized context containing any global settings (e.g.
///                logging configuration).
/// @return A handle to the xmpp client instance. This handle should be used when initiating
///         any subsequent client connections to the server.
xmpp_handle_t xmpp_startup(const xmpp_context_t *const context);

/// @brief Shut down the xmpp client library instance given the handle returned from xmpp_startup.
///
/// Once shutdown is called, all extant client connections will disconnect. It is recommended
/// that either shutdown be called in a context where the disconnect callbacks can still occur
/// or that xmpp_close be called for all connections prior to calling xmpp_shutdown_xmpp.
/// @note xmpp_shutdown_xmpp is not named xmpp_shutdown due to a name conflict with one of
///       the supported xmpp client libraries.
void xmpp_shutdown_xmpp(xmpp_handle_t handle);

/// @cond HIDDEN_SYMBOLS
// TEST-only function to verify that shutdown will not leak resources.
int xmpp_global_shutdown_okay(void);
/// @endcond


/// @brief Initiates a direct client connection to a remote xmpp server given the host configuration,
/// and the identity of the connecting user.
///
/// @param handle The handle to the XMPP client instance as returned by xmpp_startup. After
///               calling xmpp_shutdown_xmpp on this handle, the behavior of xmpp_connect
///               when called with this handle is undefined.
/// @param host A pointer to the initialized host data structure containing the remote address
///             of the XMPP server and its XMPP domain.
/// @param identity A pointer to the initialized identity structure containing the identity
///                 of the user connecting to the XMPP server.
/// @param callback An xmpp_connection_callback_t containing pointers to the callbacks functions
///                 to call when the connection attempt succeeds or fails or when an established
///                 connection disconnects. If multiple connections need to be made, it is
///                 recommended that the callback.param parameter be different for each.
/// @return An error code indicating whether the connection request could be initiated. If
///         XMPP_ERR_OK is returned, the callback will eventually be called with the result
///         (success or fail) of the connection attempt.
xmpp_error_code_t xmpp_connect(xmpp_handle_t handle, const xmpp_host_t *const host,
                               const xmpp_identity_t *const identity,
                               xmpp_connection_callback_t callback);

/// @brief Initiates a proxied client connection to a remote xmpp server given the host
/// configuration, and the identity of the connecting user.
///
/// @param handle The handle to the XMPP client instance as returned by xmpp_startup. After
///               calling xmpp_shutdown_xmpp on this handle, the behavior of xmpp_connect
///               when called with this handle is undefined.
/// @param host A pointer to the initialized host data structure containing the remote address
///             of the XMPP server and its XMPP domain.
/// @param identity A pointer to the initialized identity structure containing the identity
///                 of the user connecting to the XMPP server.
/// @param proxy A pointer to the initialzied identity structure containing the address of the
///              proxy through which the XMPP server may be reached. Not all XMPP client
///              implementations will support all proxy types.
/// @param callback An xmpp_connection_callback_t containing pointers to the callbacks functions
///                 to call when the connection attempt succeeds or fails or when an established
///                 connection disconnects. If multiple connections need to be made, it is
///                 recommended that the callback.param parameter be different for each.
/// @return An error code indicating whether the connection request could be initiated. If
///         XMPP_ERR_OK is returned, the callback will eventually be called with the result
///         (success or fail) of the connection attempt.
xmpp_error_code_t xmpp_connect_with_proxy(xmpp_handle_t handle, const xmpp_host_t *const host,
        const xmpp_identity_t *const identity,
        const xmpp_proxy_t *const proxy,
        xmpp_connection_callback_t callback);

// TODO: Add support-check

/// @brief Closes an XMPP client connection to an XMPP server opened with a call to
///        xmpp_connect or xmpp_connect_with_proxy.
///
/// @param connection The handle to the XMPP client to server connection as returned in the
///                   connection callback as passed the xmpp_connect or xmpp_connect_with_proxy
///                   call.
//// @return An error code indicating whether the closing the xmpp connection could be initiated.
///          xmpp_close may fail if the connection is already closed. If a disconnect callback
///          was registered with xmpp_connect or xmpp_connect_with_proxy, disconnect will be
///          called some time after xmpp_close is called, presuming that XMPP_ERR_OK is returned
///          from xmpp_close.
xmpp_error_code_t xmpp_close(xmpp_connection_handle_t connection);





///////////////////////////////////////////////////////////////////////////////////////////////////
// Message Transmission/Receipt
///////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct
{
    const void   *abstract_context;
} xmpp_message_context_t;

typedef void (* xmpp_message_sent_func_t)(void *const param, xmpp_error_code_t result,
        const void *const toRecipient,
        const void *const msg, size_t messageOctets);
typedef void (* xmpp_message_recv_func_t)(void *const param, xmpp_error_code_t result,
        const void *const fromSender,
        const void *const msg, size_t messageOctets);

typedef struct xmpp_message_callback
{
    xmpp_message_sent_func_t    on_sent;
    xmpp_message_recv_func_t    on_received;
    void                       *param;
} xmpp_message_callback_t;


typedef enum xmpp_transmission_options
{
    XMPP_MESSAGE_TRANSMIT_DEFAULT = 0x0
} xmpp_transmission_options_t;


/// @brief Register a message context to send outgoing and receive incoming messages for an
///        established XMPP client connection.
///
xmpp_message_context_t xmpp_message_context_create(xmpp_connection_handle_t connection,
        xmpp_message_callback_t callback);

/// @brief Send a byte blob to a remote client with a known user JID (recipient).
///
xmpp_error_code_t xmpp_send_message(xmpp_message_context_t ctx, const char *const recipient,
                                    const void *const message, const size_t messageOctets,
                                    xmpp_transmission_options_t options);

/// @brief Destroy the XMPP message context object and clean up any resources reserved for it.
void xmpp_message_context_destroy(xmpp_message_context_t ctx);


/// @}


#ifdef __cplusplus
}
#endif

#endif // RA_XMPP_H__