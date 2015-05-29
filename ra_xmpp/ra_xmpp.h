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

#pragma once
#ifndef RA_XMPP_H__
#define RA_XMPP_H__

#include <stdlib.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C"
{
#endif


typedef struct
{
    const void     *abstract_handle;
} xmpp_handle_t;

typedef struct
{
    const void     *abstract_connection;
} xmpp_connection_handle_t;

typedef enum xmpp_status
{
    XMPP_UP,
    XMPP_DOWN
} xmpp_status_t;


typedef enum xmpp_error_code
{
    XMPP_ERR_OK = 0,

    XMPP_ERR_CLIENT_DISCONNECTED = -1,
    XMPP_ERR_SERVER_DISCONNECTED = -2,

    XMPP_ERR_FAIL = 1,                      ///> Default error. Generally indicates a coding error.
    XMPP_ERR_HOST_CONNECTION_FAILED,
    XMPP_ERR_STREAM_NOT_NEGOTIATED,

    XMPP_ERR_INTERNAL_ERROR,
    XMPP_ERR_FEATURE_NOT_SUPPORTED,
    XMPP_ERR_BOSH_ERROR,                    ///> Error establishing BOSH connection
    XMPP_ERR_CONNECT_ERROR,                 ///> Error establishing XMPP connection
    XMPP_ERR_PROXY_CONNECT_ERROR,           ///> Error establishing proxy connection

    XMPP_ERR_AUTHENTICATION_FAILED,
    XMPP_ERR_TLS_NEGOTIATION_FAILED,
    XMPP_ERR_SASL_NEGOTIATION_FAILED,

    XMPP_ERR_INVALID_HANDLE,
    XMPP_ERR_INVALID_PARAMETER,
    XMPP_ERR_INVALID_SERVER_STANZA,

    XMPP_ERR_STREAM_CLOSING_NOT_AVAILABLE,
    XMPP_ERR_STREAM_ALREADY_CLOSED,

    XMPP_ERR_REQUEST_ERROR_RESPONSE,

    XMPP_ERR_BOSH_NO_SUPPORT,

    XMPP_ERR_INBAND_REGISTRATION_NO_SUPPORT,
    XMPP_ERR_INBAND_REGISTRATION_FAILURE,

    XMPP_ERR_INVALID_MESSAGE_FORMAT,

    XMPP_ERR_IBB_NO_SUPPORT,
    XMPP_ERR_IBB_CLOSED_LOCAL,
    XMPP_ERR_IBB_CLOSED_REMOTE
} xmpp_error_code_t;


///////////////////////////////////////////////////////////////////////////////////////////////////
// Callback type declarations
///////////////////////////////////////////////////////////////////////////////////////////////////
typedef void (* xmpp_log_func_t)(void *const param);  // TBD
typedef void (* xmpp_status_func_t)(xmpp_status_t status);
typedef void (* xmpp_connected_func_t)(void *const param, xmpp_error_code_t result,
                                       xmpp_connection_handle_t connection);
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


typedef struct xmpp_connection_callback
{
    xmpp_connected_func_t       on_connected;
    xmpp_disconnected_func_t    on_disconnected;
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


void xmpp_context_init(xmpp_context_t *const context);
void xmpp_context_destroy(xmpp_context_t *context);



typedef enum xmpp_protocol
{
    XMPP_PROTOCOL_XMPP = 0,
    XMPP_PROTOCOL_BOSH
} xmpp_protocol_t;

typedef struct xmpp_host
{
    size_t                  cb;
    char                   *host;
    uint16_t                port;
    char                   *xmpp_domain;
    xmpp_protocol_t         protocol;
} xmpp_host_t;

void xmpp_host_init(xmpp_host_t *const host, const char *const host_name,
                    uint16_t port, const char *const xmpp_domain,
                    xmpp_protocol_t protocol);
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

void xmpp_identity_init(xmpp_identity_t *const identity, const char *const user_name,
                        const char *const password, const char *const user_jid,
                        InBandRegister_t inband_register);
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
void xmpp_proxy_destroy(xmpp_proxy_t *proxy);



///////////////////////////////////////////////////////////////////////////////////////////////////
// Library function declarations.
///////////////////////////////////////////////////////////////////////////////////////////////////
// TODO: Get version (Check Version?)

xmpp_handle_t xmpp_startup(const xmpp_context_t *const context);

void xmpp_shutdown_xmpp(xmpp_handle_t handle);

// TEST-only function to verify that shutdown will not leak resources.
int xmpp_global_shutdown_okay(void);


xmpp_error_code_t xmpp_connect(xmpp_handle_t handle, const xmpp_host_t *const host,
                               const xmpp_identity_t *const identity,
                               xmpp_connection_callback_t callback);

xmpp_error_code_t xmpp_connect_with_proxy(xmpp_handle_t handle, const xmpp_host_t *const host,
        const xmpp_identity_t *const identity,
        const xmpp_proxy_t *const proxy,
        xmpp_connection_callback_t callback);

// TODO: Add support-check

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


xmpp_message_context_t xmpp_message_context_create(xmpp_connection_handle_t connection,
        xmpp_message_callback_t callback);

xmpp_error_code_t xmpp_send_message(xmpp_message_context_t ctx, const char *const recipient,
                                    const void *const message, const size_t messageOctets,
                                    xmpp_transmission_options_t options);

void xmpp_message_context_destroy(xmpp_message_context_t ctx);

#ifdef __cplusplus
}
#endif

#endif // RA_XMPP_H__