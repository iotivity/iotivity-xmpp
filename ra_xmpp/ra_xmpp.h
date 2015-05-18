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


#ifndef XMPP_LIB_

/// @note XMPP_LIB_ is provided to enable rough support for a C++-like namespace.
///       Define this to a value other than 'xmpp_' to change the names of the library functions.
///
#define XMPP_LIB_(x) xmpp_##x
#endif


#ifdef __cplusplus
extern "C"
{
#endif


typedef struct
{
    const void     *abstract_handle;
} XMPP_LIB_(handle_t);

typedef struct
{
    const void     *abstract_connection;
} XMPP_LIB_(connection_handle_t);

typedef enum XMPP_LIB_(status)
{
    XMPP_UP,
    XMPP_DOWN
} XMPP_LIB_(status_t);


typedef enum XMPP_LIB_(error_code)
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

    XMPP_ERR_IBB_NO_SUPPORT,
    XMPP_ERR_IBB_CLOSED_LOCAL,
    XMPP_ERR_IBB_CLOSED_REMOTE
} XMPP_LIB_(error_code_t);


///////////////////////////////////////////////////////////////////////////////////////////////////
// Callback type declarations
///////////////////////////////////////////////////////////////////////////////////////////////////
typedef void (* XMPP_LIB_(log_func_t))(void *const param);  // TBD
typedef void (* XMPP_LIB_(status_func_t))(XMPP_LIB_(status_t) status);
typedef void (* XMPP_LIB_(connected_func_t))(void *const param, XMPP_LIB_(error_code_t) result,
        XMPP_LIB_(connection_handle_t) connection);
typedef void (* XMPP_LIB_(disconnected_func_t))(void *const param, XMPP_LIB_(error_code_t) result,
        XMPP_LIB_(connection_handle_t) connection);

///////////////////////////////////////////////////////////////////////////////////////////////////
// Callback closure declarations
///////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct XMPP_LIB_(log_callback)
{
    XMPP_LIB_(log_func_t) on_log;
    void                 *param;
} XMPP_LIB_(log_callback_t);


typedef struct XMPP_LIB_(connection_callback)
{
    XMPP_LIB_(connected_func_t)     on_connected;
    XMPP_LIB_(disconnected_func_t)  on_disconnected;
    void                           *param;
} XMPP_LIB_(connection_callback_t);




///////////////////////////////////////////////////////////////////////////////////////////////////
// Support structures and init/destroy functions.
///////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct XMPP_LIB_(context)
{
    size_t                              cb;
    const XMPP_LIB_(log_callback_t) *   log_callback;
} XMPP_LIB_(context_t);


void XMPP_LIB_(context_init)(XMPP_LIB_(context_t) * const context);
void XMPP_LIB_(context_destroy)(XMPP_LIB_(context_t) *context);



typedef enum XMPP_LIB_(protocol)
{
    XMPP_PROTOCOL_XMPP = 0,
    XMPP_PROTOCOL_BOSH
} XMPP_LIB_(protocol_t);

typedef struct XMPP_LIB_(host)
{
    size_t                  cb;
    char                   *host;
    uint16_t                port;
    char                   *xmpp_domain;
    XMPP_LIB_(protocol_t)   protocol;
} XMPP_LIB_(host_t);

void XMPP_LIB_(host_init)(XMPP_LIB_(host_t) * const host, const char *const host_name,
                          uint16_t port, const char *const xmpp_domain,
                          XMPP_LIB_(protocol_t) protocol);
void XMPP_LIB_(host_destroy)(XMPP_LIB_(host_t) *host);


typedef enum InBandRegister
{
    XMPP_NO_IN_BAND_REGISTER,
    XMPP_TRY_IN_BAND_REGISTER,
    XMPP_REQUIRE_IN_BAND_REGISTER,
} InBandRegister_t;

typedef struct XMPP_LIB_(identity)
{
    size_t              cb;
    char               *user_name;
    char               *password;

    char               *user_jid;

    InBandRegister_t    inband_registration;
} XMPP_LIB_(identity_t);

void XMPP_LIB_(identity_init)(XMPP_LIB_(identity_t) * const identity, const char *const user_name,
                              const char *const password, const char *const user_jid,
                              InBandRegister_t inband_register);
void XMPP_LIB_(identity_destroy)(XMPP_LIB_(identity_t) *identity);


typedef enum XMPP_LIB_(proxy_type)
{
    XMPP_PROXY_DIRECT_CONNECT = 0,
    XMPP_PROXY_SOCKS5
} XMPP_LIB_(proxy_type_t);

typedef struct XMPP_LIB_(proxy)
{
    size_t                  cb;
    XMPP_LIB_(proxy_type_t) proxy_type;
    char                   *proxy_host;
    uint16_t                proxy_port;
} XMPP_LIB_(proxy_t);

void XMPP_LIB_(proxy_init)(XMPP_LIB_(proxy_t) * const proxy, const char *const host, uint16_t port,
                           XMPP_LIB_(proxy_type_t) proxy_type);
void XMPP_LIB_(proxy_destroy)(XMPP_LIB_(proxy_t) * proxy);



///////////////////////////////////////////////////////////////////////////////////////////////////
// Library function declarations.
///////////////////////////////////////////////////////////////////////////////////////////////////
// TODO: Get version (Check Version?)

XMPP_LIB_(handle_t) XMPP_LIB_(startup)(const XMPP_LIB_(context_t) * const context);

void XMPP_LIB_(shutdown)(XMPP_LIB_(handle_t) handle);

// TEST-only function to verify that shutdown will not leak resources.
int XMPP_LIB_(global_shutdown_okay)(void);


XMPP_LIB_(error_code_t) XMPP_LIB_(connect)(XMPP_LIB_(handle_t) handle,
        const XMPP_LIB_(host_t )* const host,
        const XMPP_LIB_(identity_t) * const identity,
        XMPP_LIB_(connection_callback_t) callback);

XMPP_LIB_(error_code_t) XMPP_LIB_(connect_with_proxy)(XMPP_LIB_(handle_t) handle,
        const XMPP_LIB_(host_t) * const host,
        const XMPP_LIB_(identity_t) * const identity,
        const XMPP_LIB_(proxy_t) * const proxy,
        XMPP_LIB_(connection_callback_t) callback);

// TODO: Add support-check

XMPP_LIB_(error_code_t) XMPP_LIB_(close)(XMPP_LIB_(connection_handle_t) connection);





///////////////////////////////////////////////////////////////////////////////////////////////////
// Message Transmission/Receipt
///////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct
{
    const void   *abstract_context;
} XMPP_LIB_(message_context_t);

typedef void (* XMPP_LIB_(message_sent_func_t))(void *const param, XMPP_LIB_(error_code_t) result,
        const void *const toRecipient,
        const void *const msg, size_t messageOctets);
typedef void (* XMPP_LIB_(message_recv_func_t))(void *const param, XMPP_LIB_(error_code_t) result,
        const void *const fromSender,
        const void *const msg, size_t messageOctets);

typedef struct XMPP_LIB_(message_callback)
{
    XMPP_LIB_(message_sent_func_t)  on_sent;
    XMPP_LIB_(message_recv_func_t)  on_received;
    void                           *param;
} XMPP_LIB_(message_callback_t);


typedef enum XMPP_LIB_(transmission_options)
{
    XMPP_MESSAGE_TRANSMIT_DEFAULT = 0x0
} XMPP_LIB_(transmission_options_t);


XMPP_LIB_(message_context_t) XMPP_LIB_(message_context_create)(
    XMPP_LIB_(connection_handle_t) connection,
    XMPP_LIB_(message_callback_t) callback);

XMPP_LIB_(error_code_t) XMPP_LIB_(send_message)(XMPP_LIB_(message_context_t) ctx,
        const char *const recipient,
        const void *const message,
        const size_t messageOctets,
        XMPP_LIB_(transmission_options_t) options);

void XMPP_LIB_(message_context_destroy)(XMPP_LIB_(message_context_t) ctx);

#ifdef __cplusplus
}
#endif

#endif // RA_XMPP_H__