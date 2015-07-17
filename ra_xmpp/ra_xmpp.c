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

/// @file ra_xmpp.c


/// @mainpage
/// @{
///
/// RA_XMPP is a library providing basic XMPP server connectivity and message-passing providing
/// a cloud-enabled transport for the Iotivity CoAP discovery mechanism.
///
/// RA_XMPP abstracts the choice of XMPP client from the CA layer, hiding the selection of
/// client implementation from the user of the client. Implementation of new client support
/// requires only implementation of the xmpp_wrapper_zzz stub functions and handling of
/// error condititions for any unsupported features.
///
///
/// <ul>
/// <li>\ref RA</li>
/// <li>\ref RA_STUBS</li>
/// </ul>
/// @}

// Required by ra_xmpp.h for the Windows target builds.
#ifdef _WIN32
#include <SDKDDKVer.h>
#endif

#include "ra_xmpp.h"

#include <string.h>
#include <errno.h>

#if !defined(_WIN32)
#ifdef WITH_SAFE
#include <safe_mem_lib.h>
#include <safe_str_lib.h>
#endif
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
errno_t memset_s(void *dest, rsize_t dmax, uint8_t value)
{
    if (value == 0)
    {
        SecureZeroMemory(dest, dmax);
    }
    else
    {
        FillMemory(dest, dmax, value);
    }
    return 0;
}
#endif //__APPLE__


/// @cond HIDDEN_SYMBOLS
typedef struct
{
    xmpp_context_t  *user_context;
    void            *wrapper_handle;
} xmpp_ctx_t;
/// @endcond


///////////////////////////////////////////////////////////////////////////////////////////////////
// Wrapper interface (implementation dependent).
///////////////////////////////////////////////////////////////////////////////////////////////////
/// @defgroup RA_STUBS XMPP Client Wrapper Stub Functions

/// @addtogroup RA_STUBS
/// @{
/// The XMPP Wrapper functions should be implemented within the RA_XMPP library to interface
/// directly to the XMPP client implementation. It is assumed by the library that all of these
/// functions will be thread-safe, so design appropriately.
/// @}


/// @addtogroup RA_STUBS
/// @{

/// @brief Create an xmpp_wrapper_ instance.
///
/// The instance pointer must be cleaned up by xmpp_wrapper_destroy_wrapper. It is recommended
/// that the pointer provided be opaque to the upper RA_XMPP layer.
extern void *const xmpp_wrapper_create_wrapper(void);

/// @brief Clean up an xmpp_wrapper_ instance.
///
/// All wrapper resources, including server connections, must be cleaned up up by this call.
/// @param handle The handle returned by xmpp_wrapper_create_wrapper. It is recommended that
///               the wrapper validate the value of handle, rather than casting it directly
///               to an internal pointer to a client resource.
extern void xmpp_wrapper_destroy_wrapper(void *handle);

/// @brief Initiate an asynchronous connection to an XMPP server.
///
/// @param handle The handle to the XMPP client instance as returned by
///               xmpp_wrapper_create_wrapper.
/// @param host A pointer to the initialized host data structure containing the remote address
///             of the XMPP server and its XMPP domain.
/// @param identity A pointer to the initialized identity structure containing the identity
///                 of the user connecting to the XMPP server.
/// @param proxy A pointer to the initialzied identity structure containing the address of the
///              proxy through which the XMPP server may be reached.
/// @param callback An xmpp_connection_callback_t containing pointers to the callback functions
///                 to call when the connection attempt succeeds or fails or when an established
///                 connection disconnects. If multiple connections need to be made, it is
///                 recommended that the callback.param parameter be different for each.
/// @return An error code indicating whether the connection request could be initiated. If
///         XMPP_ERR_OK is returned, the callback must eventually be called with the result
///         (success or fail) of the connection attempt. If an error code is returned, the
///         callback must not be called.
extern xmpp_error_code_t xmpp_wrapper_connect(void *handle,
        const xmpp_host_t *const host,
        const xmpp_identity_t *const identity,
        const xmpp_proxy_t *const proxy,
        xmpp_connection_callback_t callback);

/// @brief Disconnect an established connection to an XMPP server.
///
/// @param connection The handle to the XMPP client to server connection as returned in the
///                   connection callback as passed the xmpp_wrapper_connect call.
///
//// @return An error code indicating whether the closing of the xmpp connection could be initiated.
///          xmpp_close may fail if the connection is already closed. If a disconnect callback
///          was registered with xmpp_wrapper_connect, disconnect must be called some time after
///          xmpp_close is called, presuming that XMPP_ERR_OK is returned from xmpp_close.
extern xmpp_error_code_t xmpp_wrapper_disconnect(xmpp_connection_handle_t connection);

/// @brief Register the callback for receiving messages from an XMPP client connection.
///
/// @param connection The handle to the XMPP client to server connection as returned in the
///                   connection callback as passed to the xmpp_wrapper_connect call.
/// @param callback An xmpp_message_callback_t containing pointers to the callback functions
///                 to call when a message send succeeds or an incoming message is received.
///                 An optional parameter may be used to parameterize the callback
///                 for multiple registrations on the same connection.
/// @return A handle to a message-wrapper callback context tracking the callback internally
///         for the given connection instance or NULL if no such message callback context
///         could be registered.
///
/// @note The wrapper is expected to perform any transport-specific decoding in order to
///       accept raw data through an XMPP stanza (or stanzas). It is assumed that the decoding
///       step will have occurred prior to the message arriving through the callback.
///       The wrapper must be able to reject messages that cannot be decoded by the wrapper.
///       It is recommended that wrapper not transmit the data payload for any message that
///       would result in transmitting an error code through the callback. It is also acceptable
///       for no callback to occur if the message would otherwise be incorrectly formatted.
/// @note The xmpp_wrapper_register_callback should support the registration of multiple callbacks
///       for the same connection.
///
extern void *xmpp_wrapper_register_message_callback(xmpp_connection_handle_t connection,
        xmpp_message_callback_t callback);

/// @brief Unregister the callback to stop receiving messages from an XMPP client connection.
///
/// @param handle The handle to the message wrapper callback as returned by
///                xmpp_wrapper_register_message_callback.
extern void xmpp_wrapper_unregister_message_callback(void *handle);

/// @brief Send a message through an XMPP client connection to a remote client.
///
/// @param handle The handle to the message wrapper callback as returned by
///                xmpp_wrapper_register_message_callback.
/// @param recipient A NULL-terminated UTF-8 string containing the JID of the remote receipient
///                  being sent the packet.
/// @param message A pointer to a blob of memory to send to the remote recipient. The blob
///                will be formatted by the wrapper layer for transport, but if the blob
///                is larger than the CA MTU, delivery may not be possible and an error result
///                may be sent to the registered send callbacks.
/// @param sizeInOctets The size in bytes of the buffer pointed to by message.
/// @param options Packet-send options and formatting details. For future expansion. Until
///                defined, the passed-in value should be XMPP_MESSAGE_TRANSMIT_DEFAULT.
///
/// @return XMPP_ERR_OK if the message could be queued to be sent. If the message is sent
///         and a callback is registered for sent messages, the callback will be called with
///         the original buffer pointer as the message is sent.
///
/// @note The wrapper is expected to perform any transport-specific encoding in order to
///       send the raw data through an XMPP stanza (or stanzas). It must not be assumed that
///       the message will be well-formed to be transmitted in a stanza without some encoding
///       step. It is expected that all wrappers follow the RA specification for encoding and
///       transmission of the data, however the wrapper specification does not stipulate
///       this format.
extern xmpp_error_code_t xmpp_wrapper_send_message(void *handle,
        const char *const recipient,
        const void *const message,
        const size_t sizeInOctets,
        xmpp_transmission_options_t options);
/// @}


/// @cond HIDDEN_SYMBOLS

///////////////////////////////////////////////////////////////////////////////////////////////////
// Helper functions.
///////////////////////////////////////////////////////////////////////////////////////////////////
int g_master_init_counter = 0;
void inc_master_init_counter()
{
    // TODO: Make ATOMIC
    ++g_master_init_counter;
}

void dec_master_init_counter()
{
    // TODO: Make ATOMIC
    --g_master_init_counter;
}

size_t master_init_counter()
{
    // TODO: Make ATOMIC
    return g_master_init_counter;
}


char *const clone_c_str(const char *const str)
{
    if (str)
    {
        // NOTE: Using strnlen_s is 'better', but we don't really want to limit string lengths
        //       until we truly know the longest string we could support. An initial value
        //       of 64KB is proposed, but needs to be considered carefully.
        // size_t str_len = strnlen_s(str, 65000);      // Slightly less than 64KB
        size_t str_len = strlen(str);
        char *const cloned_str = malloc(str_len + 1);
        if (cloned_str)
        {
            memmove(cloned_str, str, str_len);
            cloned_str[str_len] = 0;

            return cloned_str;
        }
    }
    return (char *const)NULL;
}

void clear_c_str(char *const str)
{
    char *pos = str;
    while (pos && *pos != 0)
    {
        *pos++ = 0;
    }
}

void free_c_str(char *const str)
{
    if (str)
    {
        free(str);
    }
}




///////////////////////////////////////////////////////////////////////////////////////////////////
// Internal library functions.
///////////////////////////////////////////////////////////////////////////////////////////////////
void xmpp_context_init(xmpp_context_t *const context)
{
    if (context)
    {
#if (defined(__STDC_WANT_LIB_EXT1__) && (__STDC_WANT_LIB_EXT1__ >= 1))
        memset_s(context, sizeof (*context), 0, sizeof(*context));
#else
        memset(context, 0, sizeof(*context));
#endif
        context->cb = sizeof(*context);
    }
}

void xmpp_context_destroy(xmpp_context_t *context)
{
}

// This is separated out under the assumption that the context will expand to include
// pointers to heap objects.
xmpp_context_t *clone_context(const xmpp_context_t *context)
{
    xmpp_context_t *cloned_context = calloc(1, sizeof(*context));
    if (cloned_context)
    {
        memmove(cloned_context, context, sizeof(*context));
    }
    return cloned_context;
}


void xmpp_host_init(xmpp_host_t *const host, const char *const host_name,
                    uint16_t port,  const char *const xmpp_domain,
                    xmpp_protocol_t protocol)
{
    if (host)
    {
#if (defined(__STDC_WANT_LIB_EXT1__) && (__STDC_WANT_LIB_EXT1__ >= 1))
        memset_s(host, sizeof(*host), 0, sizeof(*host));
#else
        memset(host, 0, sizeof(*host));
#endif
        host->cb = sizeof(*host);

        host->host = clone_c_str(host_name);
        host->port = port;

        host->xmpp_domain = clone_c_str(xmpp_domain);

        host->protocol = protocol;

        inc_master_init_counter();
    }
}

void xmpp_host_destroy(xmpp_host_t *host)
{
    if (host)
    {
        free_c_str(host->host);
        host->host = NULL;
        free_c_str(host->xmpp_domain);
        host->xmpp_domain = NULL;
        dec_master_init_counter();
    }
}


void xmpp_identity_init(xmpp_identity_t *const identity, const char *const user_name,
                        const char *const password, const char *const user_jid,
                        InBandRegister_t inband_register)
{
    if (identity)
    {
#if (defined(__STDC_WANT_LIB_EXT1__) && (__STDC_WANT_LIB_EXT1__ >= 1))
        memset_s(identity, sizeof (*identity), 0, sizeof(*identity));
#else
        memset(identity, 0, sizeof(*identity));
#endif
        identity->cb = sizeof(*identity);

        identity->user_name = clone_c_str(user_name);
        identity->password = clone_c_str(password);
        identity->user_jid = clone_c_str(user_jid);

        identity->inband_registration = inband_register;

        inc_master_init_counter();
    }
}

void xmpp_identity_destroy(xmpp_identity_t *identity)
{
    if (identity)
    {
        free_c_str(identity->user_jid);
        identity->user_jid = NULL;
        clear_c_str(identity->password);
        free_c_str(identity->password);
        identity->password = NULL;
        free_c_str(identity->user_name);
        identity->user_name = NULL;
        dec_master_init_counter();
    }
}

void xmpp_proxy_init(xmpp_proxy_t *const proxy, const char *const host,
                     uint16_t port, xmpp_proxy_type_t proxy_type)
{
    if (proxy)
    {
#if (defined(__STDC_WANT_LIB_EXT1__) && (__STDC_WANT_LIB_EXT1__ >= 1))
        memset_s(proxy, sizeof(*proxy), 0, sizeof(*proxy));
#else
        memset(proxy, 0, sizeof(*proxy));
#endif


        proxy->cb = sizeof(*proxy);

        proxy->proxy_type = proxy_type;
        proxy->proxy_host = clone_c_str(host);
        proxy->proxy_port = port;

        inc_master_init_counter();
    }
}

void xmpp_proxy_destroy(xmpp_proxy_t *proxy)
{
    if (proxy)
    {
        free_c_str(proxy->proxy_host);
        proxy->proxy_host = NULL;
        dec_master_init_counter();
    }
}



///////////////////////////////////////////////////////////////////////////////////////////////////
// External library functions.
///////////////////////////////////////////////////////////////////////////////////////////////////
xmpp_handle_t xmpp_startup(const xmpp_context_t *const context)
{
    // Make certain the context was initialized (future versions may support different
    // context structure sizes).
    if (context->cb != sizeof(xmpp_context_t))
    {
        xmpp_handle_t nullHandle = {NULL};
        return nullHandle;
    }

    xmpp_ctx_t *new_context = calloc(1, sizeof(xmpp_ctx_t));

    if (new_context)
    {
        new_context->wrapper_handle =  xmpp_wrapper_create_wrapper();

        if (new_context->wrapper_handle == NULL)
        {
            free(new_context);
            xmpp_handle_t nullHandle = {NULL};
            return nullHandle;
        }

        new_context->user_context = clone_context(context);
        inc_master_init_counter();

    }
    xmpp_handle_t contextHandle = {new_context};
    return contextHandle;
}

void xmpp_shutdown_xmpp(xmpp_handle_t handle)
{
    // TODO: Add valid-handle lookup....
    if (handle.abstract_handle)
    {
        xmpp_ctx_t *ctx = (xmpp_ctx_t *)handle.abstract_handle;
        xmpp_wrapper_destroy_wrapper(ctx->wrapper_handle);
        if (ctx->user_context)
        {
            free(ctx->user_context);
        }
        free((void *)handle.abstract_handle);
        dec_master_init_counter();

        if (master_init_counter() != 0)
        {
            // TODO: Log issue, inits did not match destroys.

            // PANIC
            //exit(2);
        }
    }
}

int xmpp_global_shutdown_okay(void)
{
    return master_init_counter() == 0 ? 1 : 0;
}

xmpp_error_code_t xmpp_connect(xmpp_handle_t handle,
                               const xmpp_host_t *const host,
                               const xmpp_identity_t *const identity,
                               xmpp_connection_callback_t callback)
{
    return xmpp_connect_with_proxy(handle, host, identity, NULL, callback);
}

xmpp_error_code_t xmpp_connect_with_proxy(xmpp_handle_t handle,
        const xmpp_host_t *const host,
        const xmpp_identity_t *const identity,
        const xmpp_proxy_t *const proxy,
        xmpp_connection_callback_t callback)
{
    // TODO: Add handle-check
    if (!handle.abstract_handle)
    {
        return XMPP_ERR_INVALID_HANDLE;
    }

    xmpp_ctx_t *ctx = (xmpp_ctx_t *)handle.abstract_handle;
    return xmpp_wrapper_connect(ctx->wrapper_handle, host, identity, proxy, callback);
}

// TODO: Add support-check function

xmpp_error_code_t xmpp_close(xmpp_connection_handle_t connection)
{
    return xmpp_wrapper_disconnect(connection);
}





typedef struct
{
    xmpp_connection_handle_t  connection;
    xmpp_message_callback_t   callback;
    void                           *wrapper_handle;
} xmpp_message_ctx_t;

///////////////////////////////////////////////////////////////////////////////////////////////////
// Message Transmission/Receipt
///////////////////////////////////////////////////////////////////////////////////////////////////
xmpp_message_context_t xmpp_message_context_create(
    xmpp_connection_handle_t connection,
    xmpp_message_callback_t callback)
{
    xmpp_message_ctx_t *new_context = calloc(1, sizeof(xmpp_message_ctx_t));

    if (new_context)
    {
        new_context->connection = connection;
        new_context->callback = callback;
        new_context->wrapper_handle = xmpp_wrapper_register_message_callback(connection, callback);

        if (new_context->wrapper_handle == NULL)
        {
            free(new_context);
            xmpp_message_context_t nullContext = {NULL};
            return nullContext;
        }

        inc_master_init_counter();
    }

    xmpp_message_context_t resultContext = {new_context};
    return resultContext;
}

xmpp_error_code_t xmpp_send_message(xmpp_message_context_t ctx,
                                    const char *const recipient,
                                    const void *const message,
                                    const size_t messageOctets,
                                    xmpp_transmission_options_t options)
{
    if (!ctx.abstract_context)
    {
        return XMPP_ERR_INVALID_HANDLE;
    }
    return xmpp_wrapper_send_message(((xmpp_message_ctx_t *)ctx.abstract_context)->wrapper_handle,
                                     recipient, message, messageOctets, options);
}

void xmpp_message_context_destroy(xmpp_message_context_t ctx)
{
    if (ctx.abstract_context)
    {
        xmpp_wrapper_unregister_message_callback(
            ((xmpp_message_ctx_t *)ctx.abstract_context)->wrapper_handle);

        dec_master_init_counter();
        free((void *)ctx.abstract_context);
    }
}

/// @endcond
