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


// Required by ra_xmpp.h for the Windows target builds.
#ifdef _WIN32
#include <SDKDDKVer.h>
#endif

#include "ra_xmpp.h"

#include <string.h>
#include <errno.h>

#ifdef __APPLE__
#include <safec/safe_lib.h>
#elif !defined(_WIN32)
#include <safe_mem_lib.h>
#include <safe_str_lib.h>
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
// TODO: ?? Import safec into windows build for memset_s?
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



typedef struct
{
    XMPP_LIB_(context_t)   *user_context;
    void                   *wrapper_handle;
} xmpp_ctx_t;



///////////////////////////////////////////////////////////////////////////////////////////////////
// Wrapper interface (implementation dependent).
///////////////////////////////////////////////////////////////////////////////////////////////////
extern void *const xmpp_wrapper_create_wrapper(void);
extern void xmpp_wrapper_destroy_wrapper(void *handle);
extern XMPP_LIB_(error_code_t) xmpp_wrapper_connect(void *handle,
        const XMPP_LIB_(host_t) * const host,
        const XMPP_LIB_(identity_t) * const identity,
        const XMPP_LIB_(proxy_t) * const proxy,
        XMPP_LIB_(connection_callback_t) callback);
extern XMPP_LIB_(error_code_t) xmpp_wrapper_disconnect(XMPP_LIB_(connection_handle_t) connection);

extern void *xmpp_wrapper_register_message_callback(XMPP_LIB_(connection_handle_t) connection,
        XMPP_LIB_(message_callback_t) callback);
extern void xmpp_wrapper_unregister_message_callback(void *handle);
extern XMPP_LIB_(error_code_t) xmpp_wrapper_send_message(void *handle,
        const char *const recipient,
        const void *const message,
        const size_t sizeInOctets,
        XMPP_LIB_(transmission_options_t) options);


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
            memmove_s(cloned_str, str_len, str, str_len);
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
void XMPP_LIB_(context_init)(XMPP_LIB_(context_t) * const context)
{
    if (context)
    {
        memset_s(context, sizeof(*context), 0);
        context->cb = sizeof(*context);
    }
}

void XMPP_LIB_(context_destroy)(XMPP_LIB_(context_t) *context)
{
}

// This is separated out under the assumption that the context will expand to include
// pointers to heap objects.
XMPP_LIB_(context_t) *clone_context(const XMPP_LIB_(context_t) *context)
{
    XMPP_LIB_(context_t) *cloned_context = calloc(1, sizeof(*context));
    if (cloned_context)
    {
        memmove_s(cloned_context, sizeof(*cloned_context), context, sizeof(*context));
    }
    return cloned_context;
}


void XMPP_LIB_(host_init)(XMPP_LIB_(host_t) * const host, const char *const host_name,
                          uint16_t port,  const char *const xmpp_domain,
                          XMPP_LIB_(protocol_t) protocol)
{
    if (host)
    {
        memset_s(host, sizeof(*host), 0);
        host->cb = sizeof(*host);

        host->host = clone_c_str(host_name);
        host->port = port;

        host->xmpp_domain = clone_c_str(xmpp_domain);

        host->protocol = protocol;

        inc_master_init_counter();
    }
}

void XMPP_LIB_(host_destroy)(XMPP_LIB_(host_t) *host)
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


void XMPP_LIB_(identity_init)(XMPP_LIB_(identity_t) * const identity, const char *const user_name,
                              const char *const password, const char *const user_jid,
                              InBandRegister_t inband_register)
{
    if (identity)
    {
        memset_s(identity, sizeof(*identity), 0);
        identity->cb = sizeof(*identity);

        identity->user_name = clone_c_str(user_name);
        identity->password = clone_c_str(password);
        identity->user_jid = clone_c_str(user_jid);

        identity->inband_registration = inband_register;

        inc_master_init_counter();
    }
}

void XMPP_LIB_(identity_destroy)(XMPP_LIB_(identity_t) *identity)
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

void XMPP_LIB_(proxy_init)(XMPP_LIB_(proxy_t) * const proxy, const char *const host,
                           uint16_t port, XMPP_LIB_(proxy_type_t) proxy_type)
{
    if (proxy)
    {
        memset_s(proxy, sizeof(*proxy), 0);
        proxy->cb = sizeof(*proxy);

        proxy->proxy_type = proxy_type;
        proxy->proxy_host = clone_c_str(host);
        proxy->proxy_port = port;

        inc_master_init_counter();
    }
}

void XMPP_LIB_(proxy_destroy)(XMPP_LIB_(proxy_t) *proxy)
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
XMPP_LIB_(handle_t) XMPP_LIB_(startup)(const XMPP_LIB_(context_t) * const context)
{
    // Make certain the context was initialized (future versions may support different
    // context structure sizes).
    if (context->cb != sizeof(XMPP_LIB_(context_t)))
    {
        XMPP_LIB_(handle_t) nullHandle = {NULL};
        return nullHandle;
    }

    xmpp_ctx_t *new_context = calloc(1, sizeof(xmpp_ctx_t));

    if (new_context)
    {
        new_context->wrapper_handle =  xmpp_wrapper_create_wrapper();

        if (new_context->wrapper_handle == NULL)
        {
            free(new_context);
            XMPP_LIB_(handle_t) nullHandle = {NULL};
            return nullHandle;
        }

        new_context->user_context = clone_context(context);
        inc_master_init_counter();

    }
    XMPP_LIB_(handle_t) contextHandle = {new_context};
    return contextHandle;
}

void XMPP_LIB_(shutdown)(XMPP_LIB_(handle_t) handle)
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

            // PANIC  [ TODO: Lower panic-level ]
            exit(2);
        }
    }
}

int XMPP_LIB_(global_shutdown_okay)(void)
{
    return master_init_counter() == 0 ? 1 : 0;
}

XMPP_LIB_(error_code_t) XMPP_LIB_(connect)(XMPP_LIB_(handle_t) handle,
        const XMPP_LIB_(host_t) * const host,
        const XMPP_LIB_(identity_t) * const identity,
        XMPP_LIB_(connection_callback_t) callback)
{
    return XMPP_LIB_(connect_with_proxy)(handle, host, identity, NULL, callback);
}

XMPP_LIB_(error_code_t) XMPP_LIB_(connect_with_proxy)(XMPP_LIB_(handle_t) handle,
        const XMPP_LIB_(host_t) * const host,
        const XMPP_LIB_(identity_t) * const identity,
        const XMPP_LIB_(proxy_t) * const proxy,
        XMPP_LIB_(connection_callback_t) callback)
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

XMPP_LIB_(error_code_t) XMPP_LIB_(close)(XMPP_LIB_(connection_handle_t) connection)
{
    return xmpp_wrapper_disconnect(connection);
}





typedef struct
{
    XMPP_LIB_(connection_handle_t)  connection;
    XMPP_LIB_(message_callback_t)   callback;
    void                           *wrapper_handle;
} xmpp_message_ctx_t;

///////////////////////////////////////////////////////////////////////////////////////////////////
// Message Transmission/Receipt
///////////////////////////////////////////////////////////////////////////////////////////////////
XMPP_LIB_(message_context_t) XMPP_LIB_(message_context_create)(
    XMPP_LIB_(connection_handle_t) connection,
    XMPP_LIB_(message_callback_t) callback)
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
            XMPP_LIB_(message_context_t) nullContext = {NULL};
            return nullContext;
        }

        inc_master_init_counter();
    }

    XMPP_LIB_(message_context_t) resultContext = {new_context};
    return resultContext;
}

XMPP_LIB_(error_code_t) XMPP_LIB_(send_message)(XMPP_LIB_(message_context_t) ctx,
        const char *const recipient,
        const void *const message,
        const size_t messageOctets,
        XMPP_LIB_(transmission_options_t) options)
{
    if (!ctx.abstract_context)
    {
        return XMPP_ERR_INVALID_HANDLE;
    }
    return xmpp_wrapper_send_message(((xmpp_message_ctx_t *)ctx.abstract_context)->wrapper_handle,
                                     recipient, message, messageOctets, options);
}

void XMPP_LIB_(message_context_destroy)(XMPP_LIB_(message_context_t) ctx)
{
    if (ctx.abstract_context)
    {
        xmpp_wrapper_unregister_message_callback(
            ((xmpp_message_ctx_t *)ctx.abstract_context)->wrapper_handle);

        dec_master_init_counter();
        free((void *)ctx.abstract_context);
    }
}

