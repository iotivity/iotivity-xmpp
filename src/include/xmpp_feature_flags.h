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

#pragma once


// Select feature-flags based on meta-flags defined during compilation. By default
// this file enables all non-conflicting features of the library.

// libstrophe Support [Does not support SOCKS5 or BOSH]
#ifdef ENABLE_LIBSTROPHE
#define DISABLE_SUPPORT_SOCKS5
#define DISABLE_SUPPORT_BOSH
#define DISABLE_SUPPORT_NATIVE_XMPP_CLIENT
#else
#define DISABLE_SUPPORT_LIBSTROPHE
#endif

// SOCKS5 {Direct Proxy}
#ifdef DISABLE_SOCKS5
#ifndef DISABLE_SUPPORT_SOCKS5
#define DISABLE_SUPPORT_SOCKS5
#endif
#endif

// BOSH
#ifdef DISABLE_BOSH
#ifndef DISABLE_SUPPORT_BOSH
#define DISABLE_SUPPORT_BOSH
#endif
#endif

// XEP0030 Service Discovery
#ifdef DISABLE_XEP0030
#ifndef DISABLE_SUPPORT_XEP0030
#define DISABLE_SUPPORT_XEP0030
#endif
#endif

// XEP0060 Publish Subscribe
#ifdef DISABLE_XEP0060
#ifndef DISABLE_SUPPORT_XEP0060
#define DISABLE_SUPPORT_XEP0060
#endif
#endif

// XEP0077 In-Band Registration
#ifdef DISABLE_XEP0077
#ifndef DISABLE_SUPPORT_XEP0077
#define DISABLE_SUPPORT_XEP0077
#endif
#endif

// XEP0199 XMPP Ping
#ifdef DISABLE_XEP0199
#ifndef DISABLE_SUPPORT_XEP0199
#define DISABLE_SUPPORT_XEP0199
#endif
#endif

