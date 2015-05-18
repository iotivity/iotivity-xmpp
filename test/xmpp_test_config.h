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

/// @file xmpp_test_config.h

// XMPP Server configuration for live tests

#include <connect/proxy.h>

#include <xmpp/jabberid.h>

const Iotivity::Xmpp::ProxyConfig g_proxy("proxy-us.intel.com", "1080",
        Iotivity::Xmpp::ProxyConfig::ProxyType::ProxySOCKS5);

const std::string JABBERDAEMON_TEST_HOST = "xmpp-dev-lb.api.intel.com";
const std::string JABBERDAEMON_TEST_PORT = "5222";

const std::string JABBERDAEMON_INTERNAL_TEST_HOST = "strophe-test.amr.corp.intel.com";
const std::string JABBERDAEMON_INTERNAL_TEST_PORT = "5222";

static const std::string JABBERDAEMON_TEST_URL = "xmpp-dev-lb.api.intel.com/http-bind";

const Iotivity::Xmpp::JabberID MY_JID{"unittest"};