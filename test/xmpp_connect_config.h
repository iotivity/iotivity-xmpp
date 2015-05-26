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

/// @file xmpp_connect_config.h

#pragma once

#include <string>
#include <map>
#include <mutex>


struct xmpp_connect_config
{
        static void loadConfig();

        static std::string proxyHost(const std::string &configuration = "DEFAULT");
        static std::string proxyPort(const std::string &configuration = "DEFAULT");

        static std::string host(const std::string &configuration = "DEFAULT");
        static std::string port(const std::string &configuration = "DEFAULT");

        static std::string xmppDomain(const std::string &configuration = "DEFAULT");

        static std::string userName(const std::string &configuration = "DEFAULT");
        static std::string password(const std::string &configuration = "DEFAULT");

        static std::string userJID(const std::string &configuration = "DEFAULT");
        static std::string BOSHUrl(const std::string &configuration = "DEFAULT");
        static bool hasConfig(const std::string &configuration = "DEFAULT");

    protected:
        static std::mutex &mutex();
    private:
        typedef std::map<std::string, std::map<std::string, std::string>> ConfigMap;
        static ConfigMap s_config;
        static bool s_loaded;
};