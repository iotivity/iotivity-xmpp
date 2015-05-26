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

/// @file xmpp_connect_config.cpp

#include "stdafx.h"
#include "xmpp_connect_config.h"
#include <xml/portabledom.h>
#include <fstream>
#include <iostream>

using namespace std;
using namespace Iotivity::XML;


xmpp_connect_config::ConfigMap xmpp_connect_config::s_config;
bool xmpp_connect_config::s_loaded = false;

string xmpp_connect_config::proxyHost(const string &configuration)
{
    if (!hasConfig(configuration)) return "";
    return s_config[configuration]["proxyHost"];
}

string xmpp_connect_config::proxyPort(const string &configuration)
{
    if (!hasConfig(configuration)) return "";
    return s_config[configuration]["proxyPort"];
}

string xmpp_connect_config::host(const string &configuration)
{
    if (!hasConfig(configuration)) return "";
    return s_config[configuration]["host"];
}

string xmpp_connect_config::port(const string &configuration)
{
    if (!hasConfig(configuration)) return "";
    return s_config[configuration]["port"];
}

string xmpp_connect_config::xmppDomain(const string &configuration)
{
    if (!hasConfig(configuration)) return "";
    return s_config[configuration]["xmppDomain"];
}

string xmpp_connect_config::userName(const string &configuration)
{
    if (!hasConfig(configuration)) return "";
    return s_config[configuration]["userName"];
}

string xmpp_connect_config::password(const string &configuration)
{
    if (!hasConfig(configuration)) return "";
    return s_config[configuration]["password"];
}

string xmpp_connect_config::userJID(const string &configuration)
{
    if (!hasConfig(configuration)) return "";
    return s_config[configuration]["userJID"];
}

string xmpp_connect_config::BOSHUrl(const string &configuration)
{
    if (!hasConfig(configuration)) return "";
    return s_config[configuration]["BOSHUrl"];
}

bool xmpp_connect_config::hasConfig(const string &configuration)
{
    if (!s_loaded) return false;
    return s_config.find(configuration) != s_config.end();
}

string trim(const string &str)
{
    static const string s_spaceChars = " \t\n";
    auto firstChar = str.find_first_not_of(s_spaceChars);
    auto lastChar = str.find_last_not_of(s_spaceChars);
    if (firstChar == string::npos)
    {
        firstChar = 0;
    }
    if (lastChar == string::npos)
    {
        lastChar = str.size() > 0 ? str.size() - 1 : 0;
    }
    return str.substr(firstChar, lastChar - firstChar + 1);
}

void xmpp_connect_config::loadConfig()
{
    // Not strictly needed for the test suite, but present `cause
    // it's the right safeguard to have....
    lock_guard<std::mutex> lock(mutex());

    // Attempt to load the config from the current directory.
    try
    {
        auto document = XMLDocument::createEmptyDocument();
        ifstream configFile("xmpp_config.xml");
        if (configFile.is_open())
        {
            document->parse(configFile);

            XMLElement::Ptr rootElement = document->documentElement();
            if (rootElement)
            {
                // NOTE: We are ignoring the root Tag name.
                for (const auto &e : rootElement->elements())
                {
                    if (e->name() == "config")
                    {
                        string nameStr;
                        if (e->getAttribute("name", nameStr))
                        {
                            for (const auto &param : e->elements())
                            {
                                s_config[nameStr][param->name()] = trim(param->value());
                            }
                        }
                    }
                }
            }

            s_loaded = true;
        }
        else
        {
            cout << "xmpp_config.xml not found" << endl;
        }
    }
    catch (const rapidxml::parse_error &)
    {}
    catch (...)
    {}
}

std::mutex &xmpp_connect_config::mutex()
{
    static std::mutex s_mutex;
    return s_mutex;
}




