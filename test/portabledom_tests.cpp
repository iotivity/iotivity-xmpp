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

/// @file common_tests.cpp

#include "stdafx.h"

#include <gtest/gtest.h>

#include "xml/portabledom.h"
#include "common/compatibility.h"
#include "common/buffers.h"


using namespace std;
using namespace Iotivity;


// portabledom.h
using namespace Iotivity::XML;

TEST(portableDOM_Tests, XMLDocument_parse)
{
    Iotivity::XML::XMLDocument::Ptr testXML = Iotivity::XML::XMLDocument::createEmptyDocument();
    ASSERT_NE(testXML, nullptr);

    std::string testStr;
    testStr = "<test></test>";
    EXPECT_NO_THROW(testXML->parse(testStr));

    std::string testStr2;
    testStr2 = "<test><test></test2>";
    EXPECT_THROW(testXML->parse(testStr2), rapidxml::parse_error);

    char testStr3[] = "<test><inner/></test>";
    Iotivity::ByteBuffer tempBuffer(testStr3, sizeof(testStr3) - 1);
    EXPECT_NO_THROW(testXML->parse(tempBuffer));
    EXPECT_EQ(testXML->xml(), testStr3);

    const string testStr4 = "<test><inner/></invalid>";
    EXPECT_THROW(testXML->parse(testStr4), rapidxml::parse_error);

    const string testStr5 = "<test><inner/></invalid>";
    EXPECT_NO_THROW(testXML->parse(testStr5, Iotivity::XML::XMLDocument::EndingTest::IgnoreEnding));

}

TEST(portableDOM_Tests, XMLElement_elementTreeTest)
{
    Iotivity::XML::XMLDocument::Ptr testXML = Iotivity::XML::XMLDocument::createEmptyDocument();

    Iotivity::XML::XMLElement::Ptr element1 = testXML->createElement("root1");
    Iotivity::XML::XMLElement::Ptr element2 = testXML->createElement("child1_sibling1");
    Iotivity::XML::XMLElement::Ptr element3 = testXML->createElement("child1_sibling2");
    Iotivity::XML::XMLElement::Ptr element4 = testXML->createElement("child12_sibling1");
    Iotivity::XML::XMLElement::Ptr element5 = testXML->createElement("child12_sibling2");
    Iotivity::XML::XMLElement::Ptr element6 = testXML->createElement("child121");
    Iotivity::XML::XMLElement::Ptr element7 = testXML->createElement("child1211");

    EXPECT_TRUE(element6->appendChild(element7));
    EXPECT_TRUE(element4->appendChild(element6));
    EXPECT_TRUE(element3->appendChild(element4));
    EXPECT_TRUE(element3->appendChild(element5));
    EXPECT_TRUE(element1->appendChild(element2));
    EXPECT_TRUE(element1->appendChild(element3));
    EXPECT_TRUE(testXML->appendChild(element1));

    std::string treeStr =
        "<root1><child1_sibling1/><child1_sibling2><child12_sibling1><child121><child1211/></child121></child12_sibling1><child12_sibling2/></child1_sibling2></root1>";
    EXPECT_EQ(testXML->xml(), treeStr);

    Iotivity::XML::XMLDocument::Ptr testXML2 = Iotivity::XML::XMLDocument::createEmptyDocument();
    ASSERT_NE(testXML2, nullptr);

    Iotivity::XML::XMLElement::Ptr element8 = testXML2->createElement("bad_child12111");
    EXPECT_FALSE(element7->appendChild(element8));

    EXPECT_EQ(testXML->xml(), treeStr);
}

TEST(portableDOM_Tests, XMLElement_getAttributes)
{
    //EXPECT_NO_THROW(testXML->parse(testStr));
    Iotivity::XML::XMLDocument::Ptr testXML = Iotivity::XML::XMLDocument::createEmptyDocument();
    ASSERT_NE(testXML, nullptr);

    struct
    {
        std::string _name;
        std::string _val;
    } nameVal[] =
    {
        {"member_std_string", "val1"},
        {"std_string",        "val3"},
        {"bool_false",        "0"},
        {"bool_true",         "1"},
        {"uint8_t",           "254"},
        {"int8_t",            "-32"},
        {"uint16_t",          "64452"},
        {"int16_t",           "-32750"},
        {"uint32_t",          "4294967196"},
        {"int32_t",           "-1294967296"},
        {"uint64_t",          "18446744073709251611"},
        {"int64_t",           "-5446744073709551616"},
    };
    ostringstream testStream;
    testStream << "<root";
    for (auto i : nameVal)
    {
        testStream << " " << i._name << "=\"" << i._val << "\"";
    }
    testStream << "/>";
    std::string testStr = testStream.str();

    ASSERT_NO_THROW(testXML->parse(testStr));

    Iotivity::XML::XMLElement::Ptr element = testXML->documentElement();
    ASSERT_NE(element, nullptr);

    std::string member_std_string;
    EXPECT_TRUE(element->getAttribute("member_std_string", member_std_string));
    EXPECT_EQ(member_std_string, "val1");

    std::string strVal;
    EXPECT_TRUE(element->getAttribute("std_string", strVal));
    EXPECT_EQ(strVal, std::string("val3"));

    bool fVal = true;
    EXPECT_TRUE(element->getAttribute("bool_false", fVal));
    EXPECT_FALSE(fVal);

    bool tVal = false;
    EXPECT_TRUE(element->getAttribute("bool_true", tVal));
    EXPECT_TRUE(tVal);

    uint8_t uint8Val = 0;
    EXPECT_TRUE(element->getAttribute("uint8_t", uint8Val));
    EXPECT_EQ(uint8Val, (uint8_t)254);

    int8_t int8Val = 0;
    EXPECT_TRUE(element->getAttribute("int8_t", int8Val));
    EXPECT_EQ(int8Val, (int8_t) - 32);

    uint16_t uint16Val = 0;
    EXPECT_TRUE(element->getAttribute("uint16_t", uint16Val));
    EXPECT_EQ(uint16Val, (uint16_t)64452);

    int16_t int16Val = 0;
    EXPECT_TRUE(element->getAttribute("int16_t", int16Val));
    EXPECT_EQ(int16Val, (int16_t) - 32750);

    uint32_t uint32Val = 0;
    EXPECT_TRUE(element->getAttribute("uint32_t", uint32Val));
    EXPECT_EQ(uint32Val, (uint32_t)4294967196);

    int32_t int32Val = 0;
    EXPECT_TRUE(element->getAttribute("int32_t", int32Val));
    EXPECT_EQ(int32Val, (int32_t) - 1294967296);

    uint64_t uint64Val = 0;
    EXPECT_TRUE(element->getAttribute("uint64_t", uint64Val));
    EXPECT_EQ(uint64Val, (uint64_t)18446744073709251611UL);

    int64_t int64Val = 0;
    EXPECT_TRUE(element->getAttribute("int64_t", int64Val));
    EXPECT_EQ(int64Val, -5446744073709551616);

    EXPECT_TRUE(element->hasAttribute("int64_t"));
    EXPECT_FALSE(element->hasAttribute(""));
    EXPECT_FALSE(element->hasAttribute("NOT_AN_EXPECTED_ATTRIBUTE_THING"));

    Iotivity::XML::XMLAttribute::AttributeList attributes =  element->attributes();
    EXPECT_EQ(attributes.size(), ARRAYSIZE(nameVal));
    size_t attrIndex = 0;
    for (const auto &i : attributes)
    {
        ASSERT_LT(attrIndex, ARRAYSIZE(nameVal));
        EXPECT_EQ(i->name(), nameVal[attrIndex]._name);
        EXPECT_EQ(i->value(), nameVal[attrIndex]._val);
        attrIndex++;
    }
}

TEST(portableDOM_Tests, XMLElement_setAttributes)
{

    Iotivity::XML::XMLDocument::Ptr testXML = Iotivity::XML::XMLDocument::createEmptyDocument();
    ASSERT_NE(testXML, nullptr);

    Iotivity::XML::XMLElement::Ptr element = testXML->createElement("root");

    EXPECT_TRUE(testXML->appendChild(element));

    EXPECT_TRUE(element->setAttribute("member_std_string", "val1"));
    EXPECT_TRUE(element->setAttribute("std_string", std::string("val3")));
    EXPECT_TRUE(element->setAttribute("char_ptr", "val5"));
    EXPECT_TRUE(element->setAttribute("bool_false", false));
    EXPECT_TRUE(element->setAttribute("bool_true", true));
    EXPECT_TRUE(element->setAttribute("uint8_t", (uint8_t)254));
    EXPECT_TRUE(element->setAttribute("int8_t", (int8_t) - 32));
    EXPECT_TRUE(element->setAttribute("uint16_t", (uint16_t)64452));
    EXPECT_TRUE(element->setAttribute("int16_t", (int16_t) - 32750));
    EXPECT_TRUE(element->setAttribute("uint32_t", (uint32_t)4294967196));
    EXPECT_TRUE(element->setAttribute("int32_t", (int32_t) - 1294967296));
    EXPECT_TRUE(element->setAttribute("uint64_t", (uint64_t)18446744073709251611UL));
    EXPECT_TRUE(element->setAttribute("int64_t", (int64_t) - 5446744073709551616));

    std::string attrStr =
        "<root member_std_string=\"val1\" std_string=\"val3\" char_ptr=\"val5\" bool_false=\"0\" bool_true=\"1\" uint8_t=\"254\" int8_t=\"-32\" uint16_t=\"64452\" int16_t=\"-32750\" uint32_t=\"4294967196\" int32_t=\"-1294967296\" uint64_t=\"18446744073709251611\" int64_t=\"-5446744073709551616\"/>";
    EXPECT_EQ(testXML->xml(), attrStr);

    std::string attrStr2 =
        "<root member_std_string=\"val1\" std_string=\"val3\" char_ptr=\"val5\" bool_false=\"0\" bool_true=\"1\" uint8_t=\"254\" int8_t=\"-32\" uint16_t=\"64452\" int16_t=\"-32750\" uint32_t=\"4294967196\" int32_t=\"-1294967296\" uint64_t=\"18446744073709251611\" int64_t=\"-5446744073709551616\"/>";
    EXPECT_EQ(testXML->xml(), attrStr2);
}

TEST(portableDOM_Tests, XMLElement_selectNodes)
{

    Iotivity::XML::XMLDocument::Ptr testXML = Iotivity::XML::XMLDocument::createEmptyDocument();
    ASSERT_NE(testXML, nullptr);

    std::string testStr;
    testStr = "<test tag=\"Not An Element\"><tag val=\"1\"/><tag val=\"2\"/><not_tag/><tag val=\"3\"/>"
              "<not_tag/><!--comment--><![CDATA[MYDATA]]></test>";
    EXPECT_NO_THROW(testXML->parse(testStr));
    Iotivity::XML::XMLElement::Ptr documentElement = testXML->documentElement();
    ASSERT_NE(documentElement, nullptr);

    size_t counter = 0;
    for (const auto &node : documentElement->selectNodes("tag"))
    {
        ASSERT_NE(node, nullptr);
        ++counter;
    }
    EXPECT_EQ(counter, 3UL);

    size_t counter2 = 0;
    for (const auto &node : documentElement->nodes())
    {
        ASSERT_NE(node, nullptr);
        ++counter2;
    }
    EXPECT_EQ(counter2, 6UL);

    size_t counter3 = 0;
    for (const auto &element : documentElement->elements())
    {
        ASSERT_NE(element, nullptr);
        ++counter3;
    }
    EXPECT_EQ(counter3, 5UL);

}

TEST(portableDOM_Tests, XMLNode_findNamespace)
{
    const std::string testStr = "<test:test normalAttr='v' xmlns:test='http://dummy-url.net' "
                                "xmlns:other='http://dummy-url.net/v2' other:xmlns='bad' test:val='something'/>";

    Iotivity::XML::XMLDocument::Ptr testXML = Iotivity::XML::XMLDocument::createEmptyDocument();
    ASSERT_NE(testXML, nullptr);

    EXPECT_NO_THROW(testXML->parse(testStr));

    Iotivity::XML::XMLElement::Ptr documentElement = testXML->documentElement();
    ASSERT_NE(documentElement, nullptr);

    EXPECT_EQ(documentElement->findNamespace("http://dummy-url.net"), "test");
    EXPECT_EQ(documentElement->findNamespace("http://dummy-url.net/v2"), "other");
    EXPECT_EQ(documentElement->findNamespace("http://dummy-url.net/v3"), "");
}

TEST(portableDOM_Tests, XMLNode_UnterminatedXMLWithChildren)
{
    Iotivity::XML::XMLDocument::Ptr testXML = Iotivity::XML::XMLDocument::createEmptyDocument();
    ASSERT_NE(testXML, nullptr);

    std::string treeStr =
        "<root1><child1_sibling1/><child1_sibling2><child12_sibling1><child121><child1211/></child121></child12_sibling1><child12_sibling2/></child1_sibling2></root1>";
    std::string treeStrNoRoot =
        "<root1><child1_sibling1/><child1_sibling2><child12_sibling1><child121><child1211/></child121></child12_sibling1><child12_sibling2/></child1_sibling2>";
    EXPECT_NO_THROW(testXML->parse(treeStr));

    XML::XMLElement::Ptr rootElement = testXML->documentElement();
    ASSERT_NE(rootElement, nullptr);
    EXPECT_EQ(rootElement->xml(), treeStr);
    EXPECT_EQ(rootElement->unterminatedXML(), treeStrNoRoot);
}

TEST(portableDOM_Tests, XMLNode_UnterminatedXMLWithoutChildren)
{
    Iotivity::XML::XMLDocument::Ptr testXML = Iotivity::XML::XMLDocument::createEmptyDocument();
    ASSERT_NE(testXML, nullptr);

    std::string treeStr = "<name:root xmlns:name=\"http://dummy.com\" attr=\"someattr\"/>";
    std::string treeStrNoRoot = "<name:root xmlns:name=\"http://dummy.com\" attr=\"someattr\">";
    EXPECT_NO_THROW(testXML->parse(treeStr));

    XML::XMLElement::Ptr rootElement = testXML->documentElement();
    ASSERT_NE(rootElement, nullptr);
    EXPECT_EQ(rootElement->xml(), treeStr);
    EXPECT_EQ(rootElement->unterminatedXML(), treeStrNoRoot);
}

TEST(portableDOM_Tests, Streaming_Parser_StreamHeader)
{
    string headerPayload = "<stream:stream from='fromtest' to='xmpp-dev.iotivity.intel.com' "
                           "version='1.0' xml:lang='en' xmlns='jabber:client' "
                           "xmlns:stream='http://etherx.jabber.org/streams'></stream:stream>";

    XML::XMLDocument::Ptr doc = XML::XMLDocument::createEmptyDocument();
    ASSERT_NE(doc, nullptr);

    try
    {
        XML::XMLNode::Ptr node;
        size_t bytesRead = doc->parsePartial(headerPayload, node);
        EXPECT_EQ(bytesRead, headerPayload.size());
    }
    catch (const rapidxml::parse_error &err)
    {
        EXPECT_NO_THROW(throw err);
    }
}

TEST(portableDOM_Tests, Streaming_Parser_Incomplete)
{
    string incompletePayload = "<simple from='fromtest' to='xmpp-dev.iotivity.intel.com' "
                               "version='1.0' xml:lang='en' xmlns='jabber:clien";

    XML::XMLDocument::Ptr doc = XML::XMLDocument::createEmptyDocument();
    ASSERT_NE(doc, nullptr);

    try
    {
        XML::XMLNode::Ptr node;
        doc->parsePartial(incompletePayload, node);
    }
    catch (const rapidxml::parse_error &err)
    {
        EXPECT_THROW(throw err, rapidxml::parse_error);
    }
}


TEST(portableDOM_Tests, Streaming_Parser_Incomplete_Continuation)
{
    string initialPayload = "<simple from='fromtest' to='xmpp-dev.iotivity.intel.com' "
                            "version='1.0' xml:lang='en' xmlns='jabber:client'><subnode/>"
                            "</simple>";
    string incompletePayload = initialPayload + "<continuation attr=";

    XML::XMLDocument::Ptr doc = XML::XMLDocument::createEmptyDocument();
    ASSERT_NE(doc, nullptr);

    try
    {
        XML::XMLNode::Ptr node;
        size_t bytesRead = doc->parsePartial(incompletePayload, node);
        EXPECT_EQ(bytesRead, initialPayload.size());
    }
    catch (const rapidxml::parse_error &err)
    {
        EXPECT_NO_THROW(throw err);
    }
}

TEST(portableDOM_Tests, Streaming_Parser_Continuations)
{
    string payload = "<simple from='fromtest' to='xmpp-dev.iotivity.intel.com' "
                     "version='1.0' xml:lang='en' xmlns='jabber:client'><subnode/>"
                     "</simple><next/><next attr='sub'><!--comment--></next><simple></simple>"
                     "  <final/>";

    size_t totalBytesRead = 0;
    size_t totalPayloads = 0;
    do
    {
        XML::XMLDocument::Ptr doc = XML::XMLDocument::createEmptyDocument();
        ASSERT_NE(doc, nullptr);

        try
        {
            XML::XMLNode::Ptr node;
            size_t bytesRead = doc->parsePartial(payload.substr(totalBytesRead), node);

            ASSERT_NE(node, nullptr);
            EXPECT_NE(bytesRead, 0UL);

            totalBytesRead += bytesRead;
            ++totalPayloads;
        }
        catch (const rapidxml::parse_error &err)
        {
            EXPECT_NO_THROW(throw err);
        }
    }
    while (totalBytesRead < payload.size());
    EXPECT_EQ(totalPayloads, 5UL);
}

TEST(portableDOM_Tests, Streaming_Parser_Continuations_ByteBuffer)
{
    string payload = "<simple from='fromtest' to='xmpp-dev.iotivity.intel.com' "
                     "version='1.0' xml:lang='en' xmlns='jabber:client'><subnode/>"
                     "</simple><next/><next attr='sub'><!--comment--></next><simple></simple>"
                     "  <final/>";

    size_t totalBytesRead = 0;
    size_t totalPayloads = 0;

    ByteBuffer payloadRef(payload.c_str(), payload.size());
    do
    {
        XML::XMLDocument::Ptr doc = XML::XMLDocument::createEmptyDocument();
        ASSERT_NE(doc, nullptr);

        try
        {
            XML::XMLNode::Ptr node;
            size_t bytesRead;
            bytesRead = doc->parsePartial(payloadRef.slice(totalBytesRead), node);

            ASSERT_NE(node, nullptr);
            EXPECT_NE(bytesRead, 0UL);

            totalBytesRead += bytesRead;
            ++totalPayloads;
        }
        catch (const rapidxml::parse_error &err)
        {
            EXPECT_NO_THROW(throw err);
        }
    }
    while (totalBytesRead < payload.size());
    EXPECT_EQ(totalPayloads, 5UL);
}



