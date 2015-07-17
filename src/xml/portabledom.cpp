///////////////////////////////////////////////////////////////////////////////
//
// Copyright 2013-2014 Intel Mobile Communications GmbH All Rights Reserved.
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

/// @file portableDOM.cpp


#include "stdafx.h"
#include "portabledom.h"
#include "../common/compatibility.h"
#include "../common/buffers.h"

#include <sstream>

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable: 4100)
#endif

#if defined(_WIN32) && !defined(_WINRT) && defined(PORTABLE_STACK)
#include <rapidxml/rapidxml_print.hpp>
#else
#include <rapidxml_print.hpp>
#endif

extern "C"
{
#if !defined(_WIN32)
#ifdef WITH_SAFE
#include <safe_mem_lib.h>
#include <safe_str_lib.h>
#endif
#endif
}

using namespace std;

// rapidxml_print uses templates that call functions without forward declarations.
// Adding forward declarations here to avoid changing the external code.
namespace rapidxml
{
    namespace Internal
    {
        template<class OutIt, class Ch>
        inline OutIt print_children(OutIt out, const xml_node<Ch> *node, int flags, int indent);
        template<class OutIt, class Ch>
        inline OutIt print_data_node(OutIt out, const xml_node<Ch> *node, int flags, int indent);
        template<class OutIt, class Ch>
        inline OutIt print_element_node(OutIt out, const xml_node<Ch> *node, int flags, int indent);
        template<class OutIt, class Ch>
        inline OutIt print_declaration_node(OutIt out, const xml_node<Ch> *node, int flags, int indent);
        template<class OutIt, class Ch>
        inline OutIt print_comment_node(OutIt out, const xml_node<Ch> *node, int flags, int indent);
        template<class OutIt, class Ch>
        inline OutIt print_doctype_node(OutIt out, const xml_node<Ch> *node, int flags, int indent);
        template<class OutIt, class Ch>
        inline OutIt print_pi_node(OutIt out, const xml_node<Ch> *node, int flags, int indent);
        template<class OutIt, class Ch>
        inline OutIt print_cdata_node(OutIt out, const xml_node<Ch> *node, int flags, int indent);
    }
}

#ifdef _WIN32
#include <codecvt>
#endif

#ifdef _WIN32
#pragma warning(pop)
#endif

#ifndef __KLOCWORK__
# include "../common/banned.h"
#endif
using namespace rapidxml;

namespace Iotivity
{

    bool operator==(const std::string &nodeName, _xml_name xmlName)
    {
        bool equal = false;

        size_t pos = nodeName.find(':');
        if (pos != std::string::npos)
        {
            equal = nodeName.substr(pos) == xmlName.m_compareName;
        }
        else
        {
            equal = nodeName == xmlName.m_compareName;
        }
        return equal;
    }

    bool operator!=(const std::string &nodeName, _xml_name xmlName) { return !(operator==(nodeName, xmlName)); }

    namespace XML
    {

        XMLDocument::XMLAttribute::XMLAttribute(XMLDocument::Ptr document,
                                                rapidxml::xml_attribute<> &attr): m_document(document), m_sourceAttr(attr) {}

        std::string XMLDocument::XMLAttribute::name() const
        {
            const char *nameStr = m_sourceAttr.name();
            return nameStr ? nameStr : "";
        }

        std::string XMLDocument::XMLAttribute::value() const
        {
            const char *valStr = m_sourceAttr.value();
            return valStr ? valStr : "";
        }

        void XMLDocument::XMLAttribute::setValue(const std::string &val)
        {
            setValue(val.c_str(), val.length());
        }

        void XMLDocument::XMLAttribute::setValue(const char *str, size_t length)
        {
            if (m_document)
            {
                char *allocVal = document().allocate_string(str, length + 1);
                if (allocVal)
                {
                    m_sourceAttr.value(allocVal, length);
                }
            }
        }

        XMLDocument::XMLNode::XMLNode(XMLDocument::Ptr document, xml_node<> &node): m_document(document),
            m_sourceNode(node) {}

        std::string XMLDocument::XMLNode::name() const
        {
            const char *nameStr = m_sourceNode.name();
            return nameStr ? nameStr : "";
        }

        std::string XMLDocument::XMLNode::value() const
        {
            const char *valStr = m_sourceNode.value();
            return valStr ? valStr : "";
        }

        std::string XMLDocument::XMLNode::xml() const
        {
            std::ostringstream os;
            print(std::ostream_iterator<std::ostringstream::char_type>(os), m_sourceNode, print_no_indenting);
            return os.str();
        }

        std::string XMLDocument::XMLNode::unterminatedXML() const
        {
            std::ostringstream os;
            // We could print the XML and then remove the terminating characters, but instead
            // we will use a locally defined flag to avoid copying the whole string. This flag
            // will need to be reimported into newer versions of the rapidxml library
            // unless this function is reworked.
            print(std::ostream_iterator<std::ostringstream::char_type>(os), m_sourceNode,
                  print_no_indenting | print_no_ending);
            return os.str();
        }


        XMLDocument::XMLNode::NodeList XMLDocument::XMLNode::selectNodes(const std::string &pattern) const
        {
            XMLDocument::XMLNode::NodeList nodeList;
            xml_node<> *current = node().first_node(pattern.c_str(), pattern.size());
            while (current)
            {
                if (current->type() == node_element)
                {
                    nodeList.push_back(XMLNode::Ptr(new XMLElement(m_document, *current)));
                }
                else
                {
                    nodeList.push_back(XMLNode::Ptr(new XMLNode(m_document, *current)));
                }
                current = current->next_sibling(pattern.c_str(), pattern.size());
            }
            return nodeList;
        }

        XMLDocument::XMLNode::NodeList XMLDocument::XMLNode::nodes() const
        {
            XMLDocument::XMLNode::NodeList nodeList;
            xml_node<> *current = node().first_node();
            while (current)
            {
                if (current->type() == node_element)
                {
                    nodeList.push_back(XMLNode::Ptr(new XMLElement(m_document, *current)));
                }
                else
                {
                    nodeList.push_back(XMLNode::Ptr(new XMLNode(m_document, *current)));
                }
                current = current->next_sibling();
            }
            return nodeList;
        }

        XMLDocument::XMLAttribute::AttributeList XMLDocument::XMLNode::attributes() const
        {
            XMLDocument::XMLAttribute::AttributeList attrList;
            xml_attribute<> *current = node().first_attribute();
            while (current)
            {
                attrList.push_back(XMLAttribute::Ptr(new XMLAttribute(m_document, *current)));
                current = current->next_attribute();
            }
            return attrList;
        }

        std::string XMLDocument::XMLNode::findNamespace(const std::string &namespaceURL)
        {
            static const std::string XMLNS_PREFIX("xmlns:");
            std::string name;
            xml_attribute<> *current = node().first_attribute();
            while (current)
            {
                std::string attrName = current->name();
                if (attrName.size() > 6 &&
                    attrName.compare(0, 6, XMLNS_PREFIX) == 0 &&
                    current->value() == namespaceURL)
                {
                    name = attrName.substr(6);
                    break;
                }
                current = current->next_attribute();
            }

            return name;
        }

        /*
        bool XMLDocument::XMLNode::appendChild(XMLNode::Ptr &child)
        {
            bool appended = false;
            if (child)
            {
                if (&document() == &child->document())
                {
                    m_sourceNode.append_node(&child->m_sourceNode);
                    appended = true;
                }
            }
            return appended;
        }
        */

        void XMLDocument::XMLNode::setValue(const std::string &val)
        {
            setValue(val.c_str(), val.size());
        }

        void XMLDocument::XMLNode::setValue(const char *str, size_t length)
        {
            if (m_document)
            {
                char *allocVal = document().allocate_string(str, length + 1);
                if (allocVal)
                {
                    m_sourceNode.value(allocVal, length);
                }
            }
        }

        bool XMLDocument::XMLNode::hasAttribute(const string &name) const
        {
            return node().first_attribute(name.c_str(), name.size()) != nullptr;
        }

        XMLDocument::XMLAttribute::Ptr XMLDocument::XMLNode::getAttribute(const string &name) const
        {
            XMLDocument::XMLAttribute::Ptr attribute;
            xml_attribute<> *first = node().first_attribute(name.c_str(), name.size());
            if (first)
            {
                attribute.reset(new XMLDocument::XMLAttribute(m_document, *first));
            }
            return attribute;
        }

        bool XMLDocument::XMLNode::doGetAttribute(const string &name, stringstream &os) const
        {
            rapidxml::xml_attribute<> *first =
                node().first_attribute(name.c_str(), name.size());

            if (!first)
            {
                return false;
            }

            os << first->value();
            os.seekg(0);
            return true;
        }

        bool XMLDocument::XMLNode::doSetAttribute(const string &name, const ostringstream &os)
        {
            string value = os.str();
            char *allocName = document().allocate_string(name.c_str(),
                              name.size() + 1);
            char *allocVal = document().allocate_string(value.c_str(),
                             value.size() + 1);
            if (allocName && allocVal)
            {
                rapidxml::xml_attribute<> *newAttr =
                    document().allocate_attribute(allocName, allocVal,
                                                  name.size(), value.size());
                if (newAttr)
                {
                    node().append_attribute(newAttr);
                    return true;
                }
            }

            // NOTE: Because the allocate_string is pulling the strings from
            //       a pool owned by the XML document, the document will free
            //       them as it's destroyed. Don't free them on failure to
            //       allocate, either.
            return false;
        }


        template <> bool XMLNode::getAttribute(const std::string &name, uint8_t &byteVal) const
        {
            bool get = false;
            uint32_t val;
            if (getAttribute(name, val))
            {
                byteVal = (uint8_t)val;
                get = true;
            }
            return get;
        }

        template <> bool XMLNode::getAttribute(const std::string &name, int8_t &byteVal) const
        {
            bool get = false;
            int32_t val;
            if (getAttribute(name, val))
            {
                byteVal = (int8_t)val;
                get = true;
            }
            return get;
        }

        template <> bool XMLNode::getAttribute(const std::string &name, uint64_t &val) const
        {
            bool get = false;
            std::string tempVal;
            if (getAttribute(name, tempVal))
            {
                val = strtoull(tempVal.c_str(), nullptr, 10);
                get = true;
            }
            return get;
        }

#if defined(_WIN32) && !defined(_WINRT)
        template <> bool XMLNode::getAttribute(const std::string &name, std::wstring &str) const
        {
            bool get = false;
            std::string valStr;
            if (getAttribute(name, valStr))
            {
                std::wstring_convert< std::codecvt_utf8_utf16<wchar_t>, wchar_t > converter;
                str = converter.from_bytes(valStr);
                get = true;
            }
            return get;
        }
#endif

        template <> bool XMLNode::setAttribute(const std::string &name, const uint8_t &byteVal)
        {
            return setAttribute(name, (unsigned int)byteVal);
        }

        template <> bool XMLNode::setAttribute(const std::string &name, const int8_t &byteVal)
        {
            return setAttribute(name, (signed int)byteVal);
        }


        XMLDocument::XMLElement::XMLElement(XMLDocument::Ptr document, xml_node<> &node): XMLNode(document,
                    node) {}


        XMLDocument::XMLElement::Ptr XMLDocument::XMLElement::createElement(XMLDocument::Ptr document,
                const std::string &name)
        {
            XMLElement::Ptr element;
            if (document)
            {
                char *allocName = document->document().allocate_string(name.c_str(), name.size() + 1);
                if (allocName)
                {
                    xml_node<> *node = document->document().allocate_node(node_element, allocName, 0, name.size());
                    if (node)
                    {
                        element.reset(new XMLElement(document, *node));
                    }
                }
            }
            return element;
        }

        XMLDocument::XMLElement::ElementList XMLDocument::XMLElement::elements() const
        {
            XMLDocument::XMLElement::ElementList elementList;
            xml_node<> *current = node().first_node();
            while (current)
            {
                if (current->type() == node_element)
                {
                    elementList.push_back(XMLElement::Ptr(new XMLElement(m_document, *current)));
                }
                current = current->next_sibling();
            }
            return elementList;
        }

        XMLDocument::XMLDocument(): m_sourceStr(0) {}

        XMLDocument::Ptr XMLDocument::createEmptyDocument(DocumentFlags flags)
        {
            XMLDocument::Ptr doc(new XMLDocument);
            if (flags & DocumentFlags::dfIncludeDeclaration)
            {
                std::string name = "xml";
                char *allocName = doc->document().allocate_string(name.c_str(), name.size() + 1);
                if (allocName)
                {
                    xml_node<> *node = doc->document().allocate_node(node_declaration, allocName, 0, name.size());

                    if (node)
                    {
                        XMLNode tempNode(doc, *node);
                        tempNode.setAttribute("version", "1.0");
                        tempNode.setAttribute("encoding", "UTF-8");

                        doc->document().append_node(node);
                    }
                }
            }
            return doc;
        }

        XMLElement::Ptr XMLDocument::documentElement()
        {
            XMLElement::Ptr element;
            xml_node<> *current = m_sourceDoc.first_node();
            while (current)
            {
                if (current->type() == node_element)
                {
                    element.reset(new XMLElement(shared_from_this(), *current));
                    break;
                }
                current = current->next_sibling();
            }
            return element;
        }

        /*
        bool XMLDocument::appendChild(XMLNode::Ptr child)
        {
            bool appended = false;
            if (child)
            {
                xml_node<> &node = child->node();
                if (&document() == &m_sourceDoc)
                {
                    m_sourceDoc.append_node(&node);
                    appended = true;
                }
            }
            return appended;
        }
        */

        // Adapted from rapidxml.
        template <typename Ch> xml_node<Ch> *deep_clone_node(const xml_node<Ch> *source,
                xml_document<Ch> &destDoc)
        {
            xml_node<Ch> *result = 0;
            if (source)
            {
                result = destDoc.allocate_node(source->type());

                char *allocName = destDoc.allocate_string(source->name(), source->name_size() + 1);
                if (allocName)
                {
                    allocName[source->name_size()] = '\0';
                    result->name(allocName, source->name_size());
                }
                char *allocVal = destDoc.allocate_string(source->value(), source->value_size() + 1);
                if (allocVal)
                {
                    allocVal[source->value_size()] = '\0';
                    result->value(allocVal, source->value_size());
                }

                for (xml_node<Ch> *child = source->first_node(); child; child = child->next_sibling())
                {
                    result->append_node(deep_clone_node(child, destDoc));
                }
                for (xml_attribute<Ch> *attr = source->first_attribute(); attr; attr = attr->next_attribute())
                {
                    char *allocName = destDoc.allocate_string(attr->name(), attr->name_size() + 1);
                    char *allocVal = destDoc.allocate_string(attr->value(), attr->value_size() + 1);
                    if (allocName && allocVal)
                    {
                        allocName[attr->name_size()] = '\0';
                        allocVal[attr->value_size()] = '\0';
                        result->append_attribute(destDoc.allocate_attribute(allocName, allocVal, attr->name_size(),
                                                 attr->value_size()));
                    }
                }
            }
            return result;
        }

        XMLNode::Ptr XMLDocument::importNode(const XMLNode &source)
        {
            XMLNode::Ptr clone;
            xml_node<> *nodeClone = deep_clone_node(&source.node(), document());
            if (nodeClone)
            {
                if (nodeClone->type() == node_element)
                {
                    clone.reset(new XMLElement(shared_from_this(), *nodeClone));
                }
                else
                {
                    clone.reset(new XMLNode(shared_from_this(), *nodeClone));
                }
            }
            return clone;
        }

        XMLDocument::XMLElement::Ptr XMLDocument::createElement(const std::string &name)
        {
            return XMLElement::createElement(shared_from_this(), name);
        }

        std::string XMLDocument::xml() const
        {
            std::ostringstream os;
            print(std::ostream_iterator<std::ostringstream::char_type>(os), m_sourceDoc,
                  print_no_indenting);
            return os.str();
        }

        std::string XMLDocument::unterminatedXml() const
        {
            std::ostringstream os;
            print(std::ostream_iterator<std::ostringstream::char_type>(os), m_sourceDoc,
                  print_no_indenting | print_no_ending);
            return os.str();
        }

        size_t XMLDocument::parsePartial(const std::string &srcXML, XMLNode::Ptr &outNode)
        {
            size_t bytesRead = 0;
            m_sourceStr = m_sourceDoc.allocate_string(srcXML.c_str(), srcXML.size() + 1);
            if (m_sourceStr)
            {
                m_sourceDoc.parse(m_sourceStr, bytesRead, parse_stop_at_next_sibling);
                outNode = documentElement();
            }
            return bytesRead;
        }

        size_t XMLDocument::parsePartial(const ByteBuffer &utf8SrcBuffer, XMLNode::Ptr &outNode)
        {
            size_t bytesRead = 0;
            size_t size = utf8SrcBuffer.size();
            m_sourceStr = m_sourceDoc.allocate_string(0, size + 1);
            if (m_sourceStr)
            {
                memcpy(m_sourceStr, (const void *)utf8SrcBuffer, size);
                m_sourceStr[size] = 0;
                m_sourceDoc.parse(m_sourceStr, bytesRead, parse_stop_at_next_sibling);
                outNode = documentElement();
            }
            return bytesRead;
        }


        void XMLDocument::parse(const std::string &srcXML, EndingTest ending)
        {
            m_sourceStr = m_sourceDoc.allocate_string(srcXML.c_str(), srcXML.size() + 1);
            if (m_sourceStr)
            {
                m_sourceDoc.parse(m_sourceStr, ending == EndingTest::IgnoreEnding ?
                                  parse_default : parse_validate_closing_tags);
            }
        }

        void XMLDocument::parse(const ByteBuffer &utf8SrcBuffer, EndingTest ending)
        {
            size_t size = utf8SrcBuffer.size();
            m_sourceStr = m_sourceDoc.allocate_string(0, size + 1);
            if (m_sourceStr)
            {
                memcpy(m_sourceStr, (const void *)utf8SrcBuffer, size);
                m_sourceStr[size] = 0;
                m_sourceDoc.parse(m_sourceStr, ending == EndingTest::IgnoreEnding ?
                                  parse_default : parse_validate_closing_tags);
            }
        }

        void XMLDocument::parse(ifstream &rawInputStream, EndingTest ending)
        {
            std::string tempStr;
            if (decodeRawStreamToUTF8(rawInputStream, tempStr) && tempStr.size() > 0)
            {
                parse(tempStr, ending);
            }
        }

        bool XMLDocument::decodeRawStreamToUTF8(std::ifstream &is, std::string &outStr)
        {
            bool decoded = false;
            if (is.good())
            {
                std::stringstream tempStream;
                tempStream << is.rdbuf();

                size_t startSeekPos = 0;
                // Look for a byte order mark. We currently only support UTF-8/16/32
                int b1 = tempStream.get();
                int b2 = tempStream.get();
                int b3 = tempStream.get();
                int b4 = tempStream.get();
                enum class Format
                {
                    ASCII,
                    UTF8,
                    UTF16,
                    UTF32
                } format = Format::ASCII;
#ifdef _WIN32
                bool littleEndian = true;
#endif
                if (b1 == 0x00 && b2 == 0x00 && b3 == 0xFE && b4 == 0xFF)
                {
                    format = Format::UTF32;
#ifdef _WIN32
                    littleEndian = false;
#endif
                    startSeekPos = 4;
                }
                else if (b1 == 0xFF && b2 == 0xFE && b3 == 0x00 && b4 == 0x00)
                {
                    format = Format::UTF32;
                    startSeekPos = 4;
                }
                else if (b1 == 0x00 && b2 == 0x00 && b3 == 0x00 && b4 == '<')
                {
                    int b5 = tempStream.get();
                    int b6 = tempStream.get();
                    int b7 = tempStream.get();
                    int b8 = tempStream.get();
                    if (b5 == 0x00 && b6 == 0x00 && b7 == 0x00 && b8 == '?')
                    {
                        format = Format::UTF32;
#ifdef _WIN32
                        littleEndian = false;
#endif
                    }
                }
                else if (b1 == '<' && b2 == 0x00 && b3 == 0x00 && b4 == 0x00)
                {
                    int b5 = tempStream.get();
                    int b6 = tempStream.get();
                    int b7 = tempStream.get();
                    int b8 = tempStream.get();
                    if (b5 == '?' && b6 == 0x00 && b7 == 0x00 && b8 == 0x00)
                    {
                        format = Format::UTF32;
                    }
                }
                else if (b1 == 0xFE && b2 == 0xFF)
                {
                    format = Format::UTF16;
#ifdef _WIN32
                    littleEndian = false;
#endif
                    startSeekPos = 2;
                }
                else if (b1 == 0xFF && b2 == 0xFE)
                {
                    format = Format::UTF16;
                    startSeekPos = 2;
                }
                else if (b1 == 0 && b2 == '<' && b3 == 0 && b4 == '?')
                {
                    format = Format::UTF16;
#ifdef _WIN32
                    littleEndian = false;
#endif
                }
                else if (b1 == '<' && b2 == 0 && b3 == '?' && b4 == 0)
                {
                    format = Format::UTF16;
                }
                else if (b1 == 0xEF && b2 == 0xBB && b3 == 0xBF)
                {
                    format = Format::UTF8;
                    startSeekPos = 3;
                }
                else if (b1 == '<' && b2 == '?')
                {
                    format = Format::UTF8;
                }

                tempStream.clear();
                tempStream.seekg(startSeekPos);

                switch (format)
                {
                    case Format::ASCII:
                    case Format::UTF8:
                        outStr = tempStream.str();
                        break;
                    case Format::UTF16:
#ifdef _WIN32
                        {
                            std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
                            while (tempStream.good())
                            {
                                char16_t c = 0;
                                tempStream.read((char *)&c, sizeof(c));
                                if (!littleEndian)
                                {
                                    swap_byte_array(&c, sizeof(c));
                                }
                                if (tempStream.good())
                                {
                                    outStr += convert.to_bytes(c);
                                }
                            }
                        }
#endif
                        break;
                    case Format::UTF32:
#ifdef _WIN32
                        {
                            std::wstring_convert<std::codecvt_utf8_utf16<char32_t>, char32_t> convert;
                            while (!tempStream.eof())
                            {
                                char32_t c = 0;
                                tempStream.read((char *)&c, sizeof(c));
                                if (!littleEndian)
                                {
                                    swap_byte_array(&c, sizeof(c));
                                }
                                if (tempStream.good())
                                {
                                    outStr += convert.to_bytes(c);
                                }
                            }
                        }
#endif
                        break;
                }

                decoded = outStr.size() > 0;
            }
            return decoded;
        }
    }

}
