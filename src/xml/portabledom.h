///////////////////////////////////////////////////////////////////////////////
//
// Copyright 2013-2015 Intel Mobile Communications GmbH All Rights Reserved.
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

/// @file portableDOM.h


#pragma once

#include "../include/xmpp_feature_flags.h"
#include "../include/ccfxmpp.h"

#if defined(_WIN32) && !defined(_WINRT) && defined(PORTABLE_STACK)
#include <rapidxml/rapidxml.hpp>
#else
#include <rapidxml.hpp>
#endif

#include <fstream>
#include <map>
#include <mutex>
#include <memory>
#include <list>
#include <sstream>

typedef std::recursive_mutex local_recursive_mutex;



namespace Iotivity
{
    namespace XML
    {
        class XMLDocument;
    }
}

#ifdef _WIN32
XMPP_TEMPLATE template class XMPP_API std::weak_ptr<Iotivity::XML::XMLDocument>;
class XMPP_API std::recursive_mutex;
XMPP_TEMPLATE template class XMPP_API rapidxml::xml_document<>;
#endif



namespace Iotivity
{
    class ByteBuffer;

    /// @brief Represents an XML name sans namespace identifier.
    ///
    /// Used to provide an intuitive way of comparing XML element names while ignoring
    /// namespaces. (e.g. _T("xmlns:test")==_xml_name("test"))
    class _xml_name
    {
        public:
            /// Constructs an _xml_name given a pointer to the TCHAR string representing the name of the
            /// xml element without an explicit namespace.
            _xml_name(const char *name): m_compareName(name) {}

            friend bool operator==(const std::string &nodeName, _xml_name xmlName);
            friend bool operator!=(const std::string &nodeName, _xml_name xmlName);

        private:
            const char *m_compareName;
    };

    bool operator==(const std::string &nodeName, _xml_name xmlName);
    bool operator!=(const std::string &nodeName, _xml_name xmlName);

    namespace XML
    {

        /// @brief Wrapper to massage the syntax of the RapidXML document type towards
        /// the MSXML API and to manage the lifespan of the XML source strings.
        class XMPP_API XMLDocument: public std::enable_shared_from_this<XMLDocument>
        {
            public:
                enum class EndingTest
                {
                    TestEnding,
                    IgnoreEnding
                };
                typedef std::shared_ptr<XMLDocument> Ptr;

                enum DocumentFlags
                {
                    dfNone               = 0x0000,
                    dfIncludeDeclaration = 0x0001,
                };

                class XMLNode;
                /// @brief Class which wraps an XML attribute under an XML node.
                ///
                /// @note This is for iterating the attributes of a node. Directly calling
                /// setAttribute and getAttribute on existing node instances is more
                /// efficient and should be prefered.
                class XMLAttribute
                {
                    public:
                        typedef std::unique_ptr<XMLAttribute> Ptr;
                        typedef std::list<XMLAttribute::Ptr> AttributeList;
                    public:
                        virtual ~XMLAttribute() {}

                        rapidxml::xml_document<> &document() { return m_document->document(); }
                        const rapidxml::xml_document<> &document() const
                        {
                            return m_document->document();
                        }

                        rapidxml::xml_attribute<> &attribute() { return m_sourceAttr; }
                        const rapidxml::xml_attribute<> &attribute() const { return m_sourceAttr; }

                        std::string name() const;
                        std::string value() const;

                        void setValue(const std::string &val);
                        void setValue(const char *str, size_t length);

                    protected:
                        XMLAttribute(XMLDocument::Ptr document, rapidxml::xml_attribute<> &attr);

                    private:
                        XMLAttribute &operator=(const XMLAttribute &) = delete;

                        XMLDocument::Ptr                 m_document;
                        rapidxml::xml_attribute<>       &m_sourceAttr;

                        // To allow importNode to function without exposing the XMLNode
                        // protected constructor.
                        friend class XMLDocument::XMLNode;
                };

                /// @brief Wrapper for a rapidxml xml_node instance. Provides features common
                ///        to all rapidxml XML nodes.
                class XMLNode
                {
                    public:
                        typedef std::unique_ptr<XMLNode> Ptr;
                        typedef std::list<XMLNode::Ptr> NodeList;

                    public:
                        virtual ~XMLNode() {}

                        XMLDocument::Ptr owner() const { return m_document; }

                        rapidxml::xml_document<> &document() { return m_document->document(); }
                        const rapidxml::xml_document<> &document() const { return m_document->document(); }

                        rapidxml::xml_node<> &node() { return m_sourceNode; }
                        const rapidxml::xml_node<> &node() const { return m_sourceNode; }


                        NodeList selectNodes(const std::string &pattern) const;
                        NodeList nodes() const;
                        XMLAttribute::AttributeList attributes() const;

                        // Find the prefix used to describe a namespace given the URL defines it.
                        // Returns an empty string if no such namespace was found.
                        std::string findNamespace(const std::string &namespaceURL);

                        std::string name() const;
                        std::string value() const;

                        std::string xml() const;
                        std::string unterminatedXML() const;

                        template <typename T> bool appendChild(std::unique_ptr<T> &child)
                        {
                            if (child)
                            {
                                if (&this->document() == &child->document())
                                {
                                    this->m_sourceNode.append_node(&child->m_sourceNode);
                                    return true;
                                }
                            }
                            return false;
                        }

                        void setValue(const std::string &val);
                        void setValue(const char *str, size_t length);

                        bool hasAttribute(const std::string &name) const;
                        XMLAttribute::Ptr getAttribute(const std::string &name) const;

                        template <typename _Type>
                        bool getAttribute(const std::string &name, _Type &type) const
                        {
                            std::stringstream os;

                            if (this->doGetAttribute(name, os))
                            {
                                try
                                {
                                    os >> type;
                                }
                                catch (...)
                                {
                                    return false;
                                }
                                return true;
                            }
                            return false;
                        }

                        template <typename _Type>
                        bool setAttribute(const std::string &name, const _Type &type)
                        {
                            try
                            {
                                std::ostringstream os;
                                os << type;
                                return this->doSetAttribute(name, os);
                            }
                            catch (...)
                            {
                                return false;
                            }
                        }

                    protected:
                        XMLNode(XMLDocument::Ptr document, rapidxml::xml_node<> &node);

                        bool doGetAttribute(const std::string &name, std::stringstream &os) const;

                        bool doSetAttribute(const std::string &name,
                                            const std::ostringstream &val);

                    private:
                        XMLNode &operator=(const XMLNode &) = delete;

                        XMLDocument::Ptr                 m_document;
                        rapidxml::xml_node<>            &m_sourceNode;

                        // To allow importNode to function without exposing the XMLNode
                        // protected constructor.
                        friend class XMLDocument;
                };

                /// @brief Wrapper for a rapidxml xml_node instance. Provides features specific
                ///        to rapidxml element nodes.
                class XMLElement: public XMLNode
                {
                    public:
                        typedef std::unique_ptr<XMLElement> Ptr;
                        typedef std::list<XMLElement::Ptr> ElementList;

                        static XMLElement::Ptr createElement(XMLDocument::Ptr document, const std::string &name);
                        ElementList elements() const;
                    protected:
                        XMLElement(XMLDocument::Ptr document, rapidxml::xml_node<> &node);
                    private:
                        // To allow importNode to function without exposing the XMLElement
                        // protected constructor.
                        friend class XMLDocument;
                };

                // NOTE: Repeated calls to acquire the document element will return an XMLElement::Ptr reference the
                //       same document node, but the XMLElement::Ptr may not be the same object.
                XMLElement::Ptr documentElement();

                static XMLDocument::Ptr createEmptyDocument(DocumentFlags flags =
                            DocumentFlags::dfNone);
                XMLElement::Ptr createElement(const std::string &name);

                template <typename T> bool appendChild(std::unique_ptr<T> &child)
                {
                    if (child)
                    {
                        rapidxml::xml_node<> &node = child->node();
                        if (&child->document() == &this->m_sourceDoc)
                        {
                            this->m_sourceDoc.append_node(&node);
                            return true;
                        }
                    }
                    return false;
                }

                XMLNode::Ptr importNode(const XMLNode &source);

                // May throw rapidxml::parse_error or std::bad_alloc.
                void parse(const std::string &srcXML, EndingTest ending = EndingTest::TestEnding);
                void parse(const ByteBuffer &utf8SrcBuffer,
                           EndingTest ending = EndingTest::TestEnding);
                void parse(std::ifstream &rawInputStream,
                           EndingTest ending = EndingTest::TestEnding);

                size_t parsePartial(const std::string &srcXML, XMLNode::Ptr &outNode);
                size_t parsePartial(const ByteBuffer &utf8SrcBuffer, XMLNode::Ptr &outNode);

                std::string xml() const;
                std::string unterminatedXml() const;

                rapidxml::xml_document<> &document() { return m_sourceDoc; }
                const rapidxml::xml_document<> &document() const { return m_sourceDoc; }

            protected:
                XMLDocument();

                bool decodeRawStreamToUTF8(std::ifstream &is, std::string &outStr);

            private:
                mutable local_recursive_mutex    m_cs;
                char                            *m_sourceStr;
                rapidxml::xml_document<>         m_sourceDoc;
        };

        typedef XMLDocument::XMLElement XMLElement;
        typedef XMLDocument::XMLNode XMLNode;
        typedef XMLDocument::XMLAttribute XMLAttribute;


        template <> bool XMLNode::getAttribute(const std::string &name, uint8_t &byteVal) const;
        template <> bool XMLNode::getAttribute(const std::string &name, int8_t &byteVal) const;
        template <> bool XMLNode::getAttribute(const std::string &name, uint64_t &val) const;

#if defined(_WIN32) && !defined(_WINRT)
        template <> bool XMLNode::getAttribute(const std::string &name, std::wstring &str) const;
#endif

        template <> bool XMLNode::setAttribute(const std::string &name, const uint8_t &byteVal);
        template <> bool XMLNode::setAttribute(const std::string &name, const int8_t &byteVal);
    }


}
