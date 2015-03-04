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

/// @file str_helpers.cpp

#include "stdafx.h"
#include "str_helpers.h"


using namespace std;

namespace Iotivity
{
    namespace str_helper
    {
        // Split a string around a specific character. This is to work around missing
        // regex features in the available compiler collection.
        vector<string> split(const std::string &str, const char splitChar)
        {
            vector<string> segments;
            size_t offset = 0;
            string::size_type loc = string::npos;
            do
            {
                loc = str.find(splitChar, offset);
                if (loc != string::npos)
                {
                    segments.push_back(str.substr(offset, loc - offset));
                    offset = loc + 1;
                }
                else
                {
                    segments.push_back(str.substr(offset));
                }
            }
            while (loc != string::npos && loc < str.size());

            return segments;
        }

        bool okayChar(unsigned char c) { return (c >> 6) == 0x2; }

        char32_t utf8ToUtf32(const char *fromChar, size_t forChars, size_t &charsConsumed)
        {
            // NOTE: If you modify this code block, make certain to run the _WIN32
            //       unit tests to ensure compliance with the codecvt_utf8 library.
            charsConsumed = 0;
            if (forChars < 1)
            {
                return 0;
            }
            const unsigned char *currentChar = reinterpret_cast<const unsigned char *>(fromChar);
            if (*currentChar <= 0x7F)
            {
                if (forChars >= 1)
                {
                    charsConsumed = 1;
                    return static_cast<char32_t>(*currentChar);
                }
            }
            else if ((*currentChar >> 5) == 0x6)
            {
                if (forChars >= 2 && okayChar(currentChar[1]))
                {
                    charsConsumed = 2;
                    return static_cast<char32_t>
                           ((currentChar[1] & 0x3F) |
                            ((currentChar[0] & 0x1F) << 6));
                }
            }
            else if ((*currentChar >> 4) == 0xE)
            {
                if (forChars >= 3 && okayChar(currentChar[1]) && okayChar(currentChar[2]))
                {
                    charsConsumed = 3;
                    return static_cast<char32_t>
                           ((currentChar[2] & 0x3F) |
                            ((currentChar[1] & 0x3F) << 6) |
                            ((currentChar[0] & 0x0F) << 12));
                }
            }
            else if ((*currentChar >> 3) == 0x1E)
            {
                if (forChars >= 4 && okayChar(currentChar[1]) &&
                    okayChar(currentChar[2]) && okayChar(currentChar[3]))
                {
                    char32_t result = static_cast<char32_t>
                                      ((currentChar[3] & 0x3F) |
                                       ((currentChar[2] & 0x3F) << 6) |
                                       ((currentChar[1] & 0x3F) << 12) |
                                       ((currentChar[0] & 0x07) << 18));
                    if (result <= 0x10FFFF)
                    {
                        charsConsumed = 4;
                        return result;
                    }
                    else
                    {
                        return 0;
                    }
                }
            }
            return 0;
        }

        bool utf32ToUtf8(char32_t inChar, char *outFromChar, size_t forChars,
                         size_t &charsWritten)
        {
            // NOTE: If you modify this code block, make certain to run the _WIN32
            //       unit tests to ensure compliance with the codecvt_utf8 library.

            // RFC3629
            // Char. number range  |        UTF-8 octet sequence
            //    (hexadecimal)    |              (binary)
            // --------------------+---------------------------------------------
            // 0000 0000-0000 007F | 0xxxxxxx
            // 0000 0080-0000 07FF | 110xxxxx 10xxxxxx
            // 0000 0800-0000 FFFF | 1110xxxx 10xxxxxx 10xxxxxx
            // 0001 0000-0010 FFFF | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
            //
            if (!outFromChar)
            {
                return false;
            }
            if (inChar <= 0x007F)
            {
                if (forChars >= 1)
                {
                    *outFromChar = static_cast<char>(inChar);
                    charsWritten = 1;
                }
            }
            else if (inChar <= 0x07FF)
            {
                if (forChars >= 2)
                {
                    outFromChar[0] = static_cast<char>(0xC0 | ((inChar >> 6) & 0x1F));
                    outFromChar[1] = static_cast<char>(0x80 | (inChar & 0x3F));
                    charsWritten = 2;
                }
            }
            else if (inChar <= 0xFFFF)
            {
                if (forChars >= 3)
                {
                    outFromChar[0] = static_cast<char>(0xE0 | ((inChar >> 12) & 0x0F));
                    outFromChar[1] = static_cast<char>(0x80 | ((inChar >> 6) & 0x3F));
                    outFromChar[2] = static_cast<char>(0x80 | (inChar & 0x3F));
                    charsWritten = 3;
                }
            }
            else if (inChar <= 0x10FFFF)
            {
                if (forChars >= 4)
                {
                    outFromChar[0] = static_cast<char>(0xF0 | ((inChar >> 18) & 0x07));
                    outFromChar[1] = static_cast<char>(0x80 | ((inChar >> 12) & 0x3F));
                    outFromChar[2] = static_cast<char>(0x80 | ((inChar >> 6) & 0x3F));
                    outFromChar[3] = static_cast<char>(0x80 | (inChar & 0x3F));
                    charsWritten = 4;
                }
            }
            // NOTE: Code points >0x010FFFF in UTF-8 are prohibited by RFC3629
            return false;
        }

    }
}
