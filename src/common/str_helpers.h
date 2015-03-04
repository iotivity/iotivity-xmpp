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

/// @file str_helpers.h

#pragma once

#include <vector>
#include <string>

namespace Iotivity
{
    namespace str_helper
    {
        /// Split a string around a specific character. This is to work around missing
        /// regex features in the available compiler collection.
        std::vector<std::string> split(const std::string &str, const char splitChar);

        /// Quick implementation of UTF-8 to UTF-32 character conversion. This is provided
        /// to fill in the gap related to codecvt_utf8 missing on certain target platforms.
        /// @return The UTF-32 character conversion of the first UTF-8 character starting
        //          at fromChar. Returns 0x00 if the conversion is not valid (charsConsumed
        //          will be 0). Returns 0x00 if the conversion is valid from 0x00 (UTF-8)
        //          (charsConsumed will be 1 or greater).
        char32_t utf8ToUtf32(const char *fromChar, size_t forChars, size_t &charsConsumed);

        /// Quick implementation of UTF-32 to UTF-8 character conversion. This is provided
        /// to fill in the gap related to codecvt_utf8 missing on certain target platforms.
        /// @return true if the conversion was successful, false if there was insufficient
        ///              room to write the utf8 conversion into the output array.
        bool utf32ToUtf8(char32_t inChar, char *outFromChar, size_t forChars,
                         size_t &charsWritten);

    }
}