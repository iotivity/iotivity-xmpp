//******************************************************************
//
// Copyright 2005-2014 Intel Mobile Communications GmbH All Rights Reserved.
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
//******************************************************************
// File name:
//     buffers.cpp
//
// Description:
//     Implementation for IoTivity data buffer helper classes
//
//
//
//*********************************************************************


#include "stdafx.h"

#define __EXPORTDLL__

#include "buffers.h"
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>

extern "C"
{
#if !defined(_WIN32)
#ifdef WITH_SAFE
#include <safe_mem_lib.h>
#include <safe_str_lib.h>
#endif
#endif
}

#ifdef WINCE
#include <dbgapi.h>
#endif
#ifndef __KLOCWORK__
#include "banned.h"
#endif

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif


// Apply the following define in order to have the
// ByteBuffer (and its inheritors) grow buffers exponentially
// rather than linearly as bytes get added (for efficiency)
#define RESERVE_BUFFER_IN_GEOMETRIC_CHUNKS

namespace Iotivity
{

    //////////
    // ByteBuffer
    //
    ByteBuffer::ByteBuffer():
        m_flags(bfDefault),
        m_ptr(0),
        m_bufferAllocation(0),
        m_bufferSize(0)
    {
    }

    ByteBuffer::ByteBuffer(size_t size, bool clearBuffer):
        m_flags(bfDefault),
        m_ptr(0),
        m_bufferAllocation(0),
        m_bufferSize(0)
    {
        // Make a buffer of size bytes and clear it
        if (resizeBuffer(size))
        {
            if (clearBuffer)
            {
                ::memset(m_ptr, 0, size);
            }
            m_bufferSize = size;
        }
    }

    ByteBuffer::ByteBuffer(const void *buf, size_t size):
        m_flags(bfDefault),
        m_ptr(0),
        m_bufferAllocation(0),
        m_bufferSize(0)
    {
        setBuffer(buf, size, true);
    }

    ByteBuffer::ByteBuffer(void *buf, size_t size, bool bufferOwnsPtr):
        m_flags(bfDefault),
        m_ptr(0),
        m_bufferAllocation(0),
        m_bufferSize(0)
    {
        setBuffer(buf, size, bufferOwnsPtr);
    }

    ByteBuffer::ByteBuffer(const ByteBuffer &buffer):
        m_flags(buffer.m_flags),
        m_ptr(0),
        m_bufferAllocation(0),
        m_bufferSize(0)
    {
        // If the originating buffer points to an externally-owned pointer,
        // make this instance also point to that pointer.
        if (buffer.m_flags & bfExternalPtr)
        {
            m_ptr = buffer.m_ptr;
            m_bufferSize = buffer.m_bufferSize;
            m_bufferAllocation = buffer.m_bufferAllocation;
        }
        // Otherwise set the buffer to the contents of buffer
        else
        {
            setBuffer(buffer.m_ptr, buffer.m_bufferSize, true);
        }
    }

    ByteBuffer::ByteBuffer(ByteBuffer &&buffer):
        m_flags(buffer.m_flags),
        m_ptr(buffer.m_ptr),
        m_bufferAllocation(buffer.m_bufferAllocation),
        m_bufferSize(buffer.m_bufferSize)
    {
        buffer.m_flags = 0;
        buffer.m_ptr = nullptr;
        buffer.m_bufferAllocation = 0;
        buffer.m_bufferSize = 0;
    }

    ByteBuffer::~ByteBuffer()
    {
        freeBuffer();
    }

    unsigned long ByteBuffer::hash() const
    {
        unsigned long hashValue = 0;

        // djb2 variant k==33 hash
        if (m_ptr && m_bufferSize)
        {
            hashValue = 5381;
            const unsigned char *end = (const unsigned char *)m_ptr + m_bufferSize;

            for (const unsigned char *c = (const unsigned char *)m_ptr; c < end; ++c)
            {
                hashValue = ((hashValue << 5) + hashValue) + *c; // hash * 33 + *c
            }
        }
        return hashValue;
    }

    bool ByteBuffer::operator==(const ByteBuffer &buffer) const
    {
        return size() == buffer.size() ? !memcmp(*this, buffer, size()) : false;
    }

    unsigned char &ByteBuffer::operator[](size_t pos)
    {
        if (pos < size())
        {
            return ((unsigned char *)m_ptr)[pos];
        }
        else if (reserve(pos + 1))
        {
            return ((unsigned char *)m_ptr)[pos];
        }
        else
        {
            std::ostringstream os;
            os << "ByteBuffer[" << pos << "] out of bounds (MAX=" << size() << ")";
            throw std::range_error(os.str());
        }
    }

    bool ByteBuffer::operator<(const ByteBuffer &buf) const
    {
        return size() == buf.size() ? memcmp(*this, buf, size()) < 0 : size() < buf.size();
    }

    ByteBuffer &ByteBuffer::operator=(const ByteBuffer &buffer)
    {
        // First clear the contents of this buffer.
        freeBuffer();

        m_flags = buffer.m_flags;
        // If the buffer doesn't own its pointer, just assign the pointer
        if (buffer.m_flags & bfExternalPtr)
        {
            m_ptr              = buffer.m_ptr;
            m_bufferAllocation = buffer.m_bufferAllocation;
            m_bufferSize       = buffer.m_bufferSize;
        }
        // ...otherwise copy the contents of the buffer
        else
        {
            setBuffer(buffer.m_ptr, buffer.m_bufferAllocation, true);
            m_bufferSize = buffer.m_bufferSize;
        }
        return *this;
    }

    bool ByteBuffer::bufferOwnsPointer() const
    {
        return !(m_flags & bfExternalPtr);
    }

    bool ByteBuffer::remove(size_t fromPosition, size_t toPosition)
    {
        bool removed = false;
        // If the buffer owns its pointer...
        if (!(m_flags & bfExternalPtr))
        {
            // ...and the position is in range and valid
            if (toPosition >= fromPosition && toPosition < m_bufferSize)
            {
                // Cut out the region from fromPosition to toPosition inclusive.
                memmove(&((unsigned char *)m_ptr)[fromPosition], &((unsigned char *)m_ptr)[toPosition + 1],
                        m_bufferSize - toPosition - 1);
                removed = reserve(m_bufferSize - (toPosition + 1 - fromPosition));
            }
        }
        return removed;
    }

    bool ByteBuffer::setBuffer(const void *buf, size_t size, bool bufferOwnsPtr)
    {
        bool set = false;

        // If we don't own the underlying pointer, release it (zero it)
        if (m_flags & bfExternalPtr)
        {
            freeBuffer();
        }

        // If the buffer will own its pointer, allocate the memory for the
        // buffer and assign it the contents of buf (for size bytes).
        if (bufferOwnsPtr)
        {
            // If we can get the necessary space for the buffer...
            if (resizeBuffer(size))
            {
                // Copy the data in.
                m_bufferSize = size;
                memmove(m_ptr, buf, size);
                set = true;
            }
        }
        // ...otherwise just point the buffer to buf and hope for the best.
        else
        {
            m_flags |= bfExternalPtr;

            // We'll tell a little white lie with respect to the constancy of the
            // passed-in buffer.
            m_ptr = const_cast<void *>(buf);
            m_bufferSize = m_bufferAllocation = size;
            set = true;
        }

        return set;
    }

    bool ByteBuffer::resetSize()
    {
        bool cleared = false;

        // Don't allow a resetSize operation on a buffer we don't own.
        if (!(m_flags & bfExternalPtr))
        {
            m_bufferSize = 0;
            cleared = true;
        }
        return cleared;
    }

    void ByteBuffer::memset(int value)
    {
        // Clear the region of the buffer we are reporting the size of (not the allocation)
        if (m_ptr)
        {
#if (defined(WIN32) || defined(_WIN32) || defined(WINCE) || defined(_WIN32_WCE)) && !defined(_WINRT)
            if (value == 0)
            {
                ::SecureZeroMemory(m_ptr, m_bufferSize);
            }
            else
            {
#endif
                ::memset(m_ptr, value, m_bufferSize);
#if (defined(WIN32) || defined(_WIN32) || defined(WINCE) || defined(_WIN32_WCE)) && !defined(_WINRT)
            }
#endif
        }
    }

    bool ByteBuffer::xorWith(const ByteBuffer &buffer, bool allowResize, unsigned char initialValue)
    {
        size_t startingSize = m_bufferSize;
        if (allowResize && startingSize < buffer.size())
        {
            if (!reserve(buffer.size()))
            {
                return false;
            }
            ::memset((unsigned char *)m_ptr + startingSize, initialValue, m_bufferSize - startingSize);
        }
        unsigned char *dest = (unsigned char *)m_ptr;
        const unsigned char *src = (const unsigned char *)buffer;
        if (dest && src)
        {
            // We are potentially taking a time hit here for simplicitly...
            for (size_t i = 0; i < m_bufferSize && i < buffer.size(); ++i, ++dest, ++src)
            {
                *dest ^= *src;
            }

        }
        return true;
    }

    std::string ByteBuffer::hexString() const
    {
        std::ostringstream os;
        os << std::setfill('0') << std::hex << std::setiosflags(std::ios_base::uppercase);
        for (size_t i = 0; i < m_bufferSize; ++i)
        {
            os << std::setw(2) << (int)((unsigned char *)*this)[i];
        }
        return os.str();
    }

    bool ByteBuffer::reserve(size_t size)
    {
        bool reserved = false;

        // Don't allow a reserve call on a buffer we don't own
        if (!(m_flags & bfExternalPtr))
        {
            // If our current actual buffer reserved space is less than the
            // requested size, resize the buffer.
            if (m_bufferAllocation < size)
            {
                size_t optimalSize = size;

#ifdef RESERVE_BUFFER_IN_GEOMETRIC_CHUNKS
                // In order to minimize the total number of reserves made as a buffer grows,
                // select the optimal size to be the next power of two past the requested size.
                size_t temp = size;

                // Don't grow the buffer geometrially if the buffer is being resized from
                // 0, in that case we will assume the buffer will not change size and we can
                // optimize for the precise size.
                if (m_bufferSize)
                {
                    optimalSize = 1;
                    while (temp)
                    {
                        temp        >>= 1;
                        optimalSize <<= 1;
                    }
                }
#endif

                if (resizeBuffer(optimalSize))
                {
                    m_bufferSize = size;
                    reserved = true;
                }
                // If the optimal size was too big, fall back on the actual
                // size requested (if it's not the same).
                else if (optimalSize != size && resizeBuffer(size))
                {
                    m_bufferSize = size;
                    reserved = true;
                }
            }
            // ..otherwise just decrease the reported size (don't reallocate).
            else
            {
                m_bufferSize = size;
                reserved = true;
            }
        }

        return reserved;
    }

    void ByteBuffer::freeBuffer()
    {
        // If this is not an externally-assigned pointer (i.e. it is one we own)
        if (m_ptr && !(m_flags & bfExternalPtr))
        {
#if defined(DEBUG) || defined(_DEBUG)
            // If we are in debug mode, assign invalid data to buffer
            ::memset(m_ptr, 0xFE, m_bufferAllocation);
#endif

#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
            checkGuardRegions();
#endif
            // free the underlying memory
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
            free((uint8_t *)m_ptr - DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE);
#else
            free(m_ptr);
#endif
        }
        m_flags = bfDefault;
        m_ptr = 0;
        m_bufferAllocation = m_bufferSize = 0;
    }

    bool ByteBuffer::resizeBuffer(size_t size)
    {
        bool resized = false;

        // Only allow a resize if the buffer owns the pointer
        if (!(m_flags & bfExternalPtr))
        {
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
            void *newPtr = realloc(m_ptr ? (uint8_t *)m_ptr - DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE : 0,
                                   size + DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE * 2);
#else
            void *newPtr = realloc(m_ptr, size);
#endif

            if (newPtr)
            {
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
                ::memset(newPtr, DEBUG_BYTE_BUFFER_PRE_BYTE, DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE);
                ::memset((uint8_t *)newPtr + DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE + size,
                         DEBUG_BYTE_BUFFER_POST_BYTE, DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE);
                m_ptr = (uint8_t *)newPtr + DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE;
#else
                m_ptr = newPtr;
#endif
                m_bufferAllocation = size;
                // Limit the size of the buffer to the new size (but don't
                // change the size otherwise).
                m_bufferSize = std::min(m_bufferSize, size);
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
                checkGuardRegions();
#endif
                resized = true;
            }
        }

        return resized;
    }

    void ByteBuffer::shiftTowardsOrigin(size_t byBytes)
    {
        size_t shiftLength = std::min(m_bufferSize, byBytes), remainder = m_bufferSize - shiftLength;
        if (remainder > 0)
        {
            ::memmove(m_ptr, (uint8_t *)m_ptr + shiftLength, remainder);
        }
    }

    bool ByteBuffer::replaceSegment(size_t offset, size_t length, const ByteBuffer &buffer)
    {
        bool replaced = false;
        if (offset <= size())
        {
            size_t replaceLength = std::min(offset + length,
                                            size()) - offset; // size()-offset >= 0 since offset <= size()
            if (buffer.size() > replaceLength)
            {
                size_t lengthDelta = buffer.size() - replaceLength;
                if (reserve(m_bufferSize + lengthDelta))
                {
                    size_t oldPos = offset + replaceLength, newPos = offset + replaceLength + lengthDelta;
#ifdef WIN32
                    ::memmove_s((uint8_t *)m_ptr + newPos, m_bufferAllocation - newPos, (uint8_t *)m_ptr + oldPos,
                                m_bufferSize - newPos);
                    ::memmove_s((uint8_t *)m_ptr + offset, m_bufferAllocation - offset, (const void *)buffer,
                                buffer.size());
#else
                    ::memmove((uint8_t *)m_ptr + newPos, (uint8_t *)m_ptr + oldPos, m_bufferSize - newPos);
                    ::memmove((uint8_t *)m_ptr + offset, (const void *)buffer, buffer.size());
#endif
                    replaced = true;
                }
            }
            else if (buffer.size() < replaceLength)
            {
                size_t lengthDelta = replaceLength - buffer.size();
                size_t oldPos = offset + replaceLength, newPos = offset + buffer.size();
                m_bufferSize -= lengthDelta;
#ifdef WIN32
                ::memmove_s((uint8_t *)m_ptr + newPos, m_bufferAllocation - newPos, (uint8_t *)m_ptr + oldPos,
                            m_bufferSize - newPos);
                ::memmove_s((uint8_t *)m_ptr + offset, m_bufferAllocation - offset, (const void *)buffer,
                            buffer.size());
#else
                ::memmove((uint8_t *)m_ptr + newPos, (uint8_t *)m_ptr + oldPos, m_bufferSize - newPos);
                ::memmove((uint8_t *)m_ptr + offset, (const void *)buffer, buffer.size());
#endif
                replaced = true;
            }
            else
            {
#ifdef WIN32
                ::memmove_s((uint8_t *)m_ptr + offset, replaceLength, (const void *)buffer, replaceLength);
#else
                ::memmove((uint8_t *)m_ptr + offset, (const void *)buffer, replaceLength);
#endif
                replaced = true;
            }
        }
        return replaced;
    }

    ByteBuffer ByteBuffer::slice(size_t fromByteOffset, size_t forNBytes, bool copyBuffer) const
    {
        if (size() >= fromByteOffset)
        {
            size_t availableBytes = std::min(size() - fromByteOffset, forNBytes);
            return ByteBuffer((uint8_t *)m_ptr + fromByteOffset, availableBytes, copyBuffer);
        }
        else
        {
            return ByteBuffer();
        }
    }

    template <typename _T> _T BASE64_ENCODE_RESERVE(_T size) { return (size + 2) / 3 * 4; }

    bool ByteBuffer::base64Encode(const ByteBuffer &inputBuffer, ByteBuffer &outputBuffer)
    {
        bool encodeOkay = false;
        if (inputBuffer.size() > 0)
        {
            size_t newSize = BASE64_ENCODE_RESERVE(inputBuffer.size());
            if (newSize <= static_cast<size_t>(std::numeric_limits<int>::max()))
            {
                if (outputBuffer.resizeBuffer(newSize +
                                              32))     // provide extra space of the EVP_EncodeBlock to smash our buffer
                {
                    if (outputBuffer.reserve(
                            newSize))          // but only reserve what is needed (which should not require a second allocation)
                    {
                        int outputLen = EVP_EncodeBlock((unsigned char *)outputBuffer,
                                                        (const unsigned char *)inputBuffer,
                                                        (int)inputBuffer.size());

                        if (outputLen > 0)
                        {
                            encodeOkay = true;
                        }

                        // EVP_EncodeBlock has no buffer overrun checks so we will rely on
                        // the buffer checking in debug mode to test for bad behavior.
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
                        outputBuffer.checkGuardRegions();
#endif
                    }
                }
            }
        }
        else
        {
            encodeOkay = outputBuffer.resetSize();
        }
        return encodeOkay;
    }

    // NOTE: Adapted from X509Store. This was added because X509::Blob
    //       does not guarantee erasure of the memory it uses. One of these
    //       implementation should ideally supplant the other.
    bool ByteBuffer::base64Decode(const ByteBuffer &inputBuffer, ByteBuffer &outputBuffer)
    {
        static const unsigned char ascii2bin[] =
        {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xE0, 0xF0, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xF2, 0xFF, 0x3F,
            0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
            0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
            0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        static_assert(sizeof(ascii2bin) == 128, "ascii2bin must be 128 characters long");

        bool decodeOkay = false;
        if (inputBuffer.size() > 0)
        {
            size_t inputSize = inputBuffer.size();
            const uint8_t *inputPtr = (const uint8_t *)inputBuffer;
            const uint8_t *inputEnd = inputPtr + inputSize;

            // Trim leading and trailing whitespace
            while (inputPtr < inputEnd && *inputPtr == ' ') { ++inputPtr; }
            do { --inputEnd; }
            while (inputPtr < inputEnd && *inputEnd == ' ');

            // Correct inputEnd and compute adjusted input size
            inputSize = ++inputEnd - inputPtr;

            // Make sure the string is divisible by 4
            if (!(inputSize % 4))
            {
                // Estimate the output size
                size_t outputSize = 3 * inputSize / 4;

                // Calculate the actual output size
                for (--inputEnd; inputPtr < inputEnd && *inputEnd == '='; --inputEnd)
                {
                    --outputSize;
                }
                ++inputEnd;

                if (outputBuffer.reserve(outputSize))
                {
                    uint8_t *outputPtr = (uint8_t *)outputBuffer, *outputPtrEnd = outputPtr + outputSize;

                    // Process the contents
                    decodeOkay = true;
                    while (inputPtr < inputEnd)
                    {
                        uint8_t a = ascii2bin[(*inputPtr++) & 0x7F];
                        uint8_t b = ascii2bin[(*inputPtr++) & 0x7F];
                        uint8_t c = ascii2bin[(*inputPtr++) & 0x7F];
                        uint8_t d = ascii2bin[(*inputPtr++) & 0x7F];

                        // If the high-order bit is set on any parameters, break out, invalid base64 data
                        if ((a | b | c | d) & 0x80)
                        {
                            decodeOkay = false;
                            break;
                        }

                        uint32_t v = (((uint32_t)a) << 18L) |
                                     (((uint32_t)b) << 12L) |
                                     (((uint32_t)c) << 6L) |
                                     (((uint32_t)d));

                        if (outputPtr < outputPtrEnd)
                        {
                            *outputPtr++ = (uint8_t)(v >> 16L) & 0xFF;
                        }
                        if (outputPtr < outputPtrEnd)
                        {
                            *outputPtr++ = (uint8_t)(v >> 8L) & 0xFF;
                        }
                        if (outputPtr < outputPtrEnd)
                        {
                            *outputPtr++ = (uint8_t)(v) & 0xFF;
                        }
                    }
                }
            }
        }
        else
        {
            decodeOkay = outputBuffer.resetSize();
        }
        return decodeOkay;
    }



#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
    bool ByteBuffer::checkGuardRegions() const
    {
        bool regionsOkay = true;
        if (m_ptr)
        {
            for (uint8_t *p = (uint8_t *)m_ptr - DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE; p < m_ptr; ++p)
            {
                if (*p != DEBUG_BYTE_BUFFER_PRE_BYTE)
                {
                    regionsOkay = false;
                    break;
                }
            }

            for (uint8_t *p = (uint8_t *)m_ptr + m_bufferAllocation;
                 p < (uint8_t *)m_ptr + m_bufferAllocation + DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE; ++p)
            {
                if (*p != DEBUG_BYTE_BUFFER_POST_BYTE)
                {
                    regionsOkay = false;
                    break;
                }
            }
        }
        return regionsOkay;
    }
#endif





    //////////
    // StreamBuffer
    //
    StreamBuffer::StreamBuffer():
        m_position(0)
    {}

    StreamBuffer::StreamBuffer(size_t size):
        ByteBuffer(size),
        m_position(0)
    {}

    StreamBuffer::StreamBuffer(const void *buf, size_t size):
        ByteBuffer(buf, size),
        m_position(0)
    {}

    StreamBuffer::StreamBuffer(const StreamBuffer &buffer):
        ByteBuffer(buffer),
        m_position(buffer.m_position)
    {}

    StreamBuffer::StreamBuffer(StreamBuffer &&buffer):
        ByteBuffer((ByteBuffer && )buffer), m_position(buffer.m_position)
    {
        buffer.m_position = 0;
    }


    StreamBuffer::~StreamBuffer()
    {}

    StreamBuffer &StreamBuffer::operator=(const StreamBuffer &buffer)
    {
        ByteBuffer::operator=(buffer);
        m_position = buffer.m_position;

        return *this;
    }

    size_t StreamBuffer::read(void *buf, size_t size)
    {
        size_t bytesRead = 0;
        if (buf && size && m_position < this->size())
        {
            bytesRead = std::min(size, this->size() - m_position);
            memcpy(buf, &((unsigned char *)ptr())[m_position], bytesRead);
            m_position += bytesRead;
        }
        return bytesRead;
    }

    bool StreamBuffer::seek(size_t position)
    {
        bool seeked = false;

        // Check that the new position is within the bounds of the reported size of
        // the buffer.
        if (position <= size())
        {
            m_position = position;
            seeked = true;
        }

        return seeked;
    }

    bool StreamBuffer::performWrite(const void *buf, size_t size)
    {
        bool appended = false;

        // If we are allowed to resize the buffer...
        if (bufferOwnsPointer())
        {
            // Resize the buffer to account for size more bytes past the
            // current position.
            if (reserve(m_position + size))
            {
                // If the memory could be reserved, append the contents of
                // buf (for size bytes) at the current position and move
                // the position.
                if (buf)
                {
                    memcpy(&((unsigned char *)ptr())[m_position], buf, size);
                }
                m_position += size;
                appended = true;
            }
        }
        return appended;
    }

    bool StreamBuffer::write(const void *buf, size_t size)
    {
        return performWrite(buf, size);
    }

    bool StreamBuffer::write(const ByteBuffer &buf)
    {
        return performWrite(buf, buf.size());
    }

    bool StreamBuffer::write(const std::string &str, NullTerminator includeNull)
    {
        return performWrite(str.c_str(),
                            str.size() + (includeNull == NullTerminator::IncludeNull ? 1 : 0));
    }

    void *StreamBuffer::cursor()
    {
        // Return the pointer to the byte at m_position.
        return ptr() ? &((unsigned char *)ptr())[m_position] : 0;
    }

    const void *StreamBuffer::cursor() const
    {
        // Return the pointer to the byte at m_position.
        return ptr() ? &((unsigned char *)ptr())[m_position] : 0;
    }

    bool StreamBuffer::setBuffer(const void *buf, size_t size, bool bufferOwnsPtr)
    {
        bool set = ByteBuffer::setBuffer(buf, size, bufferOwnsPtr);
        // If the buffer was set to a new buffer, make certain m_position
        // is still valid.
        if (set)
        {
            m_position = std::min(m_position, StreamBuffer::size());
        }
        return set;
    }

    bool StreamBuffer::reserve(size_t size)
    {
        bool reserved = ByteBuffer::reserve(size);
        // If space was reserved make certain m_position is still valid.
        if (reserved)
        {
            m_position = std::min(m_position, size);
        }
        return reserved;
    }

    bool StreamBuffer::resetSize()
    {
        bool cleared = false;

        // If the size is reset, also reset the m_position.
        if (ByteBuffer::resetSize())
        {
            m_position = 0;
            cleared = true;
        }
        return cleared;
    }

    void StreamBuffer::shiftTowardsOrigin(size_t byBytes)
    {
        ByteBuffer::shiftTowardsOrigin(byBytes);
        m_position -= std::min(byBytes, m_position);
    }

    bool StreamBuffer::replaceSegment(size_t offset, size_t length, const ByteBuffer &buffer)
    {
        bool replaced = ByteBuffer::replaceSegment(offset, length, buffer);
        if (replaced && offset <= StreamBuffer::size())
        {
            size_t replaceLength = std::min(offset + length, size()) - offset;

            if (m_position >= offset + replaceLength)
            {
                m_position += buffer.size() - replaceLength;
            }

            m_position = std::min(m_position, StreamBuffer::size());
        }
        return replaced;
    }



    /*
    // TODO: Convert to ostream only
    std::ostream &operator<<(std::ostream &os, const ByteBuffer &buffer)
    {
        os << "        | _0 _1 _2 _3 _4 _5 _6 _7 _8 _9 _A _B _C _D _E _F | 0123456789ABCDEF" << std::endl;
        os << "----------------------------------------------------------+-----------------" << std::endl;
        for (size_t pos = 0; pos < buffer.size(); )
        {
            char hexBuf[] = "        |                                                 |                 ";

            for (size_t i = 0; i < 16; ++i)
            {
    #if defined(_WIN32)
                sprintf_s(&hexBuf[0], 9, "%07IX_", pos >> 4);
    #else
                sprintf_s(&hexBuf[0], 9, "%07zX_", pos >> 4);
    #endif
                hexBuf[8] = '|';
                unsigned char ce = ((const unsigned char *)buffer)[pos];
                sprintf_s(&hexBuf[10 + i * 3], 3, "%02X", ce);
                hexBuf[12 + i * 3] = ' ';
                sprintf_s(&hexBuf[60 + i], 2, "%c", isprint(ce) && ce != '\t' ? ce : '.');
                ++pos;
                if (pos >= buffer.size())
                {
                    break;
                }
            }
            os << hexBuf << std::endl;
        }
        os << "----------------------------------------------------------------------------" << std::endl;
        return os;
    }
    */


} // namespace Iotivity
