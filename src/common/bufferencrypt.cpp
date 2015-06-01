///////////////////////////////////////////////////////////////////////////////
//
// Copyright 2014-2015 Intel Mobile Communications GmbH All Rights Reserved.
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

/// @file bufferencrypt.cpp

#include "stdafx.h"

#include "bufferencrypt.h"
#include "rand_helper.h"
#include <openssl/evp.h>
#include <stdint.h>
#include <limits>
#include <algorithm>

extern "C"
{
#if !defined(_WIN32)
#include <safe_mem_lib.h>
#include <safe_str_lib.h>
#endif
}

#ifdef _WIN32
#include <WinCrypt.h>
#endif

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

using namespace std;

namespace Iotivity
{

    //////////
#ifdef _WIN32
    bool BufferEncrypt::ProcessLocalEncryptBuffer(ByteBuffer &buffer, const ByteBuffer &saltBuffer)
    {
        bool encrypted = false;
        _ASSERTE(buffer.size() <= MAXDWORD);
        _ASSERTE(saltBuffer.size() <= MAXDWORD);

        DATA_BLOB in = { (DWORD)buffer.size(), (uint8_t *)buffer }, out = { 0, nullptr };
        DATA_BLOB salt = { (DWORD)saltBuffer.size(), const_cast<uint8_t *>((const uint8_t *)saltBuffer) };
        DATA_BLOB *saltPtr = nullptr;
        if (saltBuffer.size() > 0)
        {
            saltPtr = &salt;
        }
        if (::CryptProtectData(&in, nullptr, saltPtr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        {
            buffer.memset(0);
            encrypted = buffer.setBuffer(out.pbData, out.cbData);
            ::LocalFree(out.pbData);
        }
        return encrypted;
    }

    bool BufferEncrypt::ProcessLocalDecryptBuffer(ByteBuffer &buffer, const ByteBuffer &saltBuffer)
    {
        bool decrypted = false;
        _ASSERTE(buffer.size() <= MAXDWORD);
        _ASSERTE(saltBuffer.size() <= MAXDWORD);

        DATA_BLOB in = { (DWORD)buffer.size(), (uint8_t *)buffer }, out = { 0, nullptr };
        DATA_BLOB salt = { (DWORD)saltBuffer.size(), const_cast<uint8_t *>((const uint8_t *)saltBuffer) };
        DATA_BLOB *saltPtr = nullptr;
        if (saltBuffer.size() > 0)
        {
            saltPtr = &salt;
        }
        if (::CryptUnprotectData(&in, nullptr, saltPtr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        {
            decrypted = buffer.setBuffer(out.pbData, out.cbData);
            ::LocalFree(out.pbData);
        }
        return decrypted;
    }
#endif

    //////////
    SecureBuffer::SecureBuffer(): StreamBuffer(), _isProtected(false) { }

    SecureBuffer::SecureBuffer(size_t size): StreamBuffer(size), _isProtected(false) { }

    SecureBuffer::SecureBuffer(const void *buf, size_t size): StreamBuffer(), _isProtected(false)
    {
        setBuffer(buf, size);
    }

    SecureBuffer::SecureBuffer(const std::string &str, NullTerminator includeNull):
        StreamBuffer(str.size())
    {
        write(str, includeNull);
    }

    SecureBuffer::SecureBuffer(const SecureBuffer &buffer)
    {
        *this = buffer;
    }

    SecureBuffer::SecureBuffer(SecureBuffer &&buffer):
        StreamBuffer((StreamBuffer && )buffer), _isProtected(buffer._isProtected)
    {
        buffer._isProtected = false;
    }

    SecureBuffer::~SecureBuffer()
    {
        SecureBuffer::freeBufferSecure();
    }

    bool SecureBuffer::resetSize()
    {
        bool reset = StreamBuffer::resetSize();
        if (reset)
        {
            _isProtected = false;
        }
        return reset;
    }

    bool SecureBuffer::setBuffer(const void *buf, size_t size, bool bufferOwnsPtr)
    {
        _isProtected = false;
        return StreamBuffer::setBuffer(buf, size, bufferOwnsPtr);
    }

    SecureBuffer &SecureBuffer::operator=(const SecureBuffer &buffer)
    {
        StreamBuffer::operator=(buffer);
        _isProtected = buffer._isProtected;
        return *this;
    }

#ifdef _WIN32
    bool SecureBuffer::protect()
    {
        if (!_isProtected && allocatedSize() <= MAXDWORD)
        {
            // NOTE: allocatedSize() is a multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE. This is
            //       ensured by the overridden resizeBuffer() and is not retested here.
            if (::CryptProtectMemory(ptr(), (DWORD)allocatedSize(), CRYPTPROTECTMEMORY_SAME_PROCESS))
            {
                _isProtected = true;
            }
        }
        return _isProtected;
    }

    bool SecureBuffer::unprotect()
    {
        bool protectionRemoved = false;
        if (_isProtected && allocatedSize() <= MAXDWORD)
        {
            if (::CryptUnprotectMemory(ptr(), (DWORD)allocatedSize(), CRYPTPROTECTMEMORY_SAME_PROCESS))
            {
                protectionRemoved = true;
                _isProtected = false;
            }
        }
        return protectionRemoved;
    }
#endif

    template <typename _T> _T BASE64_ENCODE_RESERVE(_T size) { return (size + 2) / 3 * 4; }

    bool SecureBuffer::base64Encode(SecureBuffer &outputBuffer) const
    {
        bool encodeOkay = false;
        if (size() > 0)
        {
            size_t newSize = BASE64_ENCODE_RESERVE(size());
            if (newSize <= std::numeric_limits<int>::max())
            {
                if (outputBuffer.resizeBuffer(newSize +
                                              32))   // provide extra space of the EVP_EncodeBlock to smash our buffer
                {
                    if (outputBuffer.reserve(
                            newSize))          // but only reserve what is needed (which should not require a second allocation)
                    {
                        int outputLen = EVP_EncodeBlock((unsigned char *)outputBuffer, (const unsigned char *)*this,
                                                        (int)size());

                        if (outputLen > 0)
                        {
                            encodeOkay = true;
                        }

                        outputBuffer.seek(outputLen);

                        // EVP_EncodeBlock has no buffer overrun checks so we will rely on
                        // the buffer checking in debug mode to test for bad behavior.
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
                        checkGuardRegions();
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
    bool SecureBuffer::base64Decode(SecureBuffer &outputBuffer) const
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
        if (size() > 0)
        {
            size_t inputSize = size();
            const uint8_t *inputPtr = (const uint8_t *)*this;
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
                                     (((uint32_t)c) <<  6L) |
                                     (((uint32_t)d));

                        if (outputPtr < outputPtrEnd)
                        {
                            *outputPtr++ = (uint8_t)(v >> 16L) & 0xFF;
                        }
                        if (outputPtr < outputPtrEnd)
                        {
                            *outputPtr++ = (uint8_t)(v >>  8L) & 0xFF;
                        }
                        if (outputPtr < outputPtrEnd)
                        {
                            *outputPtr++ = (uint8_t)(v       ) & 0xFF;
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

    void SecureBuffer::freeBuffer()
    {
        freeBufferSecure();
    }

    void SecureBuffer::freeBufferSecure()
    {
        // If this is not an externally-assigned pointer (i.e. it is one we own)
        if (ptr() && !(flags()&bfExternalPtr))
        {
#if defined(DEBUG) || defined(_DEBUG)
            // If we are in debug mode, assign invalid data to buffer
            ::memset(ptr(), 0xFE, allocatedSize());
#else
#  ifdef _WIN32
            // Otherwise clear out the memory.
            ::SecureZeroMemory(ptr(), allocatedSize());
#  else
            ::memset_s(ptr(), allocatedSize(), 0);
#  endif
#endif

#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
            checkGuardRegions();
#endif
            // free the underlying memory
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
            free((uint8_t *)ptr() - DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE);
#else
            free(ptr()); // NOTE: If bfExternalPtr is set this is not our memory to clear and not freeing it is not a leak.
#endif
        }
        assignFlags(bfDefault);
        assignPtr(nullptr);
        assignAllocatedSize(0);
        assignBufferSize(0);
        _isProtected = false;
    }

    bool SecureBuffer::resizeBuffer(size_t size)
    {
        bool resized = false;

        // Only allow a resize if the buffer owns the pointer
        if (!(flags()&bfExternalPtr))
        {
#ifdef _WIN32
            // Round the base size up to the nearest multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE.
            // The guard regions (if in use) will not be protected/unprotected.
            size_t modulus = size % CRYPTPROTECTMEMORY_BLOCK_SIZE;
            if (modulus)
            {
                size += CRYPTPROTECTMEMORY_BLOCK_SIZE - modulus;
            }
#endif

            size_t newBufferRealSize;
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
            newBufferRealSize = size + DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE * 2;
#else
            newBufferRealSize = size;
#endif
            void *newPtr = calloc(newBufferRealSize, sizeof(uint8_t));

            if (newPtr)
            {
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
                ::memmove_s((uint8_t *)newPtr + DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE,
                            newBufferRealSize - DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE,
                            ptr(), std::min(newBufferRealSize, allocatedSize()));
#else
                ::memmove_s(newPtr, newBufferRealSize, ptr(), std::min(newBufferRealSize, allocatedSize()));
#endif
                freeBufferSecure();

#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
                ::memset(newPtr, DEBUG_BYTE_BUFFER_PRE_BYTE, DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE);
                ::memset((uint8_t *)newPtr + DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE + size,
                         DEBUG_BYTE_BUFFER_POST_BYTE, DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE);
                assignPtr((uint8_t *)newPtr + DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE);
#else
                assignPtr(newPtr);
#endif
                assignAllocatedSize(size);
                // Limit the size of the buffer to the new size (but don't
                // change the size otherwise).
                assignBufferSize(std::min(this->size(), size));
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
                checkGuardRegions();
#endif
                resized = true;
            }
        }

        return resized;
    }

    bool SecureBuffer::performWrite(const void *buf, size_t size)
    {
        bool written = StreamBuffer::performWrite(buf, size);
        if (written)
        {
            _isProtected = false;
        }
        return written;
    }


    //////////
    RandomBuffer::RandomBuffer(size_t size): SecureBuffer(size)
    {
        uniform_int_distribution<int> rngSelector(0, 255);
        auto &rng = rand_helper::rng();
        for (size_t i = 0; i < this->size(); ++i)
        {
            (*this)[i] = static_cast<uint8_t>(rngSelector(rng));
        }
    }

    RandomBuffer::RandomBuffer(RandomBuffer &&buffer): SecureBuffer(buffer) {}

}
