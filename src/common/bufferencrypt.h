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

/// @file bufferencrypt.h

#pragma once

#include "buffers.h"
#include "../include/ccfxmpp.h"

namespace Iotivity
{
#ifdef _WIN32
    /// @brief Inline memory encryption/decryption helper functions.
    class BufferEncrypt
    {
        public:
            static bool ProcessLocalEncryptBuffer(ByteBuffer &buffer,
                                                  const ByteBuffer &saltBuffer = ByteBuffer());
            static bool ProcessLocalDecryptBuffer(ByteBuffer &buffer, const
                                                  ByteBuffer &saltBuffer = ByteBuffer());
    };
#endif

    /// @brief SecureBuffer extends StreamBuffer with modifications that ensure that
    /// any freed memory is first cleared out using SecureZeroMemory.
    ///
    /// SecureBuffer is less efficient than StreamBuffer in that it cannot make use of the
    /// optimizations afforded by realloc in  resizing the buffer. Use this buffer only
    /// where the data stored is sensitive.
    class XMPP_API SecureBuffer: public StreamBuffer
    {
        public:
            SecureBuffer();
            explicit SecureBuffer(size_t size);
            SecureBuffer(const void *buf, size_t size);
            explicit SecureBuffer(const std::string &str,
                                  NullTerminator includeNull = NullTerminator::ExcludeNull);
            SecureBuffer(const SecureBuffer &buffer);
            SecureBuffer(SecureBuffer &&buffer);

            virtual ~SecureBuffer() override;

            bool isProtected() const { return _isProtected; }

#ifdef _WIN32
            /// Protects the provided memory by locally encrypting it. This
            /// original memory can only be unprotected while the process is
            /// still running. Any modification to the memory will invalidate
            /// the protection without necessarily clearing the isProtected() flag.
            /// Calling protect() on a memory block that is already marked as
            /// protected has no effect and returns true.
            bool protect();
            bool unprotect();
#endif

            bool base64Encode(SecureBuffer &outputBuffer) const;
            bool base64Decode(SecureBuffer &outputBuffer) const;

            virtual bool resetSize() override;
            virtual bool setBuffer(const void *buf, size_t size, bool bufferOwnsPtr = true) override;

            SecureBuffer &operator=(const SecureBuffer &buffer);

        protected:
            virtual void freeBuffer() override;
            virtual bool resizeBuffer(size_t newSize) override;
            virtual bool performWrite(const void *buf, size_t size) override;

            void freeBufferSecure();

        private:
            bool _isProtected;
    };


    class RandomBuffer: protected SecureBuffer
    {
        public:
            RandomBuffer(size_t size);
            RandomBuffer(const RandomBuffer &buffer) = default;
            RandomBuffer(RandomBuffer &&buffer);

  //          operator const ByteBuffer &() const { return *this; }

            using SecureBuffer::size;
            using SecureBuffer::get;
            using SecureBuffer::hash;

            bool operator==(const RandomBuffer &buf) const
            {
                return SecureBuffer::operator==(buf);
            }
            bool operator!=(const RandomBuffer &withBuf) const
            {
                return !(RandomBuffer::operator==(withBuf));
            }

            bool operator<(const RandomBuffer &buf) const
            {
                return SecureBuffer::operator<(buf);
            }

            using SecureBuffer::base64Encode;
            using SecureBuffer::base64Decode;

        private:
            void fillRandom(void *ptr, size_t forBytes);
    };

}
