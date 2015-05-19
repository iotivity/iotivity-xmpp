//******************************************************************
//
// Copyright 2005-2015 Intel Mobile Communications GmbH All Rights Reserved.
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
//     buffers.h
//
// Description:
//     Header for IoTivity data buffer helper classes
//
//
//
//*********************************************************************


#ifndef __BUFFERSH__
#define __BUFFERSH__

#include <ostream>
#include "../include/ccfxmpp.h"

namespace Iotivity
{
    // Forward declaration
    class bstring;

    // Uncomment these definitions to add guard regions before and after all memory allocations
    // made using the ByteBuffer class. This will help to determine if code is attempting
    // write past the outer bound of a ByteBuffer.
#ifdef _DEBUG
#  define DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS    1
#endif

#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
    // The guard-region size must be reserved in quanta of 4 bytes for proper pointer alignment
#  define DEBUG_BYTE_BUFFER_GUARD_REGION_SIZE    (128*sizeof(void *))
#  define DEBUG_BYTE_BUFFER_PRE_BYTE             0x01
#  define DEBUG_BYTE_BUFFER_POST_BYTE            0x02
#endif

    /// \brief A simple wrapper class for a memory buffer.
    ///
    /// This class handles the management and storage of a memory buffer.
    /// that can be optionally resizable if the memory buffer is owned
    /// by the ByteBuffer instance, or fixed size if it is pointing
    /// to memory owned by an external party.
    ///
    class XMPP_API ByteBuffer
    {
        protected:
            /// The internal flags used by ByteBuffer to indicate properties
            /// of the underlying memory, its ownership, format, etc.
            ///
            enum BufferFlags : unsigned int
            {
                bfDefault         = 0x0000,   ///< Default (~bfExternalPtr)
                bfExternalPtr     = 0x0001    ///< Set if the memory is not owned by the ByteBuffer (i.e. it's external)
            };
        public:
            /// The format of a string passed into the ByteBuffer to be converted
            /// into bytes.
            enum class StringFormat
            {
                DelimitedHex
            };
        public:
            /// Default constructor for ByteBuffer. Constructs an empty ByteBuffer.
            /// The underlying pointer to an empty ByteBuffer will be 0. No memory
            /// is initially allocated.
            ///
            ByteBuffer();

            /// Allocates a ByteBuffer with an initial size. The memory referenced
            /// by the underlying pointer will be zeroed out by this call.
            ///
            /// \param size The size of the buffer to allocate. size bytes will
            ///        be reserved if they are available from the system.
            ///
            explicit ByteBuffer(size_t size, bool clearBuffer = true);

            /// Constructs a ByteBuffer which is a copy of the memory located at buf
            /// for size bytes. This size of this buffer will be size bytes if the
            /// memory is available from the system, otherwise the buffer will remain
            /// empty.
            ///
            /// \param buf The buffer to copy the contents of.
            /// \param size The number of bytes from buf to copy.
            ///
            ByteBuffer(const void *buf, size_t size);

            /// Constructs a ByteBuffer which is either an alias for an existing memory
            /// buffer starting at buf for size bytes if bufferOwnsPtr is false,
            /// or is a copy of the memory located at buf for size bytes if bufferOwnsPtr
            /// is true. If bufferOwnsPtr is false, the lifespan of the memory referenced by
            /// buf <b>must</b> be longer than that of the ByteBuffer instance referencing it.
            ///
            /// \param buf The buffer to either copy (if bufferOwnsPtr is true) or
            ///        reference the contents of (if bufferOwnsPtr is false).
            /// \param size The number of bytes from buf to copy (if bufferOwnsPtr is true)
            ///        or the number of bytes in buf to report (if bufferOwnsPtr is false).
            /// \param bufferOwnsPtr Determines whether this ByteBuffer will own the memory.
            ///        If true, a copy of buf will be made, otherwise this instance will
            ///        point directly to buf.
            ///
            ByteBuffer(void *buf, size_t size, bool bufferOwnsPtr);

            /// Copy constructor for ByteBuffer instances. If the ByteBuffer owns its memory
            /// the new ByteBuffer is a copy of the underlying memory. If the ByteBuffer is just
            /// an alias to a memory region, the new ByteBuffer is an alias to the same memory
            /// region as the original. If this ByteBuffer is an alias to the same memory as
            /// original the lifespan of this new instance must not be greater than the lifespan
            /// of the original referenced memory buffer.
            ///
            ByteBuffer(const ByteBuffer &);

            /// Move constructor for ByteBuffer instances. If the ByteBuffer owns its memory
            /// the new ByteBuffer is a copy of the underlying memory. If the ByteBuffer is just
            /// an alias to a memory region, the new ByteBuffer is an alias to the same memory
            /// region as the original.
            ByteBuffer(ByteBuffer &&);

            /// Frees the underlying buffer if the ByteBuffer owns its memory.
            ///
            virtual ~ByteBuffer();

            /// Comparison operator for ByteBuffer. Determines if two ByteBuffers have
            /// equivalent contents.
            ///
            /// \return true iff this ByteBuffer contains the same data as the passed-in
            ///         ByteBuffer. If the buffers have different sizes this call will
            ///         take O(1) time, otherwise it will take O(size()) time.
            ///
            bool              operator==(const ByteBuffer &) const;
            bool              operator!=(const ByteBuffer &withBuf) const
            {
                return !(ByteBuffer::operator==(withBuf));
            }

            virtual bool      operator<(const ByteBuffer &) const;

            /// Assignment operator for ByteBuffer. If the passed in buffer is owned
            /// by its buffer, a copy will be made in this instance, otherwise just
            /// the pointer will be copied. The current contents of this ByteBuffer
            /// will be freed.
            ///
            /// \param buffer The buffer to assign to this ByteBuffer
            ///
            /// \return A reference to this ByteBuffer instance.
            ///
            ByteBuffer       &operator=(const ByteBuffer &buffer);

            /// May throw range_error if the position is out-of-bounds.
            unsigned char    &operator[](size_t pos);

            /// Determines whether this ByteBuffer owns the memory it references.
            ///
            /// \return true if this ByteBuffer owns it pointer and can manipulate
            ///         the size of the memory it references, false if this ByteBuffer
            ///         is simply an alias for a static buffer.
            bool              bufferOwnsPointer() const;

            /// The size of the memory buffer referenced by this byte-buffer. This
            /// may not reflect the actual memory allocated if the ByteBuffer has
            /// reserved additional memory. The reserved memory will always be
            /// at least as large as the value returned by size().
            ///
            size_t            size() const { return m_bufferSize; }

            /// Computes a hash value of the contents of this buffer which will be
            /// the same for identical buffer contents. It is possible though unlikely
            /// that two different buffers will have the same hash value.
            ///
            /// \return A hash of the contents of this buffer or 0 if the buffer is
            ///         empty.
            ///
            unsigned long     hash() const;

            /// Assigns a memory buffer to this byte buffer. The resulting buffer is
            /// a copy of the memory in buffer. The original contents of the buffer
            /// will be freed or resized to accomodate the new memory requirements of
            /// the buffer.
            ///
            /// \param buffer The buffer to make a duplicate of.
            ///
            /// \return true if sufficient space for the buffer could be allocated,
            ///         false otherwise.
            ///
            bool              duplicate(const ByteBuffer &buffer)
            {
                return setBuffer((const void *)buffer, buffer.size(), true);
            }

            /// Erases a region of the buffer and collapses the buffer's size to
            /// compensate for the removed region. If fromPosition and toPosition
            /// are invalid (e.g. toPosition is less than fromPosition) no action will
            /// be taken. The buffer must own its pointer for this function to have
            /// any effect.
            ///
            /// \param fromPosition The 0-based position in the buffer of the start of
            ///        the region to remove from the buffer.
            /// \param toPosition The 0-based position in the buffer of the end of the
            ///        the region to remove from the buffer.
            ///
            /// \return true iff the region was valid and could be removed from
            ///         the buffer.
            ///
            bool              remove(size_t fromPosition, size_t toPosition);

            /// Assigns a new memory buffer to this byte buffer. The resulting
            /// buffer is a copy of the memory at buf for size bytes. The original
            /// contents of buffer will be freed or resized to accomodate the new
            /// memory requirements of the buffer.
            ///
            /// \param buf The buffer to make a copy of.
            /// \param size The number of bytes from buffer to copy into this
            ///        ByteBuffer instance.
            /// \param bufferOwnsPtr Determines whether this ByteBuffer will own the memory.
            ///        If true, a copy of buf will be made, otherwise this instance will
            ///        point directly to buf.
            ///
            /// \return true if sufficient space for the buffer could be allocated,
            ///         false otherwise.
            ///
            virtual bool      setBuffer(const void *buf, size_t size, bool bufferOwnsPtr = true);

            /// Accessor for the start of the ByteBuffer's underlying memory buffer.
            ///
            /// \return non-const pointer to the start of the buffer.
            ///
            operator void *() { return m_ptr; }
            void *get() { return m_ptr; }

            /// const accessor for the start of the ByteBuffer's underlying memory buffer.
            ///
            /// \return const pointer to the start of the buffer
            ///
            operator const void *() const { return m_ptr; }
            const void *get() const { return m_ptr; }

            /// Accessor for the start of the ByteBuffer's underlying memory buffer.
            ///
            /// \return non-const pointer to the start of the buffer as an array of bytes.
            ///
            operator unsigned char *() const { return (unsigned char *)m_ptr; }

            /// const accessor for the start of the ByteBuffer's underlying memory buffer.
            ///
            /// \return const pointer to the start of the buffer as an array of bytes.
            ///
            operator const unsigned char *() const { return (const unsigned char *)m_ptr; }

            /// Reserves additional space in the buffer (if necessary) to
            /// increase its size to 'size'. Any pointers to the
            /// contents of this buffer will be invalidated by this
            /// call if it succeeds. The ByteBuffer must own its underlying
            /// buffer in order for this process to succeed. This call generally
            /// invalidates any pointers held on the existing buffer, so this
            /// must be used with extreme care in a mult-threaded context (or
            /// while some code is referencing the underlying pointer).
            ///
            /// \param size The size to increase this buffer to
            ///
            /// \return true if the buffer could be resized, false
            ///         if memory was not available or the buffer
            ///         pointer was not owned by the buffer.
            ///
            virtual bool      reserve(size_t size);

            /// If this ByteBuffer instance owns its underlying buffer this member
            /// zeros the size of the buffer to empty it out as rapidly as possible.
            /// The contents and size of the allocation for the buffer are not modified
            /// by this call, so a call to reserve with a size less than or equal to
            /// the original buffer size after a call to resetSize() will not call any
            /// memory-allocation routines.
            ///
            /// \return true if the buffer could be resized to 0, false if the pointer
            ///         underlying the buffer is not owned by the buffer.
            ///
            virtual bool      resetSize();

            /// Sets the memory contents of this buffer to a given value. The value (as cast
            /// to a single byte) will be assigned to each byte of memory in the buffer.
            ///
            /// \param value The value to assign to each byte of the buffer. It is passed
            ///        as an int rather than a char to match the parameters to the
            ///        system memset call.
            ///
            void              memset(int value);

            /// XORs the contents of this buffer with a second buffer bitwise, modifying this buffer.
            /// If the buffers do not have matching sizes, the default behavior will be modify
            /// only the data which overlaps with the second buffer in this buffer. The default
            /// behavior can be overridden to force this buffer to be at least as large as the
            /// passed-in buffer to XOR with, in which case the buffer's newly allocated region
            /// will be filled with initialValue (default 0).
            ///
            /// \param buffer The buffer to XOR with this buffer.
            /// \param allowResize If true, this buffer will be resized to overlap completely the
            ///                    passed-in buffer (returning false if the allocation fails).
            /// \param initialValue The initial value to set any newly allocated space in the current
            ///                     buffer.
            ///
            /// \return true if the XOR completed successfully; false if allowResize was true and a resize
            ///         was attempted but the memory could not be reserved.
            ///
            bool              xorWith(const ByteBuffer &buffer, bool allowResize = false,
                                      unsigned char initialValue = 0);

#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
            /// Checks the guard regions in the ByteBuffer allocation.
            ///
            bool              checkGuardRegions() const;
#endif

            std::string       hexString() const;

            static const size_t all_bytes = ~((size_t)0UL);

            ByteBuffer        slice(size_t fromByteOffset, size_t forNBytes = all_bytes,
                                    bool copyBuffer = false) const;

            static bool       base64Encode(const ByteBuffer &inputBuffer,
                                           ByteBuffer &outputBuffer);
            static bool       base64Decode(const ByteBuffer &inputBuffer,
                                           ByteBuffer &outputBuffer);

        protected:
            /// Frees the underlying buffer used by this ByteBuffer instance. If
            /// this instance does not own the buffer, this function assign the
            /// buffer pointer and size 0, but does not touch the memory.
            ///
            virtual void      freeBuffer();

            /// Reallocates the underlying buffer used by this ByteBuffer instance.
            /// This call generally invalidates any pointers held on the existing
            /// buffer, so this must be used with extreme care. The size() of this
            /// buffer will not be directly modified by this call unless the new size
            /// of the underlying allocation will not accomodate the original size
            /// of the buffer in which case size() will shrink to newSize. To affect
            /// the ByteBuffer's size in the intuitive manner, call reserve() instead.
            /// The contents of the buffer (up to min(newSize, oldSize)) will not
            /// be modified by this call. Any newly-allocated memory regions will not
            /// be cleared by this call.
            ///
            /// \param newSize The new requested size of the buffer's underlying
            ///        memory region.
            ///
            /// \return true if the buffer could be resized, false if the memory
            ///         could not be acquired or this instance does not own the
            ///         underlying buffer.
            ///
            virtual bool      resizeBuffer(size_t newSize);

            /// Accessor for the buffer pointer. This should return the actual buffer
            /// pointer even if the standard accessors (cast operators) are later modified
            /// to handle special memory allocation requirements.
            ///
            /// \return A non-const pointer to the actual underlying buffer.
            ///
            void             *ptr() const { return m_ptr; }

            void              assignPtr(void *ptr) { m_ptr = ptr; }

            /// Accessor for the underlying size of the buffer owned or referenced by
            /// this ByteBuffer instance.
            ///
            /// \return The size of the memory buffer underlying this ByteBuffer.
            ///
            size_t            allocatedSize() const { return m_bufferAllocation; }

            void              assignAllocatedSize(size_t size) { m_bufferAllocation = size; }

            void              assignBufferSize(size_t size) { m_bufferSize = size; }
            BufferFlags       flags() const { return (BufferFlags)m_flags; }
            void              assignFlags(BufferFlags flags)
            {
                m_flags = static_cast<unsigned int>(flags);
            }

            /// Helper function which moves the contents of the buffer from byBytes
            /// in to the end of the reported size to the beginning of the buffer.
            ///
            /// \param byBytes      The number of bytes to shift back or the length of the
            ///                     segment from the origin which will be erased.
            ///
            virtual void      shiftTowardsOrigin(size_t byBytes);

            virtual bool      replaceSegment(size_t offset, size_t length, const ByteBuffer &buffer);

        private:
            /// Flags defined by the enumerated type BufferFlags.
            unsigned int      m_flags;
            /// Pointer to the underlying buffer allocation region
            void             *m_ptr;
            /// The amount of space allocated for the buffer
            size_t            m_bufferAllocation;
            /// The current reported size of the buffer <= m_bufferAllocation
            size_t            m_bufferSize;
    };


    /// \brief A simple wrapper class for a growable memory buffer simulating a
    ///        writeable stream.
    ///
    /// StreamBuffer extends ByteBuffer to include a position indicator for
    /// streaming raw data into a memory region. In contrast to a standard
    /// ByteBuffer, a streamBuffer always owns its underlying memory buffer.
    ///
    class XMPP_API StreamBuffer : public ByteBuffer
    {
        public:
            /// Default constructor for StreamBuffer. Constructs an empty StreamBuffer.
            /// The underlying pointer to an empty StreamBuffer will be 0, no memory
            /// is initially allocated.
            ///
            StreamBuffer();

            /// Allocates a StreamBuffer with an initial size. The memory referenced
            /// by the underlying pointer will be zeroed out by this call.
            /// \param size The size of the buffer to allocate. size bytes will
            ///        be reserved if they are available from the system.
            ///
            explicit StreamBuffer(size_t size);

            /// Constructs a StreamBuffer which is a copy of the memory located at buf
            /// for size bytes. This size of this buffer will be size bytes if the
            /// memory is available from the system, otherwise the buffer will remain
            /// empty.
            ///
            /// \param buf The buffer to copy the contents of.
            /// \param size The number of bytes from buf to copy.
            ///
            StreamBuffer(const void *buf, size_t size);

            /// Copy constructor for StreamBuffer instances. The new StreamBuffer is a
            /// copy of the underlying memory of the original.
            ///
            StreamBuffer(const StreamBuffer &buffer);

            StreamBuffer(StreamBuffer &&);

            /// Frees the underlying buffer.
            ///
            virtual ~StreamBuffer() override;

            /// Assignment operator for StreamBuffer. This assignment operator
            /// has roughly the same semantics as the ByteBuffer assignment operator,
            /// however the cursor position will be copied to the buffer instance
            /// as well.
            ///
            /// \param buffer The buffer to assign to this StreamBuffer
            /// \return A reference to this StreamBuffer instance.
            ///
            StreamBuffer     &operator=(const StreamBuffer &buffer);

            /// Resets the position of this StreamBuffer back to 0 but does not
            /// change either the size or contents of the buffer.
            ///
            void              resetCursor() { seek(0); }

            /// Reads up to size byte from the StreamBuffer at the current cursor
            /// position, copies them into the provided buffer (buf), and moves
            /// the cursor position to first byte of the buffer after the copied
            /// region (possibly the end of the buffer).
            ///
            /// \param buf The buffer into which the memory will be copied, this
            ///        buffer must be at least size bytes in length.
            /// \param size The maximum number of bytes to read from StreamBuffer.
            ///
            /// \return The number of bytes read from the StreamBuffer. This number
            ///         will be equal to or less than the value of size. If no Bytes
            ///         were read the size returned will be 0. This will occurr if an
            ///         attempt to read is made while the cursor is past the end
            ///         of the StreamBuffer's underlying buffer.
            ///
            size_t            read(void *buf, size_t size);

            /// Seeks the cursor to a new position in the StreamBuffer's
            /// memory.
            ///
            /// \param position The zero-based position to which the StreamBuffer's
            ///        cursor should be moved. If position is greater than the last
            ///        byte in the buffer, the cursor will not be moved.
            ///
            /// \return true if the new position of the cursor was assigned, false
            ///         if the position requested was outside the boundary of the
            ///         StreamBuffer's underlying memory.
            ///
            bool              seek(size_t position);

            /// Writes size bytes from buf into the current cursor position of this
            /// instance of StreamBuffer and updates the cursor position to the
            /// end of the copied memory. If this instance is not large enough to
            /// contain the newly allocated memory, StreamBuffer will be resized
            /// so that the entire contents of buf (for size bytes) will fit.
            ///
            /// \param buf The buffer from which to copy the memory written at the
            ///        current cursor position.
            /// \param size The number of bytes from buf to write to the current
            ///        cursor position.
            ///
            /// \return true if the memory could be written at the cursor, false
            ///         if the buffer could not be resized to accomodate the
            ///         space required to write size bytes past the current cursor
            ///         position.
            ///
            bool              write(const void *buf, size_t size);

            /// Writes the entire contents of the given buffer into the current
            /// cursor position of this instance of StreamBuffer and updates the
            /// cursor position to the end of the copied memory. If this instance
            /// is not large enough to contain the newly allocated memory, StreamBuffer
            /// will be resized so that the entire contents of buf (for size bytes)
            /// will fit.
            ///
            /// \param buf The ByteBuffer from which to copy the memory written
            ///        at the current cursor position.
            ///
            /// \return true if the memory could be written at the cursor, false
            ///         if the buffer could not be resized to accomodate the space
            ///         requried to write size bytes past the current cursor position.
            ///
            bool              write(const ByteBuffer &buf);

            enum class NullTerminator
            {
                IncludeNull,
                ExcludeNull
            };

            bool              write(const std::string &str,
                                    NullTerminator includeNull = NullTerminator::ExcludeNull);

            /// Accessor for the offset into the buffer at which the current cursor
            /// position rests.
            ///
            /// \return The offset (in bytes from 0) of the position of the cursor.
            ///
            size_t            position() const { return m_position; }

            /// Accessor for the current cursor position.
            ///
            /// \return The pointer to the buffer at the current cursor position.
            ///
            void             *cursor();

            /// Constant accessor for the current cursor position.
            ///
            /// \return The pointer to the buffer at the current cursor position.
            ///
            const void       *cursor() const;

            /// Assigns a new memory buffer to this byte buffer. The resulting
            /// buffer is a copy of the memory at buf for size bytes. The original
            /// contents of buffer will be freed or resized to accomodate the new
            /// memory requirements of the buffer.
            ///
            /// \param buf The buffer to make a copy of.
            /// \param size The number of bytes from buffer to copy into this
            ///        ByteBuffer instance.
            /// \param bufferOwnsPtr Determines whether this ByteBuffer will own the memory.
            ///        If true, a copy of buf will be made, otherwise this instance will
            ///        point directly to buf.
            ///
            /// \return true if sufficient space for the buffer could be allocated,
            ///         false otherwise.
            ///
            virtual bool      setBuffer(const void *buf, size_t size,
                                        bool bufferOwnsPtr = true) override;

            /// Reserves additional space in the buffer (if necessary) to
            /// increase its size to 'size'. Any pointers to the
            /// contents of this buffer will be invalidated by this
            /// call if it succeeds. The ByteBuffer must own its underlying
            /// buffer in order for this process to succeed. This call generally
            /// invalidates any pointers held on the existing buffer, so this
            /// must be used with extreme care in a mult-threaded context (or
            /// while some code is referencing the underlying pointer).
            ///
            /// \param size The size to increase this buffer to
            ///
            /// \return true if the buffer could be resized, false
            ///         if memory was not available or the buffer
            ///         pointer was not owned by the buffer.
            ///
            virtual bool      reserve(size_t size) override;

            /// Zeros the size of the buffer to empty it out as rapidly as possible and
            /// resets the cursor to the beginning of the buffer. The contents and size
            /// of the allocation for the StreamBuffer are not modified by this call
            /// all, so a call to reserve or write with a size (+cursor) less than or equal to
            /// the original buffer size after a call to resetSize() will not call any
            /// memory-allocation routines.
            ///
            /// \return true if the buffer could be resized to 0, false otherwise.
            ///
            virtual bool      resetSize() override;

            /// Helper function which moves the contents of the buffer from byBytes
            /// in to the end of the reported size to the beginning of the buffer.
            ///
            /// \param byBytes      The number of bytes to shift back or the length of the
            ///                     segment from the origin which will be erased.
            ///
            virtual void      shiftTowardsOrigin(size_t byBytes) override;

            virtual bool      replaceSegment(size_t offset, size_t length,
                                             const ByteBuffer &buffer) override;
        protected:
            virtual bool      performWrite(const void *buf, size_t size);
        private:
            /// The relative 0-offset position (in bytes) of the cursor on this StreamBuffer
            /// instance.
            size_t            m_position;
    };

    //std::ostream &operator<<(std::ostream &, const ByteBuffer &buffer);

} // namespace Iotivity


#endif //__BUFFERSH__

