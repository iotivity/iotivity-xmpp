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

#include "common/compatibility.h"
#include "common/buffers.h"
#include "common/bufferencrypt.h"
#include "common/stcqueue.h"
#include "common/str_helpers.h"
#include "common/logstream.h"
#include "common/async_notify.h"
#include "common/sync_notify.h"

#include <ostream>
#include <thread>
#include <algorithm>
#ifdef _WIN32
#include <codecvt>
#endif

#ifdef _WIN32
#pragma comment(lib, "Crypt32.lib")
#endif

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

extern char getRandomChar(char range = 25);


using namespace std;
using namespace Iotivity;

// buffers.h
TEST(ByteBuffer_Tests, ByteBuffer_Default_Constructor)
{
    Iotivity::ByteBuffer emptyBuffer;
    EXPECT_EQ(emptyBuffer.size(), 0UL);
}

TEST(ByteBuffer_Tests, ByteBuffer_hexString)
{
    unsigned char tempBuf[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFE, 0xFF, 0x22, 0x23, 0x32, 0x12, 0x45, 0x67, 0x9A};
    Iotivity::ByteBuffer tempBuffer(tempBuf, sizeof(tempBuf) / sizeof(unsigned char), false);
    std::string bufStr = tempBuffer.hexString();
    EXPECT_EQ(bufStr, "000102030405060608090A0B0C0D0E0FFEFF2223321245679A");

}

TEST(ByteBuffer_Tests, ByteBuffer_xorWith)
{
    Iotivity::ByteBuffer destTestBuffer;
    unsigned char maskBuf[] = {0x0a, 0xb6, 0x54, 0xe2, 0x3b, 0x39, 0x49, 0x20, 0x83, 0x16, 0x3f, 0x3d, 0x2e, 0xbc, 0x91, 0x06};
    Iotivity::ByteBuffer maskBuffer(maskBuf, sizeof(maskBuf), false);
    EXPECT_TRUE(destTestBuffer.xorWith(maskBuffer));
    Iotivity::ByteBuffer emptyBuffer;
    EXPECT_EQ(destTestBuffer, emptyBuffer);

    ASSERT_TRUE(destTestBuffer.reserve(4));
    EXPECT_EQ(destTestBuffer.size(), 4UL);
    destTestBuffer.memset(0xFF);

    EXPECT_TRUE(destTestBuffer.xorWith(maskBuffer));

    unsigned char expectedBuf1[] = {0xf5, 0x49, 0xab, 0x1d};
    Iotivity::ByteBuffer expectedBuffer1(expectedBuf1, sizeof(expectedBuf1), false);

    EXPECT_EQ(destTestBuffer, expectedBuffer1);

    EXPECT_TRUE(destTestBuffer.xorWith(maskBuffer, true, 0x02));

    EXPECT_EQ(destTestBuffer.size(), sizeof(maskBuf));

    unsigned char expectedBuf2[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x39, 0x3B, 0x4B, 0x22, 0x81, 0x14, 0x3D, 0x3F, 0x2C, 0xBE, 0x93, 0x04};
    Iotivity::ByteBuffer expectedBuffer2(expectedBuf2, sizeof(expectedBuf2), false);

    EXPECT_EQ(destTestBuffer, expectedBuffer2);

    unsigned char shortMaskBuf[] = {0x80, 0x40, 0x02, 0x01, 0x00, 0xFF};
    Iotivity::ByteBuffer shortMaskBuffer(shortMaskBuf, sizeof(shortMaskBuf), false);

    ASSERT_LE(shortMaskBuffer.size(), maskBuffer.size());

    EXPECT_TRUE(destTestBuffer.xorWith(shortMaskBuffer, true, 0x04));
    EXPECT_EQ(destTestBuffer.size(), sizeof(maskBuf));

    unsigned char expectedBuf3[] = {0x7F, 0xBF, 0xFD, 0xFE, 0x39, 0xC4, 0x4B, 0x22, 0x81, 0x14, 0x3D, 0x3F, 0x2C, 0xBE, 0x93, 0x04};
    Iotivity::ByteBuffer expectedBuffer3(expectedBuf3, sizeof(expectedBuf3), false);

    EXPECT_EQ(destTestBuffer, expectedBuffer3);

}

#ifdef _DEBUG
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
// Verify that the buffer overrun test catches pre and post-buffer overruns
// in debug mode and ignores untouched buffers.
TEST(ByteBuffer_Tests, ByteBuffer_BufferOverrunTest)
{
    Iotivity::ByteBuffer testBuffer(1024);
    EXPECT_EQ(testBuffer.size(), 1024UL);
    EXPECT_NE(DEBUG_BYTE_BUFFER_PRE_BYTE, 0x00);
    EXPECT_NE(DEBUG_BYTE_BUFFER_POST_BYTE, 0x00);

    if (testBuffer.size() == 1024)
    {
        EXPECT_TRUE(testBuffer.checkGuardRegions());

        uint8_t *ptr = (uint8_t *)testBuffer;
        ptr[1024] = 0x00;
        EXPECT_FALSE(testBuffer.checkGuardRegions());

        ptr[1024] = DEBUG_BYTE_BUFFER_POST_BYTE;
        EXPECT_TRUE(testBuffer.checkGuardRegions());

        ptr[-1] = 0x00;
        EXPECT_FALSE(testBuffer.checkGuardRegions());

        ptr[-1] = DEBUG_BYTE_BUFFER_PRE_BYTE;
        EXPECT_TRUE(testBuffer.checkGuardRegions());
    }
}
#endif
#endif

TEST(ByteBuffer_Tests, StreamBuffer_ReplaceSegment)
{
    StreamBuffer workingBuffer;
    ASSERT_EQ(workingBuffer.cursor(), (const void *)workingBuffer);
    struct TestAction
    {
        size_t _initialCursorPos;
        size_t _replaceOffset;
        size_t _replaceLength;
        const char *_replaceData;
        size_t _expectedSize;
        const char *_expectedData;
        size_t _expectedCursorPos;
        bool _expectedResult;
    } actions[] =
    {
        // Empty insert into empty buffer
        {0, 0, 0, "", 0, "", 0, true},
        // Invalid insert into empty buffer
        {0, 5, 0, "aaaaa", 0, "", 0, false},
        // Insert into empty buffer; truncated length
        {0, 0, 4, "aaaaa", 5, "aaaaa", 0, true},
        // Insert into buffer in existing segment
        {0, 2, 0, "bbbbb", 10, "aabbbbbaaa", 0, true},
        // Insert into buffer at beginning
        {0, 0, 0, "zz", 12, "zzaabbbbbaaa", 2, true},
        // Remove segment just added from the beginning
        {2, 0, 2, "", 10, "aabbbbbaaa", 0, true},
        // Add segment to the end
        {0, 10, 0, "yyyyy", 15, "aabbbbbaaayyyyy", 0, true},
        // Remove segment just added from the end
        {0, 10, 5, "", 10, "aabbbbbaaa", 0, true},
        // Replace segment in the middle with a longer segment
        {0, 4, 2, "yyyyyy", 14, "aabbyyyyyybaaa", 0, true},
        // Add nothing to the beginning
        {0, 0, 0, "", 14, "aabbyyyyyybaaa", 0, true},
        // Add nothing to the middle
        {0, 5, 0, "", 14, "aabbyyyyyybaaa", 0, true},
        // Add nothing to the end
        {0, 14, 0, "", 14, "aabbyyyyyybaaa", 0, true},
        // Add nothing past the end
        {0, 15, 0, "", 14, "aabbyyyyyybaaa", 0, false},
        // Replace segment in the middle with a shorter segment
        {12, 5, 3, "zz", 13, "aabbyzzyybaaa", 11, true},
        // Erase everything, replace with new segment
        {11, 0, 13, "qqqqqrrrrrsssss", 15, "qqqqqrrrrrsssss", 11, true},
        // Erase everything, leave nothing
        {0, 0, 15, "", 0, "", 0, true},
    };

    // Since StreamBuffer calls ByteBuffer, we're checking both here.
    // This does assume that StreamBuffer doesn't stop calling ByteBuffer,
    // but given the original inheritance relation between the two, it's not
    // too likely to need to change.
    for (size_t i = 0; i < ARRAYSIZE(actions); ++i)
    {
        workingBuffer.seek(actions[i]._initialCursorPos);
        bool replaceResult = workingBuffer.replaceSegment(actions[i]._replaceOffset,
                             actions[i]._replaceLength, ByteBuffer(const_cast<char *>(actions[i]._replaceData),
                                     strlen(actions[i]._replaceData), false));

        EXPECT_EQ(actions[i]._expectedResult, replaceResult);
        EXPECT_EQ(actions[i]._expectedSize, workingBuffer.size());
        EXPECT_EQ(workingBuffer, ByteBuffer(const_cast<char *>(actions[i]._expectedData),
                                            strlen(actions[i]._expectedData), false));
        EXPECT_EQ(workingBuffer.cursor(),
                  (void *)((unsigned char *)workingBuffer + actions[i]._expectedCursorPos));
    }

#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
    EXPECT_TRUE(workingBuffer.checkGuardRegions());
#endif
}

TEST(ByteBuffer_Tests, Buffer_Slice)
{
    const char randomData[] = "This data is just random even though it reads like English.";
    ByteBuffer testBuffer(randomData, sizeof(randomData));

    ByteBuffer nonCopied = testBuffer.slice(0);
    EXPECT_FALSE(nonCopied.bufferOwnsPointer());
    EXPECT_EQ(nonCopied.size(), testBuffer.size());
    EXPECT_EQ(nonCopied, testBuffer);

    ByteBuffer copied = testBuffer.slice(0, ByteBuffer::all_bytes, true);
    EXPECT_TRUE(copied.bufferOwnsPointer());
    EXPECT_EQ(copied.size(), testBuffer.size());
    EXPECT_EQ(copied, testBuffer);

    for (size_t i = 0; i < testBuffer.size(); ++i)
    {
        ByteBuffer segmentToEnd = testBuffer.slice(i);
        EXPECT_EQ(segmentToEnd.size(), testBuffer.size() - i);
        if (segmentToEnd.size() > 0)
        {
            EXPECT_EQ(segmentToEnd[0], randomData[i]);
        }
    }

    for (size_t i = 0; i < testBuffer.size(); ++i)
    {
        for (size_t j = 0; j < testBuffer.size(); ++j)
        {
            ByteBuffer segment = testBuffer.slice(i, j);
            EXPECT_EQ(segment.size(), std::min(j, testBuffer.size() - i));
            if (segment.size() > 0)
            {
                EXPECT_EQ(segment[0], randomData[i]);
            }
        }
    }

    EXPECT_EQ(testBuffer.slice(testBuffer.size() + 2).size(), 0UL);
}

TEST(ByteBuffer_Tests, StreamBuffer_WriteString)
{
    const char stringSource[] = "THIS IS A TEST";
    StreamBuffer test1;
    ASSERT_EQ(test1.size(), 0UL);
    test1.write(string(stringSource), StreamBuffer::NullTerminator::IncludeNull);
    EXPECT_GT(test1.size(), 0UL);
    EXPECT_EQ(test1.position(), sizeof(stringSource));

    StreamBuffer test2;
    test2.write(string(stringSource), StreamBuffer::NullTerminator::ExcludeNull);
    EXPECT_GT(test2.size(), 0UL);
    EXPECT_EQ(test2.position(), sizeof(stringSource) - 1);
}




// BufferEncrypt.h
#ifdef _WIN32
TEST(BufferEncrypt, BufferEncrypt_Encrypt_Decrypt)
{
    // NOTE: This tests the basic functionality of the CryptProtect/UnprotectData calls
    //       but it cannot be used to check that they function correctly in the STCServ
    //       process without elevating to a user that is service-only.
    ByteBuffer testBuffer;
    char memBlock[1024] = {0};
    for (size_t i = 0; i < ARRAYSIZE(memBlock) - 1; ++i)
    {
        // We will generally be encrypting ASCII text, so this is a good rough approx.
        memBlock[i] = getRandomChar();
    }
    ASSERT_TRUE(testBuffer.setBuffer(memBlock, sizeof(memBlock)));
    EXPECT_EQ(memcmp((const void *)testBuffer, memBlock, min(sizeof(memBlock), testBuffer.size())), 0);

    EXPECT_TRUE(BufferEncrypt::ProcessLocalEncryptBuffer(testBuffer));
    EXPECT_NE(memcmp((const void *)testBuffer, memBlock, min(sizeof(memBlock), testBuffer.size())), 0);

    EXPECT_TRUE(BufferEncrypt::ProcessLocalDecryptBuffer(testBuffer));
    EXPECT_EQ(memcmp((const void *)testBuffer, memBlock, min(sizeof(memBlock), testBuffer.size())), 0);
}

TEST(BufferEncrypt, BufferEncrypt_Encrypt_Decrypt_Salted)
{
    // NOTE: This tests the basic functionality of the CryptProtect/UnprotectData calls
    //       but it cannot be used to check that they function correctly in the STCServ
    //       process without elevating to a user that is service-only.
    char memBlock[1024] = {0}, saltBlock[ARRAYSIZE(memBlock)] = {0};
    for (size_t i = 0; i < (ARRAYSIZE(memBlock) << 1) - 2; ++i)
    {
        if (i % 2)
        {
            // We will generally be encrypting ASCII text, so this is a good rough approx.
            memBlock[i >> 1] = getRandomChar();
        }
        else
        {
            saltBlock[i >> 1] = getRandomChar(52);
        }
    }

    ByteBuffer testBuffer, saltBuffer;
    ASSERT_TRUE(testBuffer.setBuffer(memBlock, sizeof(memBlock)));
    ASSERT_TRUE(saltBuffer.setBuffer(saltBlock, sizeof(saltBlock)));
    EXPECT_EQ(memcmp((const void *)testBuffer, memBlock, min(sizeof(memBlock), testBuffer.size())), 0);

    EXPECT_TRUE(BufferEncrypt::ProcessLocalEncryptBuffer(testBuffer, saltBuffer));
    EXPECT_NE(memcmp((const void *)testBuffer, memBlock, min(sizeof(memBlock), testBuffer.size())), 0);

    EXPECT_TRUE(BufferEncrypt::ProcessLocalDecryptBuffer(testBuffer, saltBuffer));
    EXPECT_EQ(memcmp((const void *)testBuffer, memBlock, min(sizeof(memBlock), testBuffer.size())), 0);
}
#endif

bool testFuncObjectUnwinding(const void *rawPtr, size_t testSize, char testChar)
{
    bool testOkay = true;
    for (size_t i = 0; i < testSize; ++i)
    {
        if (((const uint8_t *)rawPtr)[i] == testChar)
        {
            testOkay = false;
            break;
        }
    }
    return testOkay;
}

#ifdef _WIN32
bool testFuncNoObjectUnwinding(const void *rawPtr, size_t testSize, char testChar)
{
    __try
    {
        return testFuncObjectUnwinding(rawPtr, testSize, testChar);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return false;
}
#endif

TEST(BufferEncrypt, SecureBuffer_Constructor_And_Assignment)
{
    SecureBuffer emptyBuffer, emptyBuffer2;
    EXPECT_EQ(emptyBuffer.size(), 0UL);
    EXPECT_EQ((const void *)emptyBuffer, nullptr);
    EXPECT_FALSE(emptyBuffer.isProtected());
    EXPECT_EQ(emptyBuffer, emptyBuffer2);


    char memBlock[1024] = {0};
    for (size_t i = 0; i < ARRAYSIZE(memBlock) - 1; ++i)
    {
        memBlock[i] = getRandomChar();
    }

    SecureBuffer testBuffer1(memBlock, sizeof(memBlock));
    EXPECT_EQ(testBuffer1.size(), sizeof(memBlock));
    EXPECT_EQ(memcmp((const void *)testBuffer1, memBlock, min(sizeof(memBlock), testBuffer1.size())),
              0);

    ASSERT_EQ((const void *)testBuffer1, testBuffer1.cursor());
    EXPECT_EQ(testBuffer1.position(), 0UL);
    char tempBuff[sizeof(memBlock)];
    EXPECT_EQ(testBuffer1.read(tempBuff, sizeof(tempBuff)), sizeof(tempBuff));
    EXPECT_EQ(testBuffer1.position(), sizeof(tempBuff));
    EXPECT_TRUE(testBuffer1.seek(0));
    ASSERT_EQ((const void *)testBuffer1, testBuffer1.cursor());
    EXPECT_EQ(testBuffer1.position(), 0UL);

    ByteBuffer testBuffer2(testBuffer1);
    EXPECT_EQ(testBuffer2, testBuffer1);
    EXPECT_NE((const void *)testBuffer2, (const void *)testBuffer1);

    StreamBuffer testBuffer3(testBuffer1);
    EXPECT_EQ(testBuffer3, testBuffer1);
    EXPECT_NE((const void *)testBuffer3, (const void *)testBuffer1);

    SecureBuffer testBuffer4(testBuffer1);
    EXPECT_EQ(testBuffer4, testBuffer1);
    EXPECT_NE((const void *)testBuffer4, (const void *)testBuffer1);

    const void *rawPtr = 0;
    const size_t testSize = 1024;
    {
        SecureBuffer emptyBufferSized(testSize);
        rawPtr = (const void *)emptyBufferSized;

        EXPECT_NE(rawPtr, nullptr);
        EXPECT_EQ(emptyBufferSized.size(), testSize);
        for (size_t i = 0; i < emptyBufferSized.size(); ++i)
        {
            EXPECT_EQ(((const uint8_t *)emptyBufferSized)[i], 0);
            ((uint8_t *)emptyBufferSized)[i] = 0x7A;
        }
    }
#ifdef _WIN32
    // We are sneaking a peak (synchronously) at the memory we just freed. In debug mode
    // it will be filled with a pattern, in release mode it should be filled with zeros.
    // There is a chance we will be attempting to access memory in an invalid page, so we
    // are attempting to protect against a segmentation fault.
    bool testOkay = testFuncNoObjectUnwinding(rawPtr, testSize, 0x7A);
#else
    bool testOkay = testFuncObjectUnwinding(rawPtr, testSize, 0x7A);
#endif

    // NOTE: If you see this test fail randomly it may be okay; it possible for the freed memory
    //       to be touched by another allocation on a worker thread. If possible, move this
    //       whole test earlier in the test regimen.
    EXPECT_TRUE(testOkay);
}

#ifdef _WIN32
TEST(BufferEncrypt, SecureBuffer_Protect)
{
    SecureBuffer emptyBuffer;

    // Empty buffer has a null pointer and can't be protected/unprotected using the underlying
    // windows protect-memory functions. Note this.
    EXPECT_FALSE(emptyBuffer.isProtected());
    EXPECT_FALSE(emptyBuffer.protect());
    EXPECT_FALSE(emptyBuffer.isProtected());
    EXPECT_FALSE(emptyBuffer.unprotect());
    EXPECT_FALSE(emptyBuffer.isProtected());
    EXPECT_EQ(emptyBuffer.size(), 0UL);

    char memBlock[1023] = {0};
    ASSERT_NE(sizeof(memBlock) % CRYPTPROTECTMEMORY_BLOCK_SIZE, 0);
    for (size_t i = 0; i < ARRAYSIZE(memBlock) - 1; ++i)
    {
        memBlock[i] = getRandomChar();
    }

    SecureBuffer simpleBuffer1(memBlock, sizeof(memBlock));
    EXPECT_EQ(simpleBuffer1.size(), sizeof(memBlock));
    EXPECT_EQ(memcmp((const void *)simpleBuffer1, memBlock, min(sizeof(memBlock),
                     simpleBuffer1.size())), 0);

    SecureBuffer preProtectCopy;

    preProtectCopy = simpleBuffer1;

    EXPECT_FALSE(preProtectCopy.isProtected());
    EXPECT_FALSE(simpleBuffer1.isProtected());

    EXPECT_EQ(preProtectCopy, simpleBuffer1);

    EXPECT_TRUE(simpleBuffer1.protect());
    EXPECT_TRUE(simpleBuffer1.isProtected());

    // An attempt to protect a protected buffer should fail internally, but the protection is
    // not invalidated so the protect() call should succeed.
    EXPECT_TRUE(simpleBuffer1.protect());
    EXPECT_TRUE(simpleBuffer1.isProtected());

    SecureBuffer postProtectCopy;

    postProtectCopy = simpleBuffer1;

    EXPECT_NE(preProtectCopy, simpleBuffer1);
    EXPECT_EQ(postProtectCopy, simpleBuffer1);

    EXPECT_NE(memcmp((const void *)simpleBuffer1, memBlock, min(sizeof(memBlock),
                     simpleBuffer1.size())), 0);

    EXPECT_TRUE(simpleBuffer1.unprotect());
    EXPECT_FALSE(simpleBuffer1.isProtected());
    EXPECT_EQ(simpleBuffer1.size(), sizeof(memBlock));

    EXPECT_NE(postProtectCopy, simpleBuffer1);

    EXPECT_TRUE(postProtectCopy.unprotect());
    EXPECT_FALSE(postProtectCopy.isProtected());

    EXPECT_EQ(postProtectCopy, simpleBuffer1);

    EXPECT_EQ(memcmp((const void *)simpleBuffer1, memBlock, min(sizeof(memBlock),
                     simpleBuffer1.size())), 0);

    EXPECT_EQ(preProtectCopy, simpleBuffer1);
}

TEST(BufferEncrypt, SecureBuffer_Protection_Lost)
{

    char memBlock2[1026] = {0};
    ASSERT_NE(sizeof(memBlock2) % CRYPTPROTECTMEMORY_BLOCK_SIZE, 0);
    for (size_t i = 0; i < ARRAYSIZE(memBlock2) - 1; ++i)
    {
        unsigned int randVal = 0;
        memBlock2[i] = getRandomChar();
    }

    SecureBuffer simpleBuffer2(memBlock2, sizeof(memBlock2));
    EXPECT_EQ(simpleBuffer2.size(), sizeof(memBlock2));
    EXPECT_EQ(memcmp((const void *)simpleBuffer2, memBlock2, min(sizeof(memBlock2),
                     simpleBuffer2.size())), 0);

    EXPECT_TRUE(simpleBuffer2.protect());
    EXPECT_TRUE(simpleBuffer2.isProtected());

    simpleBuffer2.write(ByteBuffer(2));

    EXPECT_FALSE(simpleBuffer2.isProtected());

    EXPECT_TRUE(simpleBuffer2.protect());
    EXPECT_TRUE(simpleBuffer2.isProtected());

    EXPECT_TRUE(simpleBuffer2.setBuffer(memBlock2, sizeof(memBlock2)));

    EXPECT_FALSE(simpleBuffer2.isProtected());

    EXPECT_TRUE(simpleBuffer2.protect());
    EXPECT_TRUE(simpleBuffer2.isProtected());

    simpleBuffer2.resetSize();

    EXPECT_FALSE(simpleBuffer2.isProtected());
}

TEST(BufferEncrypt, SecureBuffer_Protection_Invalidated)
{
    char memBlock3[1024] = {0};
    for (size_t i = 0; i < ARRAYSIZE(memBlock3) - 1; ++i)
    {
        memBlock3[i] = getRandomChar();
    }

    SecureBuffer simpleBuffer3(memBlock3, sizeof(memBlock3));
    EXPECT_EQ(simpleBuffer3.size(), sizeof(memBlock3));
    EXPECT_EQ(memcmp((const void *)simpleBuffer3, memBlock3, min(sizeof(memBlock3),
                     simpleBuffer3.size())), 0);

    EXPECT_TRUE(simpleBuffer3.protect());
    EXPECT_TRUE(simpleBuffer3.isProtected());

    ASSERT_NE((const uint8_t *)simpleBuffer3, nullptr);
    *(uint8_t *)simpleBuffer3 = (uint8_t)(*(const uint8_t *)simpleBuffer3 + 1);

    // Protection is still on, even though the buffer has been invalidated.
    EXPECT_TRUE(simpleBuffer3.isProtected());

    EXPECT_TRUE(simpleBuffer3.unprotect());
    EXPECT_FALSE(simpleBuffer3.isProtected());

    // But the original data is corrupted. This cannot be helped (as currently defined).
    EXPECT_NE(memcmp((const void *)simpleBuffer3, memBlock3, min(sizeof(memBlock3),
                     simpleBuffer3.size())), 0);
}
#endif

TEST(BufferEncrypt, SecureBuffer_Base64_Encode)
{
    // Adapted from X509 Base64.
    SecureBuffer inBuf0, outBuf0;

    EXPECT_TRUE(inBuf0.base64Encode(outBuf0));
    EXPECT_EQ(outBuf0.size(), 0UL);

    struct
    {
        const char *_inStr;
        const char *_outStr;
    } testPairs[] =
    {
        { "A", "QQ==" },
        { "AB", "QUI=" },
        { "ABC", "QUJD" },
        { "ABCD", "QUJDRA==" },
        {
            "2014-Mar-04 20:21:35.557753 [0000000018E8AFB0] {win_cloud_http.cpp:199} HTTP response text: {\"access_token\":\"2/gAAAAAdDbj4WRLEn4VjXAXD7lOx"
            "3rIAYjS6cugE4PHO_yJuU1hdVTeoEf0fnswPYytDJT-hD-Q7QkKhjFnIt3H5cfP-n8zy42WGdSj3MbLWsxgVGOr9YjcvwCOjaVPspupHsQXZFRqUkP9rjzEByIJNUupAqjitTYCSwaVG--"
            "YCFH6GL5AEAAIAAAABCJWVoCqEDis2YZk5Cs3dPK7B_ruEWGE5-IyUNMAG_ZoMBa3cv6e2mBFX-kx5xp9vqc37KUXG-PgUfMIw6CEB6rlv-O8hwTaWuBaIe0F4rz1BncYCwXITvMR9c9_I"
            "w0s9eeZP7qKQxy0JSlUebJUTzbWSX_r_xC8iWOtS-_Pw2TZTUCyJJri_Z97s_Ro8nGtFbZDYOxk60ljhAod__G5QleGObLUvSyrryFxVFJKlPl4eoMey_fNQpXLwVpf01eXmVLMqrHnqZ2_"
            "Lfdu-GUs0sOz3eyK0acYJKm7hCPP9x-t0xKnV-7G7MEAXw4Ce-fI3OjSYpd0JokrfrYCkbrkUsm5vbL1GwmkkZ3P61i3j4k2JMsunMkbu72gMPoFgylrB1gUNTDidBe95lQ8J7gF1J2bc_eg"
            "jZgjfXOtvUdtdLV-NNF_-rFLr-PeDFSpRuBL90J8N89qpNqrRg_fL3ujAsuoL5T8oqkJxriNLqFCRrlwh2NexeGC4LAFAPg2XrG13qqnj0uzawPbrvCxpTt60m3eXoxENWIelIddB34YFzq"
            "Cs6LU__QxPD2WYbq2OLA4pZWgVmtBAaFn3OmYnRyDBFK_046uPkC2-e8igbiCWDl9HtLWuRzQNMkkpWzNh1Ews/dTwrnf4F0Qg\",\"token_type\":\"bearer\",\"expires_in\":\""
            "5400\",\"refresh_token\":\"2/URkq!IAAAANAtQ54vitu3Grz8TC0Gg2DzjCsD_XkkjpgzXAqDSJgHYQEAAAHDHnXzp2cr-X0hlaRA8YZ8u3dhnHWSCHbUifB2ufkjC46j-GxF3fz4w65"
            "8K-qw_pqTH5og6ZmW5TuK0a_1StcCal01V1aiOoQ0zbspWONRomXLRB4mLK350hQb1eAbo-RM5Ajs6gen3TfeAMwx20RgzMvBQX4VwEusXUxZtFlUSMmidRJr9aLdXRekwOOsLLMs8rlEg_5ov"
            "gYYJmQzTIt2nJMnGajrHJvc78x_z3AmKpVuIdxiEAmfn6q2jGq-funwRs6lg69NLfufRnw4elKR0jXK4c0yDxFRCv6HxVHlIq5oFWgBVbFXMPxfSjBkTWKal45ZjIURY7Gjsgg28HDYL_JCHlL"
            "GXKLJlrc3xQbNIxm8c49-vAi6basV3QRrDbDbmwCvEiYva2IsGfppYqkkT4YpFjDRan5yyTLljKZAtvR46ThPlX55-dM0YSvp-Tj0jwFtQnH8FY0N_qoiHTvQ/dTwrnf4F0Qg\",\"scope\":\""
            "user:details user:scope profile:full profile:basic profile:full:write connection:basic\"}",

            "MjAxNC1NYXItMDQgMjA6MjE6MzUuNTU3NzUzIFswMDAwMDAwMDE4RThBRkIwXSB7d2luX2Nsb3VkX2h0dHAuY3BwOjE5OX0gSFRUUCByZXNwb25zZSB0ZXh0OiB7ImFjY2Vzc190b2tl"
            "biI6IjIvZ0FBQUFBZERiajRXUkxFbjRWalhBWEQ3bE94M3JJQVlqUzZjdWdFNFBIT195SnVVMWhkVlRlb0VmMGZuc3dQWXl0REpULWhELVE3UWtLaGpGbkl0M0g1Y2ZQLW44enk0MldH"
            "ZFNqM01iTFdzeGdWR09yOVlqY3Z3Q09qYVZQc3B1cEhzUVhaRlJxVWtQOXJqekVCeUlKTlV1cEFxaml0VFlDU3dhVkctLVlDRkg2R0w1QUVBQUlBQUFBQkNKV1ZvQ3FFRGlzMllaazVD"
            "czNkUEs3Ql9ydUVXR0U1LUl5VU5NQUdfWm9NQmEzY3Y2ZTJtQkZYLWt4NXhwOXZxYzM3S1VYRy1QZ1VmTUl3NkNFQjZybHYtTzhod1RhV3VCYUllMEY0cnoxQm5jWUN3WElUdk1SOWM5"
            "X0l3MHM5ZWVaUDdxS1F4eTBKU2xVZWJKVVR6YldTWF9yX3hDOGlXT3RTLV9QdzJUWlRVQ3lKSnJpX1o5N3NfUm84bkd0RmJaRFlPeGs2MGxqaEFvZF9fRzVRbGVHT2JMVXZTeXJyeUZ4"
            "VkZKS2xQbDRlb01leV9mTlFwWEx3VnBmMDFlWG1WTE1xckhucVoyX0xmZHUtR1VzMHNPejNleUswYWNZSkttN2hDUFA5eC10MHhLblYtN0c3TUVBWHc0Q2UtZkkzT2pTWXBkMEpva3Jm"
            "cllDa2Jya1VzbTV2YkwxR3dta2taM1A2MWkzajRrMkpNc3VuTWtidTcyZ01Qb0ZneWxyQjFnVU5URGlkQmU5NWxROEo3Z0YxSjJiY19lZ2paZ2pmWE90dlVkdGRMVi1OTkZfLXJGTHIt"
            "UGVERlNwUnVCTDkwSjhOODlxcE5xclJnX2ZMM3VqQXN1b0w1VDhvcWtKeHJpTkxxRkNScmx3aDJOZXhlR0M0TEFGQVBnMlhyRzEzcXFuajB1emF3UGJydkN4cFR0NjBtM2VYb3hFTldJ"
            "ZWxJZGRCMzRZRnpxQ3M2TFVfX1F4UEQyV1licTJPTEE0cFpXZ1ZtdEJBYUZuM09tWW5SeURCRktfMDQ2dVBrQzItZThpZ2JpQ1dEbDlIdExXdVJ6UU5Na2twV3pOaDFFd3MvZFR3cm5m"
            "NEYwUWciLCJ0b2tlbl90eXBlIjoiYmVhcmVyIiwiZXhwaXJlc19pbiI6IjU0MDAiLCJyZWZyZXNoX3Rva2VuIjoiMi9VUmtxIUlBQUFBTkF0UTU0dml0dTNHcno4VEMwR2cyRHpqQ3NE"
            "X1hra2pwZ3pYQXFEU0pnSFlRRUFBQUhESG5YenAyY3ItWDBobGFSQThZWjh1M2RobkhXU0NIYlVpZkIydWZrakM0NmotR3hGM2Z6NHc2NThLLXF3X3BxVEg1b2c2Wm1XNVR1SzBhXzFT"
            "dGNDYWwwMVYxYWlPb1EwemJzcFdPTlJvbVhMUkI0bUxLMzUwaFFiMWVBYm8tUk01QWpzNmdlbjNUZmVBTXd4MjBSZ3pNdkJRWDRWd0V1c1hVeFp0RmxVU01taWRSSnI5YUxkWFJla3dP"
            "T3NMTE1zOHJsRWdfNW92Z1lZSm1RelRJdDJuSk1uR2FqckhKdmM3OHhfejNBbUtwVnVJZHhpRUFtZm42cTJqR3EtZnVud1JzNmxnNjlOTGZ1ZlJudzRlbEtSMGpYSzRjMHlEeEZSQ3Y2"
            "SHhWSGxJcTVvRldnQlZiRlhNUHhmU2pCa1RXS2FsNDVaaklVUlk3R2pzZ2cyOEhEWUxfSkNIbExHWEtMSmxyYzN4UWJOSXhtOGM0OS12QWk2YmFzVjNRUnJEYkRibXdDdkVpWXZhMklz"
            "R2ZwcFlxa2tUNFlwRmpEUmFuNXl5VExsaktaQXR2UjQ2VGhQbFg1NS1kTTBZU3ZwLVRqMGp3RnRRbkg4RlkwTl9xb2lIVHZRL2RUd3JuZjRGMFFnIiwic2NvcGUiOiJ1c2VyOmRldGFp"
            "bHMgdXNlcjpzY29wZSBwcm9maWxlOmZ1bGwgcHJvZmlsZTpiYXNpYyBwcm9maWxlOmZ1bGw6d3JpdGUgY29ubmVjdGlvbjpiYXNpYyJ9"
        }
    };

    for (size_t i = 0; i < ARRAYSIZE(testPairs); ++i)
    {
        size_t inLen = string(testPairs[i]._inStr).size();
        size_t outLen = string(testPairs[i]._outStr).size();

        EXPECT_GT(inLen, 0UL);
        EXPECT_GT(outLen, 0UL);

        SecureBuffer inBuf(testPairs[i]._inStr, inLen), outBuf;
        EXPECT_EQ(inBuf.size(), (size_t)inLen);
        EXPECT_TRUE(inBuf.base64Encode(outBuf));
        EXPECT_EQ(outBuf.size(), outLen);

        EXPECT_EQ(memcmp((const void *)outBuf, testPairs[i]._outStr, min(outLen, outBuf.size())), 0);

#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
        EXPECT_TRUE(outBuf.checkGuardRegions());
#endif
    }
}

TEST(BufferEncrypt, SecureBuffer_Base64_Decode)
{
    // Adapted from X509 Base64.
    SecureBuffer inBuf0, outBuf0;

    EXPECT_TRUE(inBuf0.base64Decode(outBuf0));
    EXPECT_EQ(outBuf0.size(), 0UL);

    struct
    {
        const char *_inStr;
        const char *_outStr;
        bool _expectGood;
    } testPairs[] =
    {
        { "QQ==", "A", true },
        { "QUI=", "AB", true },
        { "QUJD", "ABC", true },
        { "QUJDRA==", "ABCD", true },
        { "    QUJDRA==  ", "ABCD", true },
        {
            "MjAxNC1NYXItMDQgMjA6MjE6MzUuNTU3NzUzIFswMDAwMDAwMDE4RThBRkIwXSB7d2luX2Nsb3VkX2h0dHAuY3BwOjE5OX0gSFRUUCByZXNwb25zZSB0ZXh0OiB7ImFjY2Vzc190b2tl"
            "biI6IjIvZ0FBQUFBZERiajRXUkxFbjRWalhBWEQ3bE94M3JJQVlqUzZjdWdFNFBIT195SnVVMWhkVlRlb0VmMGZuc3dQWXl0REpULWhELVE3UWtLaGpGbkl0M0g1Y2ZQLW44enk0MldH"
            "ZFNqM01iTFdzeGdWR09yOVlqY3Z3Q09qYVZQc3B1cEhzUVhaRlJxVWtQOXJqekVCeUlKTlV1cEFxaml0VFlDU3dhVkctLVlDRkg2R0w1QUVBQUlBQUFBQkNKV1ZvQ3FFRGlzMllaazVD"
            "czNkUEs3Ql9ydUVXR0U1LUl5VU5NQUdfWm9NQmEzY3Y2ZTJtQkZYLWt4NXhwOXZxYzM3S1VYRy1QZ1VmTUl3NkNFQjZybHYtTzhod1RhV3VCYUllMEY0cnoxQm5jWUN3WElUdk1SOWM5"
            "X0l3MHM5ZWVaUDdxS1F4eTBKU2xVZWJKVVR6YldTWF9yX3hDOGlXT3RTLV9QdzJUWlRVQ3lKSnJpX1o5N3NfUm84bkd0RmJaRFlPeGs2MGxqaEFvZF9fRzVRbGVHT2JMVXZTeXJyeUZ4"
            "VkZKS2xQbDRlb01leV9mTlFwWEx3VnBmMDFlWG1WTE1xckhucVoyX0xmZHUtR1VzMHNPejNleUswYWNZSkttN2hDUFA5eC10MHhLblYtN0c3TUVBWHc0Q2UtZkkzT2pTWXBkMEpva3Jm"
            "cllDa2Jya1VzbTV2YkwxR3dta2taM1A2MWkzajRrMkpNc3VuTWtidTcyZ01Qb0ZneWxyQjFnVU5URGlkQmU5NWxROEo3Z0YxSjJiY19lZ2paZ2pmWE90dlVkdGRMVi1OTkZfLXJGTHIt"
            "UGVERlNwUnVCTDkwSjhOODlxcE5xclJnX2ZMM3VqQXN1b0w1VDhvcWtKeHJpTkxxRkNScmx3aDJOZXhlR0M0TEFGQVBnMlhyRzEzcXFuajB1emF3UGJydkN4cFR0NjBtM2VYb3hFTldJ"
            "ZWxJZGRCMzRZRnpxQ3M2TFVfX1F4UEQyV1licTJPTEE0cFpXZ1ZtdEJBYUZuM09tWW5SeURCRktfMDQ2dVBrQzItZThpZ2JpQ1dEbDlIdExXdVJ6UU5Na2twV3pOaDFFd3MvZFR3cm5m"
            "NEYwUWciLCJ0b2tlbl90eXBlIjoiYmVhcmVyIiwiZXhwaXJlc19pbiI6IjU0MDAiLCJyZWZyZXNoX3Rva2VuIjoiMi9VUmtxIUlBQUFBTkF0UTU0dml0dTNHcno4VEMwR2cyRHpqQ3NE"
            "X1hra2pwZ3pYQXFEU0pnSFlRRUFBQUhESG5YenAyY3ItWDBobGFSQThZWjh1M2RobkhXU0NIYlVpZkIydWZrakM0NmotR3hGM2Z6NHc2NThLLXF3X3BxVEg1b2c2Wm1XNVR1SzBhXzFT"
            "dGNDYWwwMVYxYWlPb1EwemJzcFdPTlJvbVhMUkI0bUxLMzUwaFFiMWVBYm8tUk01QWpzNmdlbjNUZmVBTXd4MjBSZ3pNdkJRWDRWd0V1c1hVeFp0RmxVU01taWRSSnI5YUxkWFJla3dP"
            "T3NMTE1zOHJsRWdfNW92Z1lZSm1RelRJdDJuSk1uR2FqckhKdmM3OHhfejNBbUtwVnVJZHhpRUFtZm42cTJqR3EtZnVud1JzNmxnNjlOTGZ1ZlJudzRlbEtSMGpYSzRjMHlEeEZSQ3Y2"
            "SHhWSGxJcTVvRldnQlZiRlhNUHhmU2pCa1RXS2FsNDVaaklVUlk3R2pzZ2cyOEhEWUxfSkNIbExHWEtMSmxyYzN4UWJOSXhtOGM0OS12QWk2YmFzVjNRUnJEYkRibXdDdkVpWXZhMklz"
            "R2ZwcFlxa2tUNFlwRmpEUmFuNXl5VExsaktaQXR2UjQ2VGhQbFg1NS1kTTBZU3ZwLVRqMGp3RnRRbkg4RlkwTl9xb2lIVHZRL2RUd3JuZjRGMFFnIiwic2NvcGUiOiJ1c2VyOmRldGFp"
            "bHMgdXNlcjpzY29wZSBwcm9maWxlOmZ1bGwgcHJvZmlsZTpiYXNpYyBwcm9maWxlOmZ1bGw6d3JpdGUgY29ubmVjdGlvbjpiYXNpYyJ9",

            "2014-Mar-04 20:21:35.557753 [0000000018E8AFB0] {win_cloud_http.cpp:199} HTTP response text: {\"access_token\":\"2/gAAAAAdDbj4WRLEn4VjXAXD7lOx"
            "3rIAYjS6cugE4PHO_yJuU1hdVTeoEf0fnswPYytDJT-hD-Q7QkKhjFnIt3H5cfP-n8zy42WGdSj3MbLWsxgVGOr9YjcvwCOjaVPspupHsQXZFRqUkP9rjzEByIJNUupAqjitTYCSwaVG--"
            "YCFH6GL5AEAAIAAAABCJWVoCqEDis2YZk5Cs3dPK7B_ruEWGE5-IyUNMAG_ZoMBa3cv6e2mBFX-kx5xp9vqc37KUXG-PgUfMIw6CEB6rlv-O8hwTaWuBaIe0F4rz1BncYCwXITvMR9c9_I"
            "w0s9eeZP7qKQxy0JSlUebJUTzbWSX_r_xC8iWOtS-_Pw2TZTUCyJJri_Z97s_Ro8nGtFbZDYOxk60ljhAod__G5QleGObLUvSyrryFxVFJKlPl4eoMey_fNQpXLwVpf01eXmVLMqrHnqZ2_"
            "Lfdu-GUs0sOz3eyK0acYJKm7hCPP9x-t0xKnV-7G7MEAXw4Ce-fI3OjSYpd0JokrfrYCkbrkUsm5vbL1GwmkkZ3P61i3j4k2JMsunMkbu72gMPoFgylrB1gUNTDidBe95lQ8J7gF1J2bc_eg"
            "jZgjfXOtvUdtdLV-NNF_-rFLr-PeDFSpRuBL90J8N89qpNqrRg_fL3ujAsuoL5T8oqkJxriNLqFCRrlwh2NexeGC4LAFAPg2XrG13qqnj0uzawPbrvCxpTt60m3eXoxENWIelIddB34YFzq"
            "Cs6LU__QxPD2WYbq2OLA4pZWgVmtBAaFn3OmYnRyDBFK_046uPkC2-e8igbiCWDl9HtLWuRzQNMkkpWzNh1Ews/dTwrnf4F0Qg\",\"token_type\":\"bearer\",\"expires_in\":\""
            "5400\",\"refresh_token\":\"2/URkq!IAAAANAtQ54vitu3Grz8TC0Gg2DzjCsD_XkkjpgzXAqDSJgHYQEAAAHDHnXzp2cr-X0hlaRA8YZ8u3dhnHWSCHbUifB2ufkjC46j-GxF3fz4w65"
            "8K-qw_pqTH5og6ZmW5TuK0a_1StcCal01V1aiOoQ0zbspWONRomXLRB4mLK350hQb1eAbo-RM5Ajs6gen3TfeAMwx20RgzMvBQX4VwEusXUxZtFlUSMmidRJr9aLdXRekwOOsLLMs8rlEg_5ov"
            "gYYJmQzTIt2nJMnGajrHJvc78x_z3AmKpVuIdxiEAmfn6q2jGq-funwRs6lg69NLfufRnw4elKR0jXK4c0yDxFRCv6HxVHlIq5oFWgBVbFXMPxfSjBkTWKal45ZjIURY7Gjsgg28HDYL_JCHlL"
            "GXKLJlrc3xQbNIxm8c49-vAi6basV3QRrDbDbmwCvEiYva2IsGfppYqkkT4YpFjDRan5yyTLljKZAtvR46ThPlX55-dM0YSvp-Tj0jwFtQnH8FY0N_qoiHTvQ/dTwrnf4F0Qg\",\"scope\":\""
            "user:details user:scope profile:full profile:basic profile:full:write connection:basic\"}", true
        },
        { "This Is Not VALID", "X", false},
        { "QUJ\0x82RA==", "X", false},
        { "QUJDRA=", "X", false},
        { "QUJDRA", "X", false},
        { "QUJDRA===", "X", false}
    };

    for (size_t i = 0; i < ARRAYSIZE(testPairs); ++i)
    {
        size_t inLen = string(testPairs[i]._inStr).size();
        size_t outLen = string(testPairs[i]._outStr).size();

        EXPECT_GT(inLen, 0UL);
        EXPECT_GT(outLen, 0UL);

        SecureBuffer inBuf(testPairs[i]._inStr, inLen), outBuf;
        EXPECT_EQ(inBuf.size(), (size_t)inLen);

        if (testPairs[i]._expectGood)
        {
            EXPECT_TRUE(inBuf.base64Decode(outBuf));
            EXPECT_EQ(outBuf.size(), outLen);

            EXPECT_EQ(memcmp((const void *)outBuf, testPairs[i]._outStr, min(outLen, outBuf.size())), 0);
        }
        else
        {
            EXPECT_FALSE(inBuf.base64Decode(outBuf));
            EXPECT_EQ(outBuf.size(), 0UL);
        }

#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
        EXPECT_TRUE(outBuf.checkGuardRegions());
#endif
    }
}

TEST(BufferEncrypt, SecureBuffer_SequentialWrite)
{
    SecureBuffer testBuffer;
    testBuffer.write(string("THISISATEST1"));
    testBuffer.write(string("TEST2"));
    testBuffer.write(string("TEST3"));
    testBuffer.write("", 1);
    EXPECT_EQ(string((const char *)&testBuffer[0]), "THISISATEST1TEST2TEST3");
}



#ifdef DEBUG
#ifdef DEBUG_USE_BYTE_BUFFER_GUARD_REGIONS
// Verify that the buffer overrun test catches pre and post-buffer overruns
// in debug mode and ignores untouched buffers.
TEST(BufferEncrypt, SecureBuffer_BufferOverrunTest)
{
    SecureBuffer testBuffer(1024);
    EXPECT_EQ(testBuffer.size(), 1024UL);
    EXPECT_NE(DEBUG_BYTE_BUFFER_PRE_BYTE, 0x00);
    EXPECT_NE(DEBUG_BYTE_BUFFER_POST_BYTE, 0x00);

    if (testBuffer.size() == 1024)
    {
        EXPECT_TRUE(testBuffer.checkGuardRegions());

        uint8_t *ptr = (uint8_t *)testBuffer;
        ptr[1024] = 0x00;
        EXPECT_FALSE(testBuffer.checkGuardRegions());

        ptr[1024] = DEBUG_BYTE_BUFFER_POST_BYTE;
        EXPECT_TRUE(testBuffer.checkGuardRegions());

        ptr[-1] = 0x00;
        EXPECT_FALSE(testBuffer.checkGuardRegions());

        ptr[-1] = DEBUG_BYTE_BUFFER_PRE_BYTE;
        EXPECT_TRUE(testBuffer.checkGuardRegions());
    }
}
#endif
#endif

TEST(BufferEncrypt, SecureBuffer_FromString)
{
    SecureBuffer bufFromEmpty(string(""));
    EXPECT_EQ(bufFromEmpty.size(), 0UL);

    SecureBuffer bufNullTerminatedFromEmpty(string(""), SecureBuffer::NullTerminator::IncludeNull);
    EXPECT_EQ(bufNullTerminatedFromEmpty.size(), 1UL);

    SecureBuffer bufFromString(string("THIS IS A TEST"));
    EXPECT_EQ(bufFromString.size(), 14UL);
    ASSERT_GT(bufFromString.size(), 1UL);
    EXPECT_EQ(bufFromString[0], 'T');

    SecureBuffer bufNullTerminatedFromString(string("THIS IS A TEST"),
            SecureBuffer::NullTerminator::IncludeNull);
    ASSERT_EQ(bufNullTerminatedFromString.size(), 15UL);
    EXPECT_EQ(bufNullTerminatedFromString[0], 'T');
    EXPECT_EQ(bufNullTerminatedFromString[14], '\0');

}






/// STCQueue.h
TEST(STCQueue, Queue_Tests)
{
    struct QueueTestObject
    {
            QueueTestObject(): m_val(0) {}
            QueueTestObject(int val): m_val(val) {}
            int val() const { return m_val; }
        private:
            int m_val;
    };

    Queue<QueueTestObject> queueTest;
    EXPECT_FALSE(queueTest.isClosed());

    EXPECT_TRUE(queueTest.empty());
    EXPECT_EQ(queueTest.size(), 0UL);

    queueTest.push(QueueTestObject(1));
    queueTest.push(QueueTestObject(2));

    EXPECT_FALSE(queueTest.empty());
    EXPECT_EQ(queueTest.size(), 2UL);

    QueueTestObject item1Out;
    EXPECT_TRUE(queueTest.pop(chrono::milliseconds::max(), item1Out));
    EXPECT_FALSE(queueTest.empty());
    EXPECT_EQ(queueTest.size(), 1UL);

    EXPECT_EQ(item1Out.val(), 1);

    QueueTestObject item2Out;
    EXPECT_TRUE(queueTest.pop(chrono::milliseconds::max(), item2Out));
    EXPECT_TRUE(queueTest.empty());
    EXPECT_EQ(queueTest.size(), 0UL);

    EXPECT_EQ(item2Out.val(), 2);

    EXPECT_FALSE(queueTest.pop(chrono::milliseconds(2), item2Out));
    EXPECT_TRUE(queueTest.empty());
    EXPECT_EQ(queueTest.size(), 0UL);

    ASSERT_TRUE(queueTest.empty());

    queueTest.close();
    EXPECT_TRUE(queueTest.isClosed());

    queueTest.push(QueueTestObject(3));
    EXPECT_TRUE(queueTest.isClosed());
    EXPECT_TRUE(queueTest.empty());



    bool terminated = false;
    std::list<int> resultList;
    Queue<QueueTestObject> threadQueue;
    thread testThread([&threadQueue, &resultList, &terminated]()
    {
        while (!threadQueue.isClosed())
        {
            QueueTestObject tempObject;
            while (threadQueue.pop(chrono::milliseconds::max(), tempObject))
            {
                resultList.push_back(tempObject.val());
            }
        }
        terminated = true;
    });

    threadQueue.push(QueueTestObject(6));
    threadQueue.push(QueueTestObject(7));
    threadQueue.push(QueueTestObject(61));
    threadQueue.push(QueueTestObject(27));

    size_t cycleCount = 0;
    while (!threadQueue.empty())
    {
        this_thread::sleep_for(chrono::milliseconds(1));
        ++cycleCount;
        ASSERT_LT(cycleCount, 5000UL);
    }
    threadQueue.close();

    if (testThread.joinable())
    {
        testThread.join();
    }
    else
    {
        testThread.detach();
    }
    EXPECT_TRUE(terminated);


    for (int result : {27, 61, 7, 6})
    {
        ASSERT_TRUE(resultList.size() > 0);
        EXPECT_EQ(resultList.back(), result);
        if (!resultList.empty()) resultList.pop_back();
    }
}


// str_helpers
using namespace Iotivity::str_helper;
TEST(Str_Helpers, split)
{
    auto empty = split("", '.');
    EXPECT_EQ(empty.size(), 1UL);
    if (empty.size() >= 1)
    {
        EXPECT_EQ(empty[0], "");
    }

    auto res1 = split("nomatches", '.');
    EXPECT_EQ(res1.size(), 1UL);
    if (res1.size() >= 1)
    {
        EXPECT_EQ(res1[0], "nomatches");
    }

    auto res2 = split("two.parts", '.');
    EXPECT_EQ(res2.size(), 2UL);
    if (res2.size() >= 2)
    {
        EXPECT_EQ(res2[0], "two");
        EXPECT_EQ(res2[1], "parts");
    }

    auto res3 = split("three.parts.test", '.');
    EXPECT_EQ(res3.size(), 3UL);
    if (res3.size() >= 3)
    {
        EXPECT_EQ(res3[0], "three");
        EXPECT_EQ(res3[1], "parts");
        EXPECT_EQ(res3[2], "test");
    }

    auto res4 = split(".startWithDelim", '.');
    EXPECT_EQ(res4.size(), 2UL);
    if (res4.size() >= 2)
    {
        EXPECT_EQ(res4[0], "");
        EXPECT_EQ(res4[1], "startWithDelim");
    }

    auto res5 = split("endWithDelim.", '.');
    EXPECT_EQ(res5.size(), 2UL);
    if (res5.size() >= 2)
    {
        EXPECT_EQ(res5[0], "endWithDelim");
        EXPECT_EQ(res5[1], "");
    }

    auto res6 = split(".interdelim.", '.');
    EXPECT_EQ(res6.size(), 3UL);
    if (res6.size() >= 3)
    {
        EXPECT_EQ(res6[0], "");
        EXPECT_EQ(res6[1], "interdelim");
        EXPECT_EQ(res6[2], "");
    }

    auto res7 = split("....", '.');
    EXPECT_EQ(res7.size(), 5UL);
    if (res7.size() >= 5)
    {
        EXPECT_EQ(res7[0], "");
        EXPECT_EQ(res7[1], "");
        EXPECT_EQ(res7[2], "");
        EXPECT_EQ(res7[3], "");
        EXPECT_EQ(res7[4], "");
    }
}

#ifdef _WIN32
// NOTE: These tests are currently WIN32-only as they rely on the availability of the
//       codecvt_utf8 class from C++11 (unvailable in the target Linix buld at the time).
TEST(Str_Helpers, UTF32ToUTF8)
{
    auto toConvert = codecvt_utf8<char32_t>();
    mbstate_t state;
    char tempBuffer[16] = {0}, tempBuffer2[16] = {0};
    const char32_t *nextIn = nullptr;

    for (char32_t c = 0; c < 0x10FFFF; ++c)
    {
        char *nextOut = nullptr;

        string initialStr;
        auto result = toConvert.out(state, &c, &c + 1, nextIn,
                                    &tempBuffer[0], &tempBuffer[0] + sizeof(tempBuffer), nextOut);

        ASSERT_EQ(result, codecvt_base::ok);

        size_t written = 0;
        str_helper::utf32ToUtf8(c, tempBuffer2, sizeof(tempBuffer2), written);

        EXPECT_EQ(nextOut - &tempBuffer[0], written);
        if (nextOut - &tempBuffer[0] == written)
        {
            EXPECT_TRUE(ByteBuffer(tempBuffer, nextOut - &tempBuffer[0], false) ==
                        ByteBuffer(tempBuffer2, written, false));
        }
    }
}

TEST(Str_Helpers, UTF8ToUTF32)
{
    auto toConvert = codecvt_utf8<char32_t>();
    mbstate_t state;
    char tempBuffer[16] = {0}, tempBuffer2[16] = {0};
    const char32_t *nextIn = nullptr;

    for (char32_t c = 0; c < 0x10FFFF; ++c)
    {
        char *nextOut = nullptr;

        string initialStr;
        auto result = toConvert.out(state, &c, &c + 1, nextIn,
                                    &tempBuffer[0], &tempBuffer[0] + sizeof(tempBuffer), nextOut);

        ASSERT_EQ(result, codecvt_base::ok);

        char32_t convertChar{0}, *tempOut = nullptr;
        const char *tempIn = nullptr;
        auto result2 = toConvert.in(state, &tempBuffer[0], nextOut, tempIn,
                                    &convertChar, &convertChar + 1, tempOut);

        ASSERT_EQ(result2, codecvt_base::ok);

        size_t inLength = nextOut - &tempBuffer[0];

        ASSERT_GT(inLength, 0UL);

        size_t consumed = 0;
        ASSERT_EQ(convertChar, c);
        EXPECT_EQ(str_helper::utf8ToUtf32(tempBuffer, inLength, consumed), c);
        EXPECT_EQ(consumed, inLength);
    }

    {
        // Out-Of-Range Random (5 Char)
        char ooRange[] = "\xF8\x84\x85\x9A\x9B";
        size_t consumed2 = 1;
        EXPECT_EQ(str_helper::utf8ToUtf32(ooRange, sizeof(ooRange), consumed2), 0);
        EXPECT_EQ(consumed2, 0);
    }

    {
        // Out-Of-Range Random (6 Char)
        char ooRange[] = "\xFC\x84\x85\x9A\x9B\x8D";
        size_t consumed2 = 1;
        EXPECT_EQ(str_helper::utf8ToUtf32(ooRange, sizeof(ooRange), consumed2), 0);
        EXPECT_EQ(consumed2, 0);
    }

    {
        // Out-Of-Range 3 char with invalid inter-value
        char ooRange[] = "\xE2\xC4\x85";
        size_t consumed2 = 1;
        EXPECT_EQ(str_helper::utf8ToUtf32(ooRange, sizeof(ooRange), consumed2), 0);
        EXPECT_EQ(consumed2, 0);
    }

    {
        // Out-Of-Range 4 char >0x10FFFF
        char ooRange[] = "\xF7\xB8\xBF\xBF";
        size_t consumed2 = 1;
        EXPECT_EQ(str_helper::utf8ToUtf32(ooRange, sizeof(ooRange), consumed2), 0);
        EXPECT_EQ(consumed2, 0);
    }

}
#endif // _WIN32


/////
// logstream

#if defined(LOGSTREAM_ENABLE_LOGGING)


// These tests are designed to cover the simple default logging case. If more features
// are enabled in logging (time-stamp, line-number), the formatting breaks. For the moment
// these tests are not included if these features are enabled.
#if defined(LOGSTREAM_INCLUDE_THREAD) && !defined(LOGSTREAM_INCLUDE_TIME) && !defined(LOGSTREAM_INCLUDE_FILE) && !defined(LOGSTREAM_INCLUDE_LINE)

TEST(Log_Stream, MultiThread_Log_SingleThread)
{
    ostringstream output;

    try
    {
        streamlogredirect::redirectLoggingToStream(output);

        logstream os;
        os << "SIMPLE " << "LOGGING TEST" << endl;

        os << "Multi\nSegment\nLogging Test\n" << endl;

        os.flush();

    }
    catch (...) {}
    streamlogredirect::redirectLoggingToVoid();

    streamlogredirect::redirectLoggingToStream(cout);


    ostringstream tempStr;

    tempStr << "[" << this_thread::get_id() << "](INFO|DEFAULT): SIMPLE LOGGING TEST" << endl;
    tempStr << "[" << this_thread::get_id() << "](INFO|DEFAULT): Multi" << endl;
    tempStr << "[" << this_thread::get_id() << "](INFO|DEFAULT): Segment" << endl;
    tempStr << "[" << this_thread::get_id() << "](INFO|DEFAULT): Logging Test" << endl;
    tempStr << "[" << this_thread::get_id() << "](INFO|DEFAULT): " << endl;

    EXPECT_EQ(output.str(), tempStr.str());

    // TODO: Correct test to look for line endings.
}

TEST(Log_Stream, MultiThread_Log_dout)
{
    ostringstream output;

    try
    {
        streamlogredirect::redirectLoggingToStream(output);
        dout << "SIMPLE LOGGING TEST" << endl;
        dout << "Multi\nSegment\nLogging Test\n" << endl;
        dout.flush();

    }
    catch (...) {}
    streamlogredirect::redirectLoggingToVoid();

    streamlogredirect::redirectLoggingToStream(cout);


    ostringstream tempStr;

    tempStr << "[" << this_thread::get_id() << "](INFO|DEFAULT): SIMPLE LOGGING TEST" << endl;
    tempStr << "[" << this_thread::get_id() << "](INFO|DEFAULT): Multi" << endl;
    tempStr << "[" << this_thread::get_id() << "](INFO|DEFAULT): Segment" << endl;
    tempStr << "[" << this_thread::get_id() << "](INFO|DEFAULT): Logging Test" << endl;
    tempStr << "[" << this_thread::get_id() << "](INFO|DEFAULT): " << endl;

    EXPECT_EQ(output.str(), tempStr.str());
}
#endif


TEST(Log_Stream, MultiThread_Log_MultiThread)
{
    ostringstream output;

    try
    {
        streamlogredirect::redirectLoggingToStream(output);

        logstream os;
        vector<thread> threads;
        for (size_t i = 0; i < 10; ++i)
        {
            threads.emplace_back(thread([&os]()
            {
                for (size_t i = 0; i < 30; ++i)
                {
                    os << "OUTPUT TEST* " << i << endl;
                }
            }));
        }

        for (auto &t : threads)
        {
            if (t.joinable()) t.join();
        }
        os.flush();

    }
    catch (...) {}
    streamlogredirect::redirectLoggingToVoid();

    streamlogredirect::redirectLoggingToStream(cout);

    string resultStr = output.str();
    vector<string> lines = str_helper::split(resultStr, '\n');


    for (const auto &l : lines)
    {
        if (l.size() > 0)
        {
            EXPECT_EQ(l[0], '[');
            EXPECT_EQ(l.find_first_of("*"), l.find_last_of("*"));
            EXPECT_NE(l.find_first_of("*"), string::npos);
        }
    }
}

TEST(Log_Stream, MultiThread_Log_Callback)
{
    ostringstream output;
    list<string> outLines;

    try
    {
        streamlogredirect::redirectLoggingToCallback(
        [&outLines](const string & line) { outLines.push_back(line); });

        dout << "SIMPLE LOGGING TEST" << endl;
        dout << "Multi\nSegment\nLogging Test\n" << endl;
        dout.flush();

    }
    catch (...) {}
    streamlogredirect::redirectLoggingToVoid();

    streamlogredirect::redirectLoggingToStream(cout);

    EXPECT_EQ(outLines.size(), 5UL);
}

#endif // LOGSTREAM_ENABLE_LOGGING


///////////
TEST(RandomBuffer, Rand_Buffer)
{
    RandomBuffer emptyBuf(0);
    EXPECT_EQ(emptyBuf.size(), 0UL);

    RandomBuffer someBuf(4096);
    EXPECT_EQ(someBuf.size(), 4096UL);

    RandomBuffer someBuf2(4096);
    EXPECT_EQ(someBuf2.size(), 4096UL);

    // NOTE: There is a very small chance that these two buffers will actually be the same,
    //       presuming hardware random-numer generation. If this fails for you here and the code
    //       has not otherwise regressed, buy a lottery ticket today.
    EXPECT_NE(someBuf, someBuf2);
    EXPECT_TRUE(someBuf < someBuf2 || someBuf2 < someBuf);

}


//////////
// async_notify.h

struct AsyncTestEvent
{
        AsyncTestEvent(const std::string &str): _str(str) {}

        const std::string str() const { return _str; }
    private:
        std::string _str;
};
typedef Iotivity::NotifyAsyncBase<AsyncTestEvent> AsyncTestNotifier;

struct TriggerTestThread
{
        TriggerTestThread(const std::chrono::milliseconds &waitTime, const std::string &triggerStr):
            _waitTime(waitTime), _triggerStr(triggerStr)
        {}
        ~TriggerTestThread()
        {
            if (_testThread)
            {
                _testThread->join();
                _testThread.reset();
            }
        }

        bool start(AsyncTestNotifier::Ptr notifyComplete)
        {
            bool started = false;
            if (!_testThread)
            {
                _notifyComplete = notifyComplete;
                _testThread.reset(new std::thread(std::bind(&TriggerTestThread::run, this)));

                started = _testThread != nullptr;
            }
            return started;
        }

    protected:
        void run()
        {
            try
            {
                std::this_thread::sleep_for(_waitTime);
                if (_notifyComplete)
                {
                    AsyncTestEvent *e(new AsyncTestEvent(_triggerStr));
                    if (e)
                    {
                        _notifyComplete->notify(e);
                    }
                }
            }
            catch (...)
            {
            }
        }
    private:
        std::chrono::milliseconds _waitTime;
        AsyncTestNotifier::Ptr _notifyComplete;
        std::string _triggerStr;

        typedef std::shared_ptr<std::thread> thread_ptr;
        thread_ptr _testThread;
};


TEST(AsyncNotifier_Tests, NotifyAsyncCondition_SUCCESS_simple_lock)
{
    std::mutex waitMutex;
    std::condition_variable waitCondition;

    typedef Iotivity::NotifyAsyncCondition<AsyncTestEvent, std::mutex, std::condition_variable>
    ConditionNotify;
    ConditionNotify::Ptr newCondition(new ConditionNotify(waitMutex, waitCondition));

    ASSERT_NE(newCondition, nullptr);

    TriggerTestThread trigger(std::chrono::milliseconds(500), "trigger1_wake");
    {
        bool waitResult;
        {
            std::unique_lock<std::mutex> lock(waitMutex);
            ASSERT_TRUE(trigger.start(newCondition));

            waitResult = waitCondition.wait_for(lock,
                                                std::chrono::milliseconds(20000)) != std::cv_status::timeout;
        }
        EXPECT_TRUE(waitResult);
        if (waitResult)
        {
            AsyncTestEvent *e = newCondition->acceptNotification();
            EXPECT_NE(e, nullptr);
            if (e)
            {
                EXPECT_EQ(e->str(), "trigger1_wake");

                newCondition->deleteNotification(e);
            }
        }
    }
    newCondition->detachOwner();
}

TEST(AsyncNotifier_Tests, NotifyAsyncCondition_SUCCESS_recursive_lock)
{
    std::recursive_mutex waitMutex;
    std::condition_variable_any waitCondition;

    typedef Iotivity::NotifyAsyncCondition<AsyncTestEvent, std::recursive_mutex,
            std::condition_variable_any> ConditionNotify;
    ConditionNotify::Ptr newCondition(new ConditionNotify(waitMutex, waitCondition));

    ASSERT_NE(newCondition, nullptr);

    TriggerTestThread trigger(std::chrono::milliseconds(500), "trigger3_wake");
    {
        bool waitResult;
        std::unique_lock<std::recursive_mutex> lock(waitMutex);
        ASSERT_TRUE(trigger.start(newCondition));

        waitResult = waitCondition.wait_for(lock,
                                            std::chrono::milliseconds(20000)) != std::cv_status::timeout;
        EXPECT_TRUE(waitResult);
        if (waitResult)
        {
            AsyncTestEvent *e = newCondition->acceptNotification();
            EXPECT_NE(e, nullptr);
            if (e)
            {
                EXPECT_EQ(e->str(), "trigger3_wake");

                newCondition->deleteNotification(e);
            }
        }
    }
    newCondition->detachOwner();
}


TEST(AsyncNotifier_Tests, NotifyAsyncCondition_TIMEOUT)
{
    std::mutex waitMutex;
    std::condition_variable waitCondition;

    typedef Iotivity::NotifyAsyncCondition<AsyncTestEvent, std::mutex, std::condition_variable>
    ConditionNotify;
    ConditionNotify::Ptr newCondition(new ConditionNotify(waitMutex, waitCondition));

    ASSERT_NE(newCondition, nullptr);

    TriggerTestThread trigger(std::chrono::milliseconds(2000), "trigger2_wake");
    {
        bool waitResult;
        {
            std::unique_lock<std::mutex> lock(waitMutex);
            ASSERT_TRUE(trigger.start(newCondition));

            waitResult = waitCondition.wait_for(lock,
                                                std::chrono::milliseconds(100)) != std::cv_status::timeout;
        }
        EXPECT_FALSE(waitResult);
        if (waitResult)
        {
            AsyncTestEvent *e = newCondition->acceptNotification();
            EXPECT_NE(e, nullptr);
            if (e)
            {
                EXPECT_EQ(e->str(), "trigger2_wake");

                newCondition->deleteNotification(e);
            }
        }
    }
    newCondition->detachOwner();
}


TEST(AsyncNotifier_Tests, NotifyAsyncFunc)
{
    struct NotifierTestEvent
    {
            NotifierTestEvent(bool testThrow): m_testThrow(testThrow) {}
            ~NotifierTestEvent() { ++destructorCallCounter(); }

            void incrementUseCount()
            {
                if (m_testThrow) throw std::runtime_error("TEST");
                ++useCallCounter();
            }

            static size_t useCount() { return useCallCounter(); }
            static size_t destructorCount() { return destructorCallCounter(); }
        private:
            static size_t &destructorCallCounter() { static size_t s_counter = 0; return s_counter; }
            static size_t &useCallCounter() { static size_t s_counter = 0; return s_counter; }
            bool m_testThrow;
    };

    auto testCallback = [](NotifierTestEvent & e) { e.incrementUseCount(); };
    typedef Iotivity::NotifyAsyncFunc<NotifierTestEvent, decltype(testCallback)> FuncNotify;

    EXPECT_EQ(NotifierTestEvent::useCount(), 0UL);
    EXPECT_EQ(NotifierTestEvent::destructorCount(), 0UL);

    FuncNotify::Ptr newCondition(new FuncNotify(testCallback));
    ASSERT_NE(newCondition, nullptr);

    NotifierTestEvent *testEventNoThrow(new NotifierTestEvent(false));
    ASSERT_NE(testEventNoThrow, nullptr);

    newCondition->notify(testEventNoThrow);

    EXPECT_EQ(NotifierTestEvent::useCount(), 1UL);
    EXPECT_EQ(NotifierTestEvent::destructorCount(), 1UL);

    NotifierTestEvent *testEventThrow(new NotifierTestEvent(true));
    ASSERT_NE(testEventThrow, nullptr);

    EXPECT_THROW(newCondition->notify(testEventThrow), std::runtime_error);

    EXPECT_EQ(NotifierTestEvent::useCount(), 1UL);
    EXPECT_EQ(NotifierTestEvent::destructorCount(), 2UL);
}


TEST(SyncNotifier_Tests, NotifySyncFunc)
{
    struct NotifierTestEvent
    {
            NotifierTestEvent(bool testThrow): m_testThrow(testThrow) {}
            ~NotifierTestEvent() { ++destructorCallCounter(); }

            void incrementUseCount()
            {
                if (m_testThrow) throw std::runtime_error("TEST");
                ++useCallCounter();
            }

            static size_t useCount() { return useCallCounter(); }
            static size_t destructorCount() { return destructorCallCounter(); }
        private:
            static size_t &destructorCallCounter() { static size_t s_counter = 0; return s_counter; }
            static size_t &useCallCounter() { static size_t s_counter = 0; return s_counter; }
            bool m_testThrow;
    };

    auto testCallback = [](NotifierTestEvent & e) { e.incrementUseCount(); };
    typedef Iotivity::NotifySyncFunc<NotifierTestEvent, decltype(testCallback)> FuncNotify;

    EXPECT_EQ(NotifierTestEvent::useCount(), 0UL);
    EXPECT_EQ(NotifierTestEvent::destructorCount(), 0UL);

    FuncNotify::Ptr newCondition(new FuncNotify(testCallback));
    ASSERT_NE(newCondition, nullptr);

    {
        NotifierTestEvent testEventNoThrow(false);

        newCondition->notify(testEventNoThrow);
    }

    EXPECT_EQ(NotifierTestEvent::useCount(), 1UL);
    EXPECT_EQ(NotifierTestEvent::destructorCount(), 1UL);

    {
        NotifierTestEvent testEventThrow(true);

        EXPECT_THROW(newCondition->notify(testEventThrow), std::runtime_error);
    }

    EXPECT_EQ(NotifierTestEvent::useCount(), 1UL);
    EXPECT_EQ(NotifierTestEvent::destructorCount(), 2UL);
}




TEST(SyncNotifier_Tests, SyncEvent)
{
    struct EventType
    {
        EventType(int eventData): m_eventData(eventData) {}
        int m_eventData;
    };

    struct SyncEventProvider
    {
            SyncEventProvider(): m_mutex(), m_event(m_mutex) {}
            SyncEvent<EventType> &event() { return m_event; }

            void testSignal(int val)
            {
                EventType e(val);
                m_event.fire(e);
            }

        private:
            std::recursive_mutex m_mutex;
            SyncEvent<EventType> m_event;
    } testProvider;

    int grabbedVal1 = 0, grabbedVal2 = 0;
    auto testCallback1 = [&grabbedVal1](EventType & e) { grabbedVal1 = e.m_eventData; };
    typedef Iotivity::NotifySyncFunc<EventType, decltype(testCallback1)> FuncNotify1;

    auto testCallback2 = [&grabbedVal2](EventType & e) { grabbedVal2 = e.m_eventData; };
    typedef Iotivity::NotifySyncFunc<EventType, decltype(testCallback2)> FuncNotify2;

    auto func1 = make_shared<FuncNotify1>(testCallback1);
    auto func2 = make_shared<FuncNotify2>(testCallback2);

    testProvider.event() += func1;
    testProvider.event() += func2;

    EXPECT_EQ(grabbedVal1, 0);
    EXPECT_EQ(grabbedVal2, 0);

    testProvider.testSignal(43);

    EXPECT_EQ(grabbedVal1, 43);
    EXPECT_EQ(grabbedVal2, 43);

    testProvider.event() -= func2;

    testProvider.testSignal(41);

    EXPECT_EQ(grabbedVal1, 41);
    EXPECT_EQ(grabbedVal2, 43);
}


TEST(SyncNotifier_Tests, OneShot_SyncEvent)
{
    struct EventType
    {
        EventType(int eventData): m_eventData(eventData) {}
        int m_eventData;
    };

    struct SyncEventProvider
    {
            SyncEventProvider(): m_mutex(), m_event(m_mutex) {}
            SyncEvent<EventType> &event() { return m_event; }

            void testSignal(int val)
            {
                EventType e(val);
                m_event.fire(e);
            }

        private:
            std::recursive_mutex m_mutex;
            OneShotSyncEvent<EventType> m_event;
    } testProvider;

    int grabbedVal1 = 0;
    auto testCallback1 = [&grabbedVal1](EventType & e) { grabbedVal1 = e.m_eventData; };
    typedef Iotivity::NotifySyncFunc<EventType, decltype(testCallback1)> FuncNotify1;

    auto func1 = make_shared<FuncNotify1>(testCallback1);

    testProvider.event() += func1;

    EXPECT_EQ(grabbedVal1, 0);

    testProvider.testSignal(41);

    EXPECT_EQ(grabbedVal1, 41);

    testProvider.testSignal(45);

    EXPECT_EQ(grabbedVal1, 41);

}