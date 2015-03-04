//******************************************************************
//
// Copyright 2007-2014 Intel Mobile Communications GmbH All Rights Reserved.
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
//     compatibility.cpp
//
// Description:
//     Implementation for IoTivity Common_Library cross-platform compatibility.
//
//
//
//*********************************************************************

#include "stdafx.h"

#include "compatibility.h"
#ifndef __KLOCWORK__
# include "banned.h"
#endif

#if defined(_WIN32)
CRITICAL_SECTION *g_debugMsgCS = 0;
void releaseDebugMsgCS(void)
{
    if (g_debugMsgCS)
    {
        DeleteCriticalSection(g_debugMsgCS);
        free(g_debugMsgCS);
        g_debugMsgCS = 0;
    }
}
void requireDebugMsgCS(void)
{
    if (!g_debugMsgCS)
    {
        g_debugMsgCS = (CRITICAL_SECTION *)malloc(sizeof(CRITICAL_SECTION));
        if (g_debugMsgCS)
        {
            InitializeCriticalSectionEx(g_debugMsgCS, 4000, 0);

            EnterCriticalSection(g_debugMsgCS);
            atexit(releaseDebugMsgCS);
            LeaveCriticalSection(g_debugMsgCS);
        }
    }
}


#ifdef __cplusplus
InterlockLockDebugMsg::InterlockLockDebugMsg()
{
    requireDebugMsgCS();
    if (g_debugMsgCS)
    {
        ::EnterCriticalSection(g_debugMsgCS);
    }
}
InterlockLockDebugMsg::~InterlockLockDebugMsg()
{
    if (g_debugMsgCS)
    {
        ::LeaveCriticalSection(g_debugMsgCS);
    }
}
#endif
#endif

void swap_byte_array(void *vec, const size_t bytes)
{
    for (size_t i = 0; i < (bytes >> 1); ++i)
    {
        uint8_t tmp = ((uint8_t *)vec)[i];
        ((uint8_t *)vec)[i] = ((uint8_t *)vec)[bytes - i - 1];
        ((uint8_t *)vec)[bytes - i - 1] = tmp;
    }
}
