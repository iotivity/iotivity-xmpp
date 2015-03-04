//******************************************************************
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
//******************************************************************
// File name:
//     stcqueue.h
//
// Description:
//
//
//*********************************************************************


/// @file stcqueue.h


#pragma once

#include <stdint.h>
#include <list>
#include <condition_variable>

namespace Iotivity
{
    /// @brief Defines a simple thread-safe queue mechanism which may be used to
    ///        wake when items are pushed into the queue.
    template <typename _ItemType> class Queue
    {
        public:
            Queue() : m_isClosed(false) { }

            ~Queue()
            {
                close();

                {
                    std::lock_guard<std::recursive_mutex> synchronize(m_mutex);
                    m_list.clear();
                }
            }

            void close()
            {
                {
                    std::lock_guard<std::recursive_mutex> synchronize(m_mutex);
                    m_isClosed = true;
                }
                m_wake.notify_all();
            }

            bool isClosed()
            {
                return m_isClosed;
            }

            bool empty()
            {
                std::lock_guard<std::recursive_mutex> synchronize(m_mutex);
                return m_list.empty();
            }

            size_t size()
            {
                std::lock_guard<std::recursive_mutex> synchronize(m_mutex);
                return m_list.size();
            }

            void push(const _ItemType &item)
            {
                if (!m_isClosed)
                {
                    {
                        std::lock_guard<std::recursive_mutex> synchronize(m_mutex);
                        m_list.push_back(item);
                    }
                    m_wake.notify_all();
                }
            }

            bool pop(const std::chrono::milliseconds &timeout, _ItemType &itemOut)
            {
                std::unique_lock<std::recursive_mutex> synchronize(m_mutex);
                while (m_list.empty())
                {
                    if (m_isClosed)
                    {
                        return false;
                    }

                    if (m_wake.wait_for(synchronize, timeout) == std::cv_status::timeout)
                    {
                        return false;
                    }
                }

                itemOut = m_list.front();
                m_list.pop_front();
                return true;
            }

        private:
            bool m_isClosed;
            std::recursive_mutex m_mutex;
            std::condition_variable_any m_wake;
            std::list<_ItemType> m_list;
    };

}
