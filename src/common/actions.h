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

/// @file actions.h

#pragma once

#include "../include/xmpp_feature_flags.h"
#include "../common/stcqueue.h"
#include <thread>
#include <map>

namespace Iotivity
{
    /// @brief Provides an interface for a simple function that may run a asynchronously
    ///        on an action-runner thread.
    ///
    /// @note This is functionally equivalent to a std::function implementation of the
    ///       same concept, but shaves quite a bit off the footprint of the code.
    template<typename Context> struct IAction
    {
        virtual void operator()(Context &) = 0;
    };

    /// @cond HIDDEN_SYMBOLS
    /// @brief Default Implementation of an IAction given a function or functor to call.
    template <typename Func, typename Context> struct ActionT: public IAction<Context>
    {
            ActionT(Func f): m_func(f) {}
            virtual void operator()(Context &c) override { m_func(c); }

        private:
            Func m_func;
    };
    /// @endcond

    /// @brief Simple thread queue which provides a means for running queued actions.
    ///        Functions similarly to an asio::io_service.
    ///
    /// @note May be replaced by an asio::io_service if it reduces the code footprint/
    template <typename QueueKey, typename ActionContext>
    class ActionRunner
    {
        public:
            typedef IAction<ActionContext> runner_action;
            typedef Queue<std::shared_ptr<runner_action>> runner_queue;

        public:
            ActionRunner(): m_mutex(), m_connectionThreads() {}
            ~ActionRunner()
            {
                // Derived destructors must also call shutdownThreads() if their threads
                // access the this pointer.
                try
                {
                    shutdown();
                }
                catch (...)
                {}
            }

            void shutdown()
            {
                std::unique_lock<std::recursive_mutex> lock(m_mutex);
                for (auto &i : m_connectionThreads)
                {
                    i.second.second->close();
                    if (i.second.first.joinable())
                    {
                        lock.unlock();
                        try
                        {
                            if (std::this_thread::get_id() == i.second.first.get_id())
                            {
                                i.second.first.detach();
                            }
                            else
                            {
                                i.second.first.join();
                            }
                        }
                        catch (...)
                        {}
                        lock.lock();
                    }
                }
                m_connectionThreads.clear();
            }

            // NOTE: This will work just as well using std::function<void(ActionContext &)>, but
            //       the code size increases significantly >2KB by doing so. On balance the
            //       time cost for constructing the shared_ptr wrapper object for the action
            //       is minimal.
            template <typename T> static std::shared_ptr<runner_action> make_action_from(T func)
            {
                return std::static_pointer_cast<runner_action>(
                           std::make_shared<ActionT<decltype(func), ActionContext>>(func));
            }

            std::shared_ptr<runner_queue> getQueue(const QueueKey &key)
            {
                std::lock_guard<std::recursive_mutex> lock(m_mutex);
                const auto f = m_connectionThreads.find(key);
                if (f == m_connectionThreads.end())
                {
                    std::shared_ptr<runner_queue> actionQueue = std::make_shared<runner_queue>();
                    m_connectionThreads[key] = make_pair(createActionThread(actionQueue, key),
                                                         actionQueue);
                    return actionQueue;
                }
                else
                {
                    return f->second.second;
                }
            }

            void closeQueue(const QueueKey &key)
            {
                std::lock_guard<std::recursive_mutex> lock(m_mutex);
                const auto f = m_connectionThreads.find(key);
                if (f != m_connectionThreads.end())
                {
                    f.second.second->close();
                    if (f.second.first.joinable())
                    {
                        f.second.first.join();
                    }
                }
            }

        protected:
            typedef std::map<QueueKey,
                    std::pair<std::thread,
                    std::shared_ptr<runner_queue>>> ConnectionThreads;

            virtual std::thread createActionThread(std::shared_ptr<runner_queue> queue,
                                                   QueueKey key) = 0;

        private:
            mutable std::recursive_mutex m_mutex;
            ConnectionThreads m_connectionThreads;
    };

}
