///////////////////////////////////////////////////////////////////////////////
//
// Copyright 2010-2015 Intel Mobile Communications GmbH All Rights Reserved.
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

/// @file async_notify.h

#pragma once

#include <memory>
#include <list>
#include <set>
#include <mutex>

namespace Iotivity
{
    /// NotifySyncBase is the abstract base of a group of synchronous notification
    /// templates which provide various mechanisms for notifying an object/thread that
    /// a particular state change has occurred. These are generally designed to be
    /// one-shot synchronous callbacks, although they are not specifically restricted to
    /// function this way. A consumer of the notification object should use a pointer
    /// (or shared_ptr) to the NotifySyncBase class so that the caller can choose the
    /// notification flavor it wishes to use.
    template <typename _ObservableT>
    class NotifySyncBase
    {
        public:
            typedef std::shared_ptr<NotifySyncBase<_ObservableT> > Ptr;

            struct AutoDetachOwner
            {
                    AutoDetachOwner(Ptr &notifyObject): m_notifyObject(notifyObject) {}
                    ~AutoDetachOwner() { if (m_notifyObject) m_notifyObject->detachOwner(); }
                private:
                    Ptr m_notifyObject;
            };
            typedef std::list<AutoDetachOwner> AutoDetachList;

        public:

            NotifySyncBase(): m_ownerValid(true) {}
            virtual ~NotifySyncBase() {}

            /// Notify returns true iff the remote side was notified.
            // NOTE: This member function should be pure virtual, however there is a bug in g++
            //        reported in 4.7.0 but not fixed as of the targeted build environment
            //        which causes an error using a derived type with a template parameter
            //        from a local type. See:
            //
            //        https://gcc.gnu.org/bugzilla/show_bug.cgi?id=51048
            //
            virtual bool            notify(_ObservableT &) { return false; }

            /// An object which constructs a NotifySyncBase-derived notification object is
            /// considered the owner of the notification, whereas the recipient of the
            /// NotifySyncBase instance should be considered the owner of the NotifySyncBase
            /// object itself. This call must be made by the owner of the notification (not the
            /// NotifySyncBase) prior to its own destruction so that the notifier does not attempt
            /// to notify a non-existent object instance.
            virtual void            detachOwner() = 0;

        protected:
            std::recursive_mutex             m_ownerAccessCS;
            bool                             m_ownerValid;
    };

    /// NotifySyncBase-derived notifier which calls a static function with a
    /// reference parameter when the instance's notify function is called.
    template <typename _ObservableT>
    class NotifySyncStatic : public NotifySyncBase<_ObservableT>
    {
        public:
            typedef std::shared_ptr<NotifySyncStatic<_ObservableT> > Ptr;

            // The caller takes ownership of the notification object through this
            // static callback.
            typedef void (*NotifyMemberFunc)(_ObservableT &notification, void *param);

            NotifySyncStatic(NotifyMemberFunc notifyFunc, void *param = 0):
                m_notifyFunc(notifyFunc), m_param(param) {}

            virtual bool notify(_ObservableT &notification) override
            {
                bool notified = false;
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                if (this->m_ownerValid && m_notifyFunc)
                {
                    m_notifyFunc(notification, m_param);
                    notified = true;
                }
                return notified;
            }

            virtual void detachOwner() override
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                this->m_ownerValid = false;
                m_param = 0;
            }
        private:
            NotifyMemberFunc        m_notifyFunc;
            void                   *m_param;
    };


    /// NotifyAsyncBase-derived notifier which calls a functor with a
    /// pointer parameter when the instance's notify function is called. The
    /// functor implementation is responsible for deleting the notification data object.
    /// The functor's signature should match the following:
    /// void (*)(_ObservableT &notification)
    template <typename _ObservableT, typename _FuncT>
    class NotifySyncFunc : public NotifySyncBase<_ObservableT>
    {
        public:
            typedef std::shared_ptr<NotifySyncFunc<_ObservableT, _FuncT> > Ptr;

            NotifySyncFunc(_FuncT notifyFunc): m_notifyFunc(notifyFunc) {}

            virtual bool notify(_ObservableT &notification) override
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                (m_notifyFunc)(notification);
                return true;
            }

            virtual void detachOwner() override
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                this->m_ownerValid = false;
            }
        private:
            _FuncT m_notifyFunc;
    };


    /// NotifySyncBase-derived notifier which calls an object member function with a
    /// pointer parameter when the instance's notify function is called. The member
    /// function is responsible for deleting the notification data object.
    template <typename _ObservableT, typename _OwnerT>
    class NotifySyncMember : public NotifySyncBase<_ObservableT>
    {
        public:
            typedef std::shared_ptr<NotifySyncMember<_ObservableT, _OwnerT> > Ptr;

            // The caller takes ownership of the notification object through this
            // callback.
            typedef void (_OwnerT::*NotifyMemberFunc)(_ObservableT &notification);

            NotifySyncMember(_OwnerT &owner, NotifyMemberFunc notifyFunc):
                m_owner(owner), m_notifyFunc(notifyFunc) {}

            virtual bool notify(_ObservableT &notification) override
            {
                bool notified = false;
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                if (this->m_ownerValid && m_notifyFunc)
                {
                    (m_owner.*m_notifyFunc)(notification);
                    notified = true;
                }
                return notified;
            }

            virtual void detachOwner() override
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                this->m_ownerValid = false;
            }
        private:
            NotifyMemberFunc        m_notifyFunc;
            _OwnerT                &m_owner;
    };

    /// Helper class for the NotifySyncMember synchronous notifier which provides automatic
    /// construction and cleanup of the synchronous notifier. This object can be used in place
    /// of the NotifySyncMember pointer as it contains an implicit cast to the pointer type.
    template <typename _ObservableT, typename _OwnerT>
    class SyncObserver
    {
        public:
            typedef NotifySyncMember<_ObservableT, SyncObserver> notifier_type;
            typedef std::shared_ptr<notifier_type> notifier_type_ptr;
            typedef void (_OwnerT::*member_func)(_ObservableT &notification);

            SyncObserver(_OwnerT &owner, member_func callback):
                m_owner(owner), m_callback(callback)
            {
                m_notifier.reset(new notifier_type(*this, &SyncObserver::handleNotification));
            }

            SyncObserver(_OwnerT &owner): m_owner(owner), m_callback(0)
            {
                m_notifier.reset(new notifier_type(*this, &SyncObserver::handleNotification));
            }

            void assignCallback(member_func callback) { m_callback = callback; }

            virtual ~SyncObserver()
            {
                detach();
            }

            operator std::shared_ptr<NotifySyncBase<_ObservableT> >() const { return m_notifier; }

            void detach()
            {
                if (m_notifier)
                {
                    m_notifier->detachOwner();
                }
            }

        protected:
            __inline void handleNotification(_ObservableT &notification)
            {
                if (m_callback) (m_owner.*m_callback)(notification);
            }
        private:
            SyncObserver(const SyncObserver &);
            SyncObserver  &operator=(const SyncObserver &);
        private:
            _OwnerT &m_owner;
            member_func m_callback;
            notifier_type_ptr m_notifier;
    };

    template <typename _ObservableT, typename _MutexT = std::recursive_mutex>
    struct SyncEvent
    {
            typedef typename NotifySyncBase<_ObservableT>::Ptr notifier_type;

            SyncEvent() = delete;
            SyncEvent(_MutexT &mutex): m_mutex(mutex) {}
            SyncEvent(const SyncEvent &) = delete;
            ~SyncEvent()
            {
                std::lock_guard<_MutexT> lock(m_mutex);
                for (auto i = m_notifiers.begin(); i != m_notifiers.end(); ++i)
                {
                    (*i)->detachOwner();
                }

            }

            size_t notifierCount() const
            {
                std::lock_guard<_MutexT> lock(m_mutex);
                return m_notifiers.size();
            }

            SyncEvent &operator=(const SyncEvent &) = delete;

            SyncEvent &operator+=(notifier_type notifier)
            {
                if (notifier)
                {
                    std::lock_guard<_MutexT> lock(m_mutex);
                    m_notifiers.insert(notifier);
                }
                return *this;
            }

            SyncEvent &operator-=(notifier_type notifier)
            {
                if (notifier)
                {
                    std::lock_guard<_MutexT> lock(m_mutex);
                    m_notifiers.erase(notifier);
                }
                return *this;
            }

            void fire(_ObservableT &&e)
            {
                // This cast to an lvalue is implicit (it has already happened), but so this doesn't
                // look like we're making a recursive call, it's being written out explicitly.
                fire(static_cast<_ObservableT &>(e));
            }

            void fire(_ObservableT &e)
            {
                sendNotification(e);
            }

        protected:
            virtual void sendNotification(_ObservableT &e)
            {
                std::set<notifier_type> callbacks;
                {
                    std::lock_guard<_MutexT> lock(m_mutex);
                    callbacks = m_notifiers;
                }
                for (auto i = callbacks.begin(); i != callbacks.end(); ++i)
                {
                    (*i)->notify(e);
                }
            }

        protected:
            _MutexT &mutex() { return m_mutex; }

        private:
            _MutexT &m_mutex;
            std::set<notifier_type> m_notifiers;
    };


    /// @brief A SyncEvent which is guaranteed to only make one callback to signal the current
    ///        state of a one-shot signal.
    template <typename _ObservableT, typename _MutexT = std::recursive_mutex>
    struct OneShotSyncEvent: public SyncEvent<_ObservableT, _MutexT>
    {
            OneShotSyncEvent() = delete;
            OneShotSyncEvent(_MutexT &mutex):
                SyncEvent<_ObservableT, _MutexT>(mutex), m_signalCount(0) {}
            OneShotSyncEvent(const OneShotSyncEvent &) = delete;

            OneShotSyncEvent &operator=(const OneShotSyncEvent &) = delete;

        protected:
            virtual void sendNotification(_ObservableT &e)
            {
                int currentCount;
                {
                    std::lock_guard<_MutexT> lock(this->mutex());
                    currentCount = ++m_signalCount;
                }

                if (currentCount <= 1)
                {
                    this->SyncEvent<_ObservableT, _MutexT>::sendNotification(e);
                }
            }

        private:
            unsigned int m_signalCount;
    };

}





