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
    /// NotifyDeleteProvider gives an extensible object type which can be assigned to
    /// a NotifyAsyncBase-derviced notification object to allow the recipient to
    /// assign the method for deleting (or recovering) the notification data object.
    template <typename _ObservableT>
    class NotifyDeleteProvider
    {
        public:
            typedef std::shared_ptr<NotifyDeleteProvider> Ptr;

            virtual void deleteNotification(_ObservableT *notification)
            {
                if (notification)
                {
                    delete notification;
                }
            }
    };

    template <typename _SignalT> struct SignalWaitObject
    {
        void operator()(_SignalT &signal) {}
    };


    /// NotifyAsyncBase is the abstract base of a group of asynchronous notification
    /// templates which provide various mechanisms for notifying an object/thread that
    /// a particular state change has occurred. These are generally designed to be
    /// one-shot asynchronous events, although they are not specifically restricted to
    /// function this way. A consumer of the notification object should use a pointer
    /// (or shared_ptr) to the NotifyAsyncBase class so that the caller can choose the
    /// notification flavor it wishes to use.
    template <typename _ObservableT,
              typename _DeleteProviderT = NotifyDeleteProvider<_ObservableT> >
    class NotifyAsyncBase
    {
        public:
            typedef std::shared_ptr<NotifyAsyncBase<_ObservableT, _DeleteProviderT> > Ptr;

            struct AutoDetachOwner
            {
                    AutoDetachOwner(Ptr &notifyObject): m_notifyObject(notifyObject) {}
                    ~AutoDetachOwner() { if (m_notifyObject) m_notifyObject->detachOwner(); }
                private:
                    Ptr m_notifyObject;
            };
            typedef std::list<AutoDetachOwner> AutoDetachList;

            typedef _ObservableT event_type;

        public:

            NotifyAsyncBase(): m_ownerValid(true), m_deleteProvider(new _DeleteProviderT) {}
            virtual ~NotifyAsyncBase() {}

            /// The notification call ALWAYS takes ownership of the notification object.
            /// Notify returns true iff the remote side was notified.

            // NOTE: This member function should be pure virtual, however there is a bug in g++
            //        reported in 4.7.0 but not fixed as of the targeted build environment
            //        which causes an error using a derived type with a template parameter
            //        from a local type. See:
            //
            //        https://gcc.gnu.org/bugzilla/show_bug.cgi?id=51048
            //
            virtual bool notify(_ObservableT *) { return false; }

            /// An object which constructs a NotifyAsyncBase-derived notification object is
            /// considered the owner of the notification, whereas the recipient of the
            /// NotifyAsyncBase instance should be considered the owner of the NotifyAsyncBase
            /// object itself. This call must be made by the owner of the notification (not the
            /// NotifyAsyncBase) prior to its own destruction so that the notifier does not
            /// attempt to notify a non-existent object instance.
            virtual void detachOwner() = 0;


            // Should always be called by the consumer of a notification to free up the
            // notification object. The actual behavior of the deleteNotification is undefined
            // (it may not delete a real object), but the notified party must not use the
            // notification object after calling deleteNotification.
            virtual void deleteNotification(_ObservableT *notification)
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                if (this->m_deleteProvider)
                {
                    this->m_deleteProvider->deleteNotification(notification);
                }
            }

            // Assigns the delete provider which is used to delete notification objects
            // received on the async notifier. This should only be called by the generator
            // of the notification object in order to select a new method for deleting the object.
            virtual void assignDeleteProvider(typename _DeleteProviderT::Ptr deleteProvider)
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                this->m_deleteProvider = deleteProvider;
            }
        protected:
            std::recursive_mutex             m_ownerAccessCS;
            bool                             m_ownerValid;
            typename _DeleteProviderT::Ptr   m_deleteProvider;
    };

    /// NotifyAsyncBase-derived notifier that triggers an auto-reset event when the notification
    /// occurs. It is the responsibility of the notified party to then read the notification
    /// from the NotifyAsyncEvent instance and delete it.
    template <typename _ObservableT, typename _WaitObjectT,
              typename _SignalT = SignalWaitObject<_WaitObjectT>,
              typename _DeleteProviderT = NotifyDeleteProvider<_ObservableT> >
    class NotifyAsyncEvent : public NotifyAsyncBase<_ObservableT, _DeleteProviderT>
    {
        public:
            typedef std::shared_ptr<NotifyAsyncEvent<_ObservableT, _WaitObjectT, _SignalT,
                    _DeleteProviderT> >
                    Ptr;

            NotifyAsyncEvent(_WaitObjectT &waitObject):
                m_waitObject(waitObject), m_notification(0)
            {}
            virtual ~NotifyAsyncEvent() { this->deleteNotification(m_notification); }

            virtual bool notify(_ObservableT *notification) override
            {
                bool notified = false;
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                if (m_notification)
                {
                    this->deleteNotification(m_notification);
                    m_notification = 0;
                }
                // The reference to the _waitObject is dead if m_ownerValid is false.
                if (this->m_ownerValid)
                {
                    m_notification = notification;
                    _SignalT signalCall;
                    signalCall(m_waitObject);
                    notified = true;
                }
                else
                {
                    this->deleteNotification(notification);
                }
                return notified;
            }

            virtual void detachOwner() override
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                this->m_ownerValid = false;
                _ObservableT *notification = m_notification;
                if (notification)
                {
                    m_notification = 0;
                    this->deleteNotification(notification);
                }
            }

            _ObservableT *acceptNotification()
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                _ObservableT *notification = 0;
                notification = m_notification;
                m_notification = 0;
                return notification;
            }

            typename _DeleteProviderT::Ptr deleteProvider() const
            {
                return this->m_deleteProvider;
            }
        private:
            _WaitObjectT           &m_waitObject;
            _ObservableT           *m_notification;
    };


    template <typename _WaitObjectT, typename _ConditionObjectT> struct SignalCondition
    {
        void operator()(_WaitObjectT &wait, _ConditionObjectT &condition)
        {
            condition.notify_all();
        }
    };

    template <> struct SignalCondition<std::mutex, std::condition_variable>
    {
        void operator()(std::mutex &, std::condition_variable &c)
        {
            c.notify_all();
        }
    };

    template <> struct SignalCondition<std::recursive_mutex, std::condition_variable_any>
    {
        void operator()(std::recursive_mutex &, std::condition_variable_any &c)
        {
            c.notify_all();
        }
    };

    template <typename _WaitObjectT> struct LockGuard
    {
        LockGuard(_WaitObjectT &) {}
    };

    template <> struct LockGuard<std::mutex>
    {
            LockGuard(std::mutex &waitObject) : m_guard(waitObject) {}
        private:
            std::lock_guard<std::mutex> m_guard;
    };

    template <> struct LockGuard<std::recursive_mutex>
    {
            LockGuard(std::recursive_mutex &waitObject): m_guard(waitObject) {}
        private:
            std::lock_guard<std::recursive_mutex> m_guard;
    };


    template <typename _ObservableT, typename _WaitObjectT, typename _ConditionObjectT,
              typename _SignalT = SignalCondition<_WaitObjectT, _ConditionObjectT>,
              typename _LockGuardT = LockGuard<_WaitObjectT>,
              typename _DeleteProviderT = NotifyDeleteProvider<_ObservableT> >
    class NotifyAsyncCondition: public NotifyAsyncBase<_ObservableT, _DeleteProviderT>
    {
        public:
            typedef std::shared_ptr<NotifyAsyncCondition<_ObservableT, _WaitObjectT,
                    _ConditionObjectT, _SignalT, _LockGuardT, _DeleteProviderT> >
                    Ptr;

            NotifyAsyncCondition(_WaitObjectT &waitObject, _ConditionObjectT &conditionObject):
                m_waitObject(waitObject), m_conditionObject(conditionObject),
                m_notification(0)
            {}
            virtual ~NotifyAsyncCondition() { this->deleteNotification(m_notification); }

            virtual bool notify(_ObservableT *notification) override
            {
                bool notified = false;
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                {
                    if (this->m_ownerValid)
                    {
                        _LockGuardT guard(m_waitObject);
                        if (m_notification)
                        {
                            this->deleteNotification(m_notification);
                            m_notification = 0;
                        }
                    }
                }
                // The reference to the _waitObject is dead if m_ownerValid is false.
                if (this->m_ownerValid)
                {
                    {
                        _LockGuardT guard(m_waitObject);
                        m_notification = notification;
                    }
                    _SignalT signalCall;
                    signalCall(m_waitObject, m_conditionObject);
                    notified = true;
                }
                else
                {
                    this->deleteNotification(notification);
                }
                return notified;
            }

            virtual void detachOwner() override
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                this->m_ownerValid = false;
                {
                    _LockGuardT guard(m_waitObject);
                    _ObservableT *notification = m_notification;
                    if (notification)
                    {
                        m_notification = 0;
                        this->deleteNotification(notification);
                    }
                }
            }

            _ObservableT *acceptNotification()
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                _LockGuardT guard(m_waitObject);

                _ObservableT *notification = 0;
                notification = m_notification;
                m_notification = 0;
                return notification;
            }

            typename _DeleteProviderT::Ptr deleteProvider() const
            {
                return this->m_deleteProvider;
            }
        private:
            _WaitObjectT              &m_waitObject;
            _ConditionObjectT         &m_conditionObject;
            _ObservableT              *m_notification;
    };

    /// NotifyAsyncBase-derived notifier which calls a functor with a
    /// pointer parameter when the instance's notify function is called. The
    /// functor implementation is responsible for deleting the notification data object.
    /// The functor's signature should match the following:
    /// void (*)(_ObservableT &notification)
    template <typename _ObservableT, typename _FuncT,
              typename _DeleteProviderT = NotifyDeleteProvider<_ObservableT> >
    class NotifyAsyncFunc : public NotifyAsyncBase<_ObservableT, _DeleteProviderT>
    {
        protected:
            template <typename F> struct Delete
            {
                    Delete(F func): m_func(func) {}
                    ~Delete() { m_func(); }
                private:
                    F m_func;
            };

        public:
            NotifyAsyncFunc(_FuncT notifyFunc): m_notifyFunc(notifyFunc) {}

            virtual bool notify(_ObservableT *notification) override
            {
                bool notified = false;
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                if (notification)
                {
                    auto deleteFunc = [this, &notification]()
                    { this->deleteNotification(notification); };
                    Delete<decltype(deleteFunc)> cleanup(deleteFunc);

                    if (this->m_ownerValid)
                    {
                        this->m_notifyFunc(*notification);
                        notified = true;
                    }
                }
                return notified;
            }

            virtual void detachOwner() override
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                this->m_ownerValid = false;
            }
        private:
            _FuncT m_notifyFunc;
    };


    /// NotifyAsyncBase-derived notifier which calls a static function with a
    /// pointer parameter when the instance's notify function is called. The
    /// static function is responsible for deleting the notification data object.
    template <typename _ObservableT,
              typename _DeleteProviderT = NotifyDeleteProvider<_ObservableT> >
    class NotifyAsyncStatic : public NotifyAsyncBase<_ObservableT, _DeleteProviderT>
    {
        public:
            typedef std::shared_ptr<NotifyAsyncStatic<_ObservableT, _DeleteProviderT> > Ptr;

            // The caller takes ownership of the notification object through this
            // static callback.
            typedef void (*NotifyMemberFunc)(_ObservableT *notification,
                                             NotifyAsyncStatic &asyncNotify, void *param);

            NotifyAsyncStatic(NotifyMemberFunc notifyFunc, void *param = 0):
                m_notifyFunc(notifyFunc), m_param(param) {}

            virtual bool notify(_ObservableT *notification) override
            {
                bool notified = false;
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                if (this->m_ownerValid && m_notifyFunc)
                {
                    m_notifyFunc(notification, *this, m_param);
                    notified = true;
                }
                else
                {
                    this->deleteNotification(notification);
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

    /// NotifyAsyncBase-derived notifier which calls an object member function with a
    /// pointer parameter when the instance's notify function is called. The member
    /// function is responsible for deleting the notification data object.
    template <typename _ObservableT, typename _OwnerT,
              typename _DeleteProviderT = NotifyDeleteProvider<_ObservableT> >
    class NotifyAsyncMember : public NotifyAsyncBase<_ObservableT, _DeleteProviderT>
    {
        public:
            typedef std::shared_ptr<NotifyAsyncMember<_ObservableT, _OwnerT,
                    _DeleteProviderT> > Ptr;

            // The caller takes ownership of the notification object through this
            // callback.
            typedef void (_OwnerT::*NotifyMemberFunc)(_ObservableT *notification);

            NotifyAsyncMember(_OwnerT &owner, NotifyMemberFunc notifyFunc):
                m_notifyFunc(notifyFunc), m_owner(owner) {}

            virtual bool notify(_ObservableT *notification) override
            {
                bool notified = false;
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                if (this->m_ownerValid && m_notifyFunc)
                {
                    (m_owner.*m_notifyFunc)(notification);
                    notified = true;
                }
                else
                {
                    this->deleteNotification(notification);
                }
                return notified;
            }

            virtual void detachOwner() override
            {
                std::lock_guard<std::recursive_mutex> lock(this->m_ownerAccessCS);
                this->m_ownerValid = false;
            }
        private:
#if defined(_WIN32)
            uint32_t                m_padding; // Added to avoid C4121 warning
#endif
            NotifyMemberFunc        m_notifyFunc;
            _OwnerT                &m_owner;
    };


    /// Helper class for the NotifyAsyncMember asynchronous notifier which provides automatic
    /// construction and cleanup of the asynchronous notifier and handles deletion of the
    /// notification object. This object can be used in place of the NotifyAsyncMember pointer
    /// as it contains an implicit cast to the pointer type.
    template <typename _ObservableT, typename _OwnerT>
    class AsyncObserver
    {
        public:
            typedef NotifyAsyncMember<_ObservableT, AsyncObserver> notifier_type;
            typedef std::shared_ptr<notifier_type> notifier_type_ptr;
            typedef void (_OwnerT::*member_func)(_ObservableT &notification);

            AsyncObserver(_OwnerT &owner, member_func callback):
                m_owner(owner), m_callback(callback),
                m_activeEvent(0), m_suppressCleanup(false)
            {
                m_notifier.reset(new notifier_type(*this, &AsyncObserver::handleNotification));
            }

            AsyncObserver(_OwnerT &owner):
                m_owner(owner), m_callback(0), m_activeEvent(0), m_suppressCleanup(false)
            {
                m_notifier.reset(new notifier_type(*this, &AsyncObserver::handleNotification));
            }

            void assignCallback(member_func callback) { m_callback = callback; }

            virtual ~AsyncObserver()
            {
                detach();
            }

            AsyncObserver &operator=(const AsyncObserver &) = delete;

            operator std::shared_ptr<NotifyAsyncBase<_ObservableT> >() const { return m_notifier; }

            void detach()
            {
                if (m_notifier)
                {
                    m_notifier->detachOwner();
                }
            }

            // Useful only for relaying a notification object to another notifier
            // of the same type. This call is only valid during the callback.
            // Calling it at any other time is undefined.
            _ObservableT *detachEventAndSuppressCleanup()
            {
                if (m_activeEvent)
                {
                    m_suppressCleanup = true;
                }
                return m_activeEvent;
            }

        protected:
            void handleNotification(_ObservableT *notification)
            {
                if (notification)
                {
                    if (m_callback)
                    {
                        try
                        {
                            m_activeEvent = notification;
                            (m_owner.*m_callback)(*notification);
                            m_activeEvent = 0;
                        }
                        catch (...)
                        {
                            m_activeEvent = 0;
                            if (m_notifier && !m_suppressCleanup)
                            {
                                m_notifier->deleteNotification(notification);
                            }
                            throw;
                        }
                    }
                    if (m_notifier && !m_suppressCleanup)
                    {
                        m_notifier->deleteNotification(notification);
                    }
                }
            }
        private:
            _OwnerT &m_owner;
            member_func m_callback;
            notifier_type_ptr m_notifier;
            _ObservableT *m_activeEvent;
            bool m_suppressCleanup;
    };

    /// Helper function which takes a set of notifiers and its synchronization object and
    /// calls the notify function on each notifier instance providing a newly created event object
    /// from the passed-in functor. Use this version with a mutual exclusion object.
    template <typename _ObservableT, typename _CreateEventFuncT, typename _MutexT>
    void fireAsyncNotify(const std::set<std::shared_ptr<NotifyAsyncBase<_ObservableT> > > &
                         eventSet, _MutexT &cs, _CreateEventFuncT createFunc)
    {
        // Note that the type is expanded fully (here and above) so that template type deduction
        // will work properly.
        typedef std::set<std::shared_ptr<NotifyAsyncBase<_ObservableT> > > ObservableSet;
        ObservableSet callSet;
        {
            std::lock_guard<_MutexT> lock(cs);
            callSet = eventSet;
        }
        for (typename ObservableSet::const_iterator i = callSet.begin(); i != callSet.end(); ++i)
        {
            _ObservableT *newT = createFunc();
            if (newT)
            {
                (*i)->notify(newT);
            }
        }
    }

    /// Helper function which takes a set of notifiers and calls the notify function on each
    /// notifier instance providing a newly created event object from the passed-in functor.
    /// Use this version when you do not require a mutual exclusion object on the collection.
    template <typename _ObservableT, typename _CreateEventFuncT>
    void fireAsyncNotify(const std::set<std::shared_ptr<NotifyAsyncBase<_ObservableT> > > &
                         eventSet, _CreateEventFuncT createFunc)
    {
        // Note that the type is expanded fully (here and above) so that template type deduction
        // will work properly.
        typedef std::set<std::shared_ptr<NotifyAsyncBase<_ObservableT> > > ObservableSet;
        for (typename ObservableSet::const_iterator i = eventSet.begin(); i != eventSet.end(); ++i)
        {
            _ObservableT *newT = createFunc();
            if (newT)
            {
                (*i)->notify(newT);
            }
        }
    }

    /// Trivial helper class to support the RAII pattern for notifier clases in a limited
    /// scope. Can be used in the following manner:
    ///
    /// auto bindNotifier = [...](...){... set_up_notifier_binding(); ...};
    /// auto unbindNotifier = [...](...){... tear_down_notifier_binding(); ...};
    /// NotifierBinding<decltype(bindNotifier), decltype(unbindNotifier)>
    ///                                                localBinding(bindNotifier, unbindNotifier);
    ///
    template <typename _BindFunc, typename _UnbindFunc> struct NotifierBinding
    {
            NotifierBinding(_BindFunc bind, _UnbindFunc unbind): m_unbind(unbind)
            {
                bind();
            }

            ~NotifierBinding()
            {
                m_unbind();
            }

        private:
            _UnbindFunc m_unbind;
    };

}





