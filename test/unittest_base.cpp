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

/// @file unittest_base.cpp

#include "stdafx.h"
#include <gtest/gtest.h>

#include <common/logstream.h>
#include "xmpp_connect_config.h"

#include <random>

using namespace testing;
using namespace std;

char getRandomChar(char range = 26)
{
    random_device rd;
    mt19937 rng(rd());
    uniform_int_distribution<unsigned int> selector('A', 'A' + range);
    return (char)selector(rng);
}

namespace Iotivity
{
    std::ostream &TEST_COMMENT()
    {
        std::cout << "             ";
        return std::cout;
    }

    /// \brief Listener for processing test result and outputting them to
    ///        the TBD.
    class ExtendedTestEventListener: public EmptyTestEventListener
    {
        public:
            virtual void OnTestProgramStart(const UnitTest & /*unit_test*/)
            {
                xmpp_connect_config::loadConfig();
            }
            //virtual void OnTestIterationStart(const UnitTest& /*unit_test*/, int /*iteration*/) {}
            //virtual void OnEnvironmentsSetUpStart(const UnitTest& /*unit_test*/) {}
            //virtual void OnEnvironmentsSetUpEnd(const UnitTest& /*unit_test*/) {}
            //virtual void OnTestCaseStart(const TestCase& /*test_case*/) {}
            //virtual void OnTestStart(const TestInfo& /*test_info*/) {}
            //virtual void OnTestPartResult(const TestPartResult& /*test_part_result*/) {}
            //virtual void OnTestEnd(const TestInfo& /*test_info*/) {}
            //virtual void OnTestCaseEnd(const TestCase& /*test_case*/) {}
            //virtual void OnEnvironmentsTearDownStart(const UnitTest& /*unit_test*/) {}
            //virtual void OnEnvironmentsTearDownEnd(const UnitTest& /*unit_test*/) {}
            //virtual void OnTestIterationEnd(const UnitTest& /*unit_test*/, int /*iteration*/) {}
            //virtual void OnTestProgramEnd(const UnitTest& /*unit_test*/) {}
    };

}



int main(int argc, char *argv[])
{
    // TODO: Configure the test result working folder set.

    InitGoogleTest(&argc, argv);

#ifdef LOGSTREAM_ENABLE_LOGGING
    Iotivity::streamlogredirect::redirectLoggingToStream(cout);
#endif

    UnitTest *unitTest = UnitTest::GetInstance();
    if (unitTest)
    {
        // Tee output to the extended test event listener.
        unitTest->listeners().Append(new Iotivity::ExtendedTestEventListener);
    }

    int runResult = RUN_ALL_TESTS();

    if (!runResult)
    {
        // TODO: Manage marking up a successful run's working result set.
    }
    else
    {
        // TODO: Any post-fail operations should go here.
    }

#ifdef LOGSTREAM_ENABLE_LOGGING
    Iotivity::streamlogredirect::redirectLoggingToVoid();
#endif


    return runResult;
}