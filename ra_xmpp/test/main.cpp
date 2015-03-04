
#ifdef _WIN32
#include "targetver.h"
#endif

#include <gtest/gtest.h>


using namespace testing;
using namespace std;

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
            //virtual void OnTestProgramStart(const UnitTest& /*unit_test*/) {}
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


    return runResult;
}
