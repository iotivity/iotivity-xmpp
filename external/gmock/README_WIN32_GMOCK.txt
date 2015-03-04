For the moment, the windows build does not have an automated script to pull down gmock. As of
gmock 1.7.0 it is necessary to perform four steps to make this build succeed.

Download gmock 1.7.0 (or later) and unpack its root folder under this gmock folder (i.e.
gmock's LICENSE file should appear in the same directory as this readme).

Open WinDT.sln for ccfxmpp and upgrade the gmock project to the latest build environment.

Add an x64 configuration for the x64 build target for gmock through the Configuration Manager.

Modify the C runtime target for the gmock project to use the Multi-Threaded Debug DLL and
Multi-Threaded DLL versions.


