@echo off

set path=%path%;"D:\Tools\ISDC_Tools\Compilers\cmake-3.16.4-win64-x64\bin"

set VS_CODE="Visual Studio 16 2019"
set CMAKE_ARGS="-DLIBMETEE_REPO=ssh://git@gitlab.devtools.intel.com:29418/mesw/metee.git"
cmake %CMAKE_ARGS% -G %VS_CODE% -S . -B build
cmake --build build --config Release -t package
FOR %%F in (build\igsc-*-win64.zip) DO set pkgversioned=%%F
copy /b /y /v %pkgversioned% build\igsc-win64.zip
