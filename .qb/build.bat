rem SPDX-License-Identifier: Apache-2.0
rem Copyright (C) 2022 Intel Corporation

SET COMPILE_MODE=%1
if not defined COMPILE_MODE SET COMPILE_MODE=Release

set ERROR_FLAG=0

set EWDK_DIR=%EWDK%
if [%EWDK%]==[] set EWDK_DIR=D:\Tools\ISDC_Tools\EWDK\WIN11_21H2

if not exist %EWDK_DIR% (
	echo Can't find EWDK at %EWDK_DIR%!!
	EXIT /B 1
)

pushd %EWDK_DIR%\BuildEnv
call SetupBuildEnv.cmd
popd

set CMAKE_WINDOWS_KITS_10_DIR=%EWDK_DIR%\Program Files\Windows Kits\10
set PATH=%PATH%;D:\Tools\ISDC_Tools\Compilers\cmake-3.21.4-windows-x86_64\bin

set "PUBLISH_DIR=Bin\Kit\IGSC_FUL"
if %COMPILE_MODE%==Debug set "PUBLISH_DIR=Bin\Kit\IGSC_FUL_DEBUG"

REM Clean publish directories
mkdir "%PUBLISH_DIR%"
mkdir "%PUBLISH_DIR%\INTERNAL"

setlocal EnableDelayedExpansion

@echo on

ECHO Building IGSC.

RD /S /Q %COMPILE_MODE%
md %COMPILE_MODE%

copy .qb\CMakeUserPresets.json CMakeUserPresets.json

cmake --preset %COMPILE_MODE%CI
IF ERRORLEVEL 1 (
	echo Error while configuring IGSC in %COMPILE_MODE% mode
	set ERROR_FLAG=1
	goto FINISH
)

cmake --build --preset %COMPILE_Mode%CI -j 32
IF ERRORLEVEL 1 (
	echo Error while building IGSC in %COMPILE_MODE% mode
	set ERROR_FLAG=1
	goto FINISH
)

del CMakeUserPresets.json

if not "%KW_SCAN%"=="1" (
        REM *** sign dll ***
        call %SIGN_SCRIPT% %COMPILE_MODE%\lib\%COMPILE_MODE%\igsc.dll
        if ERRORLEVEL 1 (
		set ERROR_FLAG=1
		goto FINISH
        )
)

copy include\igsc_lib.h %PUBLISH_DIR%\
copy %COMPILE_MODE%\lib\%COMPILE_MODE%\igsc.lib %PUBLISH_DIR%\
copy %COMPILE_MODE%\lib\%COMPILE_MODE%\igsc.dll %PUBLISH_DIR%
copy %COMPILE_MODE%\lib\%COMPILE_MODE%\igsc.dll %PUBLISH_DIR%\INTERNAL
copy %COMPILE_MODE%\src\%COMPILE_MODE%\igsc.exe %PUBLISH_DIR%\INTERNAL

:FINISH
IF %ERROR_FLAG% == 0 GOTO NO_ERROR
echo.
echo IGSC Build had Errors!!
endlocal
::Do not use %ERROR_FLAG% because we are after the endlocal
EXIT /B 1

:NO_ERROR
echo.
echo IGSC Build Completed Successfully !!!
endlocal
::Do not use %ERROR_FLAG% because we are after the endlocal
EXIT /B 0
