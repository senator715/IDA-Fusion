@echo off

:: close IDA
taskkill /f /im ida.exe

:: create temp folder
mkdir obj

set OUTPUT_FILE=fusion.dll
set BUILD_FOR=32
make make_objects -j%NUMBER_OF_PROCESSORS%
make make_output

:: delete temp folder
rmdir /S /Q obj

copy /Y "%cd%\%OUTPUT_FILE%" "C:\Program Files\IDA77\plugins\fusion.dll"