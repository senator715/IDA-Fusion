@echo off

:: close IDA64
taskkill /f /im ida64.exe

:: create temp folder
mkdir obj

set OUTPUT_FILE=fusion64.dll
set BUILD_FOR=64
make make_objects -j%NUMBER_OF_PROCESSORS%
make make_output

:: delete temp folder
rmdir /S /Q obj

copy /Y "%cd%\%OUTPUT_FILE%" "C:\Program Files\IDA77\plugins\fusion64.dll"