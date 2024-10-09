@echo off

:: Enable delayed variable expansion
setlocal EnableDelayedExpansion

:: Set IDA plugins directory
set IDA_PLUGIN_DIR=C:\Program Files\IDA Professional 9.0\plugins

:: Loop through both build types
for %%B in (32 64) do (
  :: Set build variables based on current loop iteration
  if "%%B" == "32" (
    set "OUTPUT_FILE=fusion.dll"
    set "BUILD_FOR=32"
  ) else if "%%B" == "64" (
    set "OUTPUT_FILE=fusion64.dll"
    set "BUILD_FOR=64"
  )

  :: Close IDA if running
  tasklist | findstr /i ida%%B.exe >nul && (
    echo [INFO] Closing IDA...
    taskkill /f /im ida%%B.exe
  )

  :: Create temp folder if it doesn't exist
  if not exist obj (
    echo [INFO] Creating temporary directory 'obj'...
    mkdir obj
  )

  :: Build project
  echo [INFO] Starting build process with %NUMBER_OF_PROCESSORS% processors for %%B-bit...
  make make_objects -j%NUMBER_OF_PROCESSORS%
  if !errorlevel! neq 0 (
    echo [ERROR] Failed to make objects for %%B-bit.
    exit /b !errorlevel!
  )

  make make_output
  if !errorlevel! neq 0 (
    echo [ERROR] Failed to make output for %%B-bit.
    exit /b !errorlevel!
  )

  :: Delete temp folder
  echo [INFO] Deleting temporary directory 'obj'...
  rmdir /S /Q obj

  :: Copy output file to IDA plugins folder
  echo [INFO] Copying output file to IDA plugins directory for %%B-bit...
  echo "!cd!\!OUTPUT_FILE!" "!IDA_PLUGIN_DIR!\!OUTPUT_FILE!"
  copy /Y "!cd!\!OUTPUT_FILE!" "!IDA_PLUGIN_DIR!\!OUTPUT_FILE!"
  if !errorlevel! neq 0 (
    echo [ERROR] Failed to copy output file for %%B-bit.
    exit /b !errorlevel!
  )

  echo [INFO] Build completed successfully for %%B-bit.
)

echo [INFO] All builds completed successfully.
