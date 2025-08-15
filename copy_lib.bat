@echo off
echo Copying BMC Cryptographic libraries to build directory...

REM Create the target directories if they don't exist
if not exist "build\windows\x64\runner\Debug\" (
    echo Creating Debug build directory...
    mkdir "build\windows\x64\runner\Debug\"
)

if not exist "build\windows\x64\runner\Release\" (
    echo Creating Release build directory...
    mkdir "build\windows\x64\runner\Release\"
)

REM Copy DLL to both Debug and Release directories
echo Copying bmc_crypt.dll to Debug directory...
copy "windows\libs\bmc_crypt.dll" "build\windows\x64\runner\Debug\" /Y

echo Copying bmc_crypt.dll to Release directory...
copy "windows\libs\bmc_crypt.dll" "build\windows\x64\runner\Release\" /Y

echo Library copy completed successfully!
pause
