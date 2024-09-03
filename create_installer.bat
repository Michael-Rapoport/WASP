@echo off
setlocal

REM Set paths
set WIX_PATH=C:\Program Files (x86)\WiX Toolset v3.11\bin
set PROJECT_ROOT=%~dp0
set INSTALLER_DIR=%PROJECT_ROOT%installer
set BUILD_DIR=%PROJECT_ROOT%target\release

REM Build the Rust project
cargo build --release

REM Create installer directory if it doesn't exist
if not exist "%INSTALLER_DIR%" mkdir "%INSTALLER_DIR%"

REM Compile WiX source file
"%WIX_PATH%\candle.exe" -dBinDir="%BUILD_DIR%" -dConfigDir="%PROJECT_ROOT%" "%INSTALLER_DIR%\WASP.wxs" -o "%INSTALLER_DIR%\WASP.wixobj"

REM Link WiX object file
"%WIX_PATH%\light.exe" -ext WixUIExtension "%INSTALLER_DIR%\WASP.wixobj" -o "%INSTALLER_DIR%\WASP_Installer.msi"

echo Installer created: %INSTALLER_DIR%\WASP_Installer.msi

endlocal