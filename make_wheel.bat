@echo off
rem whatever2sbom — build a distributable wheel on Windows.
rem Mirrors the `wheel` target in the Makefile.

setlocal enabledelayedexpansion

set VENV=.venv
set VENV_PYTHON=%VENV%\Scripts\python.exe

if not exist "%VENV_PYTHON%" (
    echo Creating venv in %VENV%...
    python -m venv "%VENV%" || goto :error
)

"%VENV_PYTHON%" -m pip install --upgrade pip || goto :error
"%VENV_PYTHON%" -m pip install -e ".[dev]" || goto :error

if exist dist rmdir /s /q dist

"%VENV_PYTHON%" -m build --wheel || goto :error

echo.
for %%F in (dist\*.whl) do (
    echo Wheel ready: %%F
    echo.
    echo Install locally: pip install %%F
)

goto :eof

:error
echo.
echo Build failed.
exit /b 1
