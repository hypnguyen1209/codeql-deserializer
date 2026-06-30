@echo off
REM Build a CodeQL database for the Java deserialization demo target.
REM Requires CODEQL_JAVA_HOME (set by the CodeQL CLI during extraction).
cd /d "%~dp0src"
if exist ..\classes rmdir /s /q ..\classes
mkdir ..\classes
dir /s /b *.java > ..\sources.txt
"%CODEQL_JAVA_HOME%\bin\javac.exe" -d ..\classes @..\sources.txt
exit /b 0
