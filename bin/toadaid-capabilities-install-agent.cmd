@echo off
rem ToadAid Agent Capabilities - generic-agent bootstrap (native Windows entrypoint)
rem
rem Thin transport wrapper only, for cmd.exe. It also works when called from
rem PowerShell and does not depend on PowerShell script execution policy.
rem ALL installer semantics live in the ONE cross-platform Node core next to
rem this file:
rem
rem   bin\toadaid-capabilities-install-agent.mjs
rem
rem This wrapper locates Node, invokes the core, forwards argv unchanged and
rem preserves the exit code. It holds no installer policy and grants no authority.
setlocal
where node >nul 2>nul
if errorlevel 1 (
  >&2 echo toadaid-capabilities-install-agent: required command unavailable: node
  exit /b 2
)
node "%~dp0toadaid-capabilities-install-agent.mjs" %*
exit /b %ERRORLEVEL%
