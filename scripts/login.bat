@echo off
rem Print a one-time login link -- by default for user 1, the owner -- for
rem whichever deployment of this checkout is actually live. The Windows twin
rem of scripts/login.sh.
rem
rem   scripts\login.bat               the owner (user 1)
rem   scripts\login.bat 3             user 3
rem   scripts\login.bat --docker      the docker container, even if a local
rem                                   server is running too
rem   scripts\login.bat --local       this checkout's local server
rem   scripts\login.bat --no-start    never start a server: with none running,
rem                                   write the link into the database offline
rem   scripts\login.bat --background  with none running, start one detached
rem                                   instead of in this window
rem
rem Where the link comes from: the local server (scripts\run.bat) when it is
rem running, otherwise the docker container (docker/run.sh) when it is running,
rem otherwise this writes the link into the database, prints it, and runs
rem scripts\run.bat: the server runs in this window and Ctrl-C stops it. With no
rem database yet, the server's first start prints the owner's link instead. With
rem --background the server starts hidden instead (log in .run\server.log, stop
rem it with scripts\run.bat stop), and the link comes from it once it answers.
rem The local server and the container keep separate databases, so a link from
rem one does nothing in the other. This says which one it used.
setlocal
cd /d "%~dp0.."


set "USER_ID=1"
set "MODE=auto"
set "START=true"
set "BACKGROUND=false"
:args
if "%~1"=="" goto args_done
if /i "%~1"=="--docker" (set "MODE=docker" & shift & goto args)
if /i "%~1"=="--local" (set "MODE=local" & shift & goto args)
if /i "%~1"=="--no-start" (set "START=false" & shift & goto args)
if /i "%~1"=="--background" (set "BACKGROUND=true" & shift & goto args)
echo %~1| findstr /r "^[0-9][0-9]*$" >nul
if errorlevel 1 (
  echo ERROR: expected a numeric user id, --docker, --local, --no-start or --background; got "%~1".
  exit /b 1
)
set "USER_ID=%~1"
shift
goto args
:args_done

set "BINARY=%CD%\ipb.exe"
set "RUN_DIR=%CD%\.run"
set "BUILT=%RUN_DIR%\ipb.exe"
if not exist "%RUN_DIR%" mkdir "%RUN_DIR%"

rem The same build scripts\run.bat makes, into .run\ so a running server's
rem .exe is never touched.
where go >nul 2>&1
if errorlevel 1 (
  echo ERROR: go is not on PATH. Install Go from https://go.dev/dl/ and re-run.
  exit /b 1
)
go build -buildvcs=false -trimpath -o "%BUILT%" .
if errorlevel 1 exit /b 1

set "config_file="
for /f "usebackq tokens=1,* delims==" %%a in (`"%BUILT%" config shell -format bat server`) do set "%%a=%%b"
if not defined config_file exit /b 1
for /f "usebackq tokens=1,* delims==" %%a in (`"%BUILT%" config shell -format bat docker`) do set "%%a=%%b"

if "%config_exists%"=="true" goto have_config
echo ERROR: no config yet -- %config_file% does not exist.
echo        Run scripts\run.bat first: it writes one, and the first start prints
echo        the owner's login link.
exit /b 1
:have_config

rem Is this checkout's server running? Any process whose image is its
rem ipb.exe -- the same test scripts\run.bat stops it by.
set "RUN_EXE=%BINARY%"
set "LOCAL_PID="
for /f "delims=" %%p in ('powershell -NoProfile -Command "@(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $env:RUN_EXE })[0].ProcessId" 2^>nul') do set "LOCAL_PID=%%p"

set "DOCKER_UP=false"
where docker >nul 2>&1
if errorlevel 1 goto docker_checked
for /f "delims=" %%n in ('docker ps --filter "name=^%docker_container%$" --format "{{.Names}}" 2^>nul') do set "DOCKER_UP=true"
:docker_checked

if not "%MODE%"=="auto" goto mode_chosen
set "MODE=local"
if defined LOCAL_PID goto auto_local
if "%DOCKER_UP%"=="true" set "MODE=docker"
goto mode_chosen
:auto_local
if not "%DOCKER_UP%"=="true" goto mode_chosen
echo Note: the %docker_container% container is running too. It has its own database;
echo       this link is for the local server. Use --docker for the container.
echo.
:mode_chosen

if not "%MODE%"=="docker" goto local
if "%DOCKER_UP%"=="true" goto docker_up
echo ERROR: the %docker_container% container is not running.
echo        Start it with docker/run.sh, or see why it stopped: docker logs %docker_container%
exit /b 1
:docker_up
echo Docker container %docker_container%, served at %docker_url%
echo.
docker exec %docker_container% /app/server manage reissue-login -user-id %USER_ID%
if not errorlevel 1 exit /b 0
echo.
echo Accounts in the container: docker exec %docker_container% /app/server manage list-users
exit /b 1

:local
if not defined LOCAL_PID goto not_running
echo Local server (pid %LOCAL_PID%), served at %url%
echo   database %database%
echo.
call :issue_link
exit /b %errorlevel%

:not_running
if "%START%"=="true" goto start_server
if exist "%database%" goto offline
echo ERROR: there is no database yet at %database%.
echo        Start the server with scripts\run.bat -- its first start creates the owner
echo        and prints their login link.
exit /b 1
:offline
echo No server is running for this checkout, so the link goes straight into
echo the database. It works once you start it: scripts\run.bat
echo   database %database%
echo.
call :issue_link
exit /b %errorlevel%

:start_server
if "%BACKGROUND%"=="true" goto start_background
if not exist "%database%" goto first_start
echo No server is running for this checkout, so the link goes straight into
echo the database, and the server starts right here.
echo   database %database%
echo.
call :issue_link
if errorlevel 1 exit /b 1
echo.
goto start_here
:first_start
echo No database yet: the first start below creates the owner and prints their
echo login link.
echo.
:start_here
echo Starting the server here; Ctrl-C stops it.
echo.
call "%CD%\scripts\run.bat"
exit /b %errorlevel%

:start_background
if not "%secure_cookies%"=="true" goto cookies_ok
if not "%url:~0,7%"=="http://" goto cookies_ok
echo WARNING: server.secure_cookies is true but the URL is %url%.
echo          The browser will drop the session cookie and this link will seem to do
echo          nothing. Set it to false in %config_file%
echo          for local use, or set server.public_url to the https:// address in front.
echo.
:cookies_ok

rem Without the control socket, manage cannot reach a running server and opens
rem the database itself -- so the link has to go in before the server starts.
rem With no database yet there is nothing to put it in; the server's first
rem start creates the owner and prints their link into the log instead.
if "%control_socket%"=="true" goto launch
if not exist "%database%" goto launch
echo server.control_socket is off, so the link goes into the database before the
echo server starts.
echo.
call :issue_link
if errorlevel 1 exit /b 1
echo.

:launch
rem scripts\run.bat in a hidden window of its own, so closing this one does
rem not take the server with it. It is up once this checkout's .exe is running
rem (run.bat copies the build over it first) and answers its health check --
rem asked of the .run\ copy, which run.bat has finished building by then. It
rem gives up after 20 seconds, or as soon as run.bat exits. [char]34 is a
rem double quote: a literal one would end this line's quoting for cmd.
echo No server was running for this checkout; starting one in the background...
set "RUN_BAT=%CD%\scripts\run.bat"
set "LOG_FILE=%RUN_DIR%\server.log"
set "BACKGROUND_PID="
for /f "delims=" %%p in ('powershell -NoProfile -Command "$q = [char]34; $cmd = Start-Process -FilePath cmd.exe -ArgumentList ('/c ' + $q + $q + $env:RUN_BAT + $q + ' > ' + $q + $env:LOG_FILE + $q + ' 2>&1' + $q) -WindowStyle Hidden -PassThru; for ($i = 0; $i -lt 80; $i++) { Start-Sleep -Milliseconds 250; $p = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $env:RUN_EXE })[0]; if ($p) { & $env:BUILT health *> $null; if ($LASTEXITCODE -eq 0) { $p.ProcessId; exit } }; if ($cmd.HasExited) { break } }" 2^>nul') do set "BACKGROUND_PID=%%p"
if defined BACKGROUND_PID goto started
echo ERROR: the server did not come up. The end of %LOG_FILE%:
echo.
powershell -NoProfile -Command "Get-Content -Tail 20 -LiteralPath $env:LOG_FILE | ForEach-Object { '    ' + $_ }"
exit /b 1

:started
echo Local server (pid %BACKGROUND_PID%), served at %url%
echo   database %database%
echo   log      %LOG_FILE%
echo   stop it  scripts\run.bat stop
echo.
if "%control_socket%"=="true" goto socket_link
rem The first start's link for the owner, as the server printed it.
findstr /c:"/login/" "%LOG_FILE%"
exit /b 0
:socket_link
call :issue_link
exit /b %errorlevel%

rem ---------------------------------------------------------------------------
:issue_link
"%BUILT%" manage reissue-login -user-id %USER_ID%
if not errorlevel 1 exit /b 0
echo.
echo Accounts in this database: scripts\run.bat manage list-users
exit /b 1
