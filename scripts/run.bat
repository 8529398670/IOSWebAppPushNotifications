@echo off
rem Build and run the server from this checkout, outside Docker. The Windows
rem twin of scripts/run.sh: same commands, same behavior, except where noted
rem below.
rem
rem   scripts\run.bat                    rebuild if anything changed, stop the
rem                                      copy this checkout started last, start
rem                                      a fresh one here
rem   scripts\run.bat stop               stop the copy this checkout started
rem                                      (in this window, another, or the
rem                                      hidden one login.bat --background
rem                                      starts)
rem   scripts\run.bat manage <command>   run an admin command against it
rem   scripts\run.bat <anything else>    same: passed straight to the binary
rem
rem The server runs in the foreground: its log streams here and Ctrl-C stops it.
rem Running scripts\run.bat again from another window stops this one and takes
rem over, so "edit, scripts\run.bat, reload the page" is the whole loop.
rem
rem With arguments it is a one-off instead -- the same build, then the binary
rem with those arguments -- and the running server is left alone. That is what
rem makes the admin CLI usable while it is up: `manage` talks to the live server
rem over its control socket rather than opening the database itself.
rem
rem   scripts\login.bat                                  owner's login link
rem   scripts\run.bat manage list-users
rem   scripts\run.bat manage create-login -name "Grace" -role user
rem   scripts\run.bat manage create-invite -user-id 1 -label "Book club"
rem   scripts\run.bat manage create-key -user-id 1 -name "CI"
rem   scripts\run.bat manage paths                       where the state lives
rem   scripts\run.bat config check
rem   scripts\run.bat config shell server                every resolved value
rem   scripts\run.bat version
rem
rem Where it differs from run.sh, Windows forces it:
rem
rem   - A running .exe cannot be overwritten. The build goes to .run\ and is
rem     copied over ipb.exe only once the old server has exited;
rem     one-off runs use the copy in .run\ and never touch the server's.
rem   - There is no pid file. The old server is whatever process is running
rem     this checkout's ipb.exe, which a full path pins down
rem     exactly, so a stale pid can never point at something else.
rem   - Windows cannot send SIGTERM to another console's process, so the old
rem     server is killed rather than drained. bolt is crash-safe, and the
rem     control socket a kill leaves behind is cleared on the next start.
rem
rem This is for development and internal boxes. It is a plain process with your
rem permissions -- none of docker\run.sh's read-only filesystem, dropped
rem capabilities, or pid and memory limits apply -- so use Docker for anything
rem long-lived or internet-facing.
setlocal
cd /d "%~dp0.."


set "BINARY=%CD%\ipb.exe"
set "RUN_DIR=%CD%\.run"
set "BUILT=%RUN_DIR%\ipb.exe"

if not exist "%RUN_DIR%" mkdir "%RUN_DIR%"

if /i not "%~1"=="stop" goto not_stop
if not "%~2"=="" goto not_stop
set "RUN_EXE=%BINARY%"
powershell -NoProfile -Command "$old = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $env:RUN_EXE }); if (-not $old) { Write-Host 'No server started by this checkout is running.'; exit }; foreach ($p in $old) { Write-Host ('Stopping the server this checkout started (pid ' + $p.ProcessId + ', running since ' + $p.CreationDate + ')...'); Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }; foreach ($p in $old) { Wait-Process -Id $p.ProcessId -Timeout 15 -ErrorAction SilentlyContinue }; Write-Host 'Stopped.'"
exit /b 0
:not_stop

rem Rebuild every time and let Go decide whether that means anything: its build
rem cache makes an unchanged tree a near-instant no-op, and catches every input
rem that matters -- .go files, go.mod, and the embedded static\ and config\ --
rem with no timestamp bookkeeping here to get wrong.
rem
rem This happens before anything is stopped, so a build error leaves the server
rem that was already running untouched.
rem
rem Version metadata is stamped the way scripts\build.sh does it, so
rem `scripts\run.bat version` says what is running. No -s -w: this build is for
rem debugging, not shipping. The version is the UTC build time
rem (2026.10.23-1412), like run.sh.
where go >nul 2>&1
if errorlevel 1 (
  echo ERROR: go is not on PATH. Install Go from https://go.dev/dl/ and re-run.
  exit /b 1
)
set "VERSION=dev"
set "COMMIT=unknown"
for /f "delims=" %%v in ('powershell -NoProfile -Command "(Get-Date).ToUniversalTime().ToString('yyyy.MM.dd-HHmm')" 2^>nul') do set "VERSION=%%v"
for /f "delims=" %%c in ('git rev-parse --short HEAD 2^>nul') do set "COMMIT=%%c"
go build -buildvcs=false -trimpath -ldflags "-X main.version=%VERSION% -X main.commit=%COMMIT%" -o "%BUILT%" .
if not errorlevel 1 goto built
echo.
echo ERROR: the build failed (above). Nothing was stopped or started.
exit /b 1
:built

if "%~1"=="" goto server
"%BUILT%" %*
exit /b %errorlevel%

:server
call :read_config
if not defined config_file exit /b 1

rem First run on this checkout: config\config.yaml is gitignored, so a fresh
rem clone has none. Without one here the binary would quietly create
rem %USERPROFILE%\.config\ipb\config.yaml instead, which is the
rem right thing for a portable binary and the wrong one for a checkout. Write it
rem here and stop, like docker\run.sh, so it gets looked at before the first start.
if "%config_exists%"=="true" goto migrate
"%BUILT%" config init -file .\config\config.yaml >nul
if errorlevel 1 exit /b 1
call :read_config
echo First run: wrote %config_file%
echo   and %secret_file%
echo   (secret.key holds a new key -- back it up with the database; it is the
echo   only thing that can read it).
echo.
echo It will serve %url%
echo   (from %url_source%).
if not "%secure_cookies%"=="true" goto first_done
if not "%url:~0,7%"=="http://" goto first_done
call :config_line secure_cookies
echo.
echo server.secure_cookies is true. That is right behind HTTPS, but at %url%
echo the browser drops a Secure cookie and signing in silently does nothing.
echo For local use, change line %LINE% of %config_file%:
echo.
echo     secure_cookies: true   -^>   secure_cookies: false
:first_done
echo.
echo Most settings can be changed later while the server runs, from the owner's
echo Settings screen or by editing config.yaml. Then run scripts\run.bat again.
exit /b 0

:migrate
rem A config.yaml from before secret.key existed has the key inside it. Move it
rem out now, before anything starts, so the window says so. Silent otherwise.
"%BUILT%" config migrate -file .\config\config.yaml
if errorlevel 1 exit /b 1
call :read_config
if "%secret_exists%"=="true" goto stop_old
if not "%database_exists%"=="true" goto stop_old
echo ERROR: %secret_file% is missing, and %database% exists.
echo        Restore secret.key from your backup: a new key cannot read the database.
exit /b 1

:stop_old
rem Stop the copy this checkout started last: any process whose image is this
rem checkout's ipb.exe. The path goes to PowerShell through the
rem environment rather than inside the command, so no character in it (a
rem quote in a user name, say) can break the quoting.
set "RUN_EXE=%BINARY%"
powershell -NoProfile -Command "$old = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $env:RUN_EXE }); foreach ($p in $old) { Write-Host ('Stopping the server this checkout started (pid ' + $p.ProcessId + ', running since ' + $p.CreationDate + ')...'); Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }; foreach ($p in $old) { Wait-Process -Id $p.ProcessId -Timeout 15 -ErrorAction SilentlyContinue }"

rem Anything still on the port is not ours, and the server would only die on
rem "address already in use" after printing a banner that says it started.
set "PORT_OWNER="
for /f "delims=" %%o in ('powershell -NoProfile -Command "$c = Get-NetTCPConnection -State Listen -LocalPort %port% -ErrorAction SilentlyContinue | Select-Object -First 1; if ($c) { $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; $name = if ($p.Path) { $p.Path } else { $p.ProcessName }; $name + ' (pid ' + $c.OwningProcess + ')' }" 2^>nul') do set "PORT_OWNER=%%o"
if not defined PORT_OWNER goto port_free
call :config_line port
echo ERROR: port %port% (server.port) is already in use by %PORT_OWNER%.
echo.
echo        It is not the server this checkout started. Stop it, or change line
echo        %LINE% of %config_file% to a free port, then re-run.
exit /b 1
:port_free

rem Not a parenthesized block: a ")" in the checkout's path would end it early.
copy /y "%BUILT%" "%BINARY%" >nul
if not errorlevel 1 goto start
echo ERROR: could not replace %BINARY% -- something else is still running it.
exit /b 1

:start
if not "%secure_cookies%"=="true" goto cookies_ok
if not "%url:~0,7%"=="http://" goto cookies_ok
call :config_line secure_cookies
echo WARNING: server.secure_cookies is true but the URL is %url%.
echo          The browser will drop the session cookie and signing in will silently
echo          do nothing. Set it to false on line %LINE% of %config_file%
echo          for local use, or set server.public_url to the https:// address in front.
echo.
:cookies_ok

set "DB_NOTE=existing"
if not "%database_exists%"=="true" set "DB_NOTE=new -- the owner's first login link is printed below"
set "STATIC_NOTE=%static_dir%  (from disk: frontend edits need only a reload)"
if not "%static_on_disk%"=="true" set "STATIC_NOTE=embedded copy  (no directory at %static_dir%)"
set "LANGUAGE_NOTE=%language_file%  (from disk)"
if not "%language_on_disk%"=="true" set "LANGUAGE_NOTE=embedded copy  (no file at %language_file%)"
set "CONTROL_NOTE=%control_socket_path%  (manage works while it runs)"
if not "%control_socket%"=="true" set "CONTROL_NOTE=off (server.control_socket: false) -- manage needs the server stopped"

echo Starting ipb %VERSION% (commit %COMMIT%)
echo   url       %url%
echo             from %url_source%
echo   config    %config_file%
echo   app dir   %app_dir%
echo   database  %database%  (%DB_NOTE%)
echo   static    %STATIC_NOTE%
echo   language  %LANGUAGE_NOTE%
echo   control   %CONTROL_NOTE%
echo.
echo A login link for the owner any time: scripts\login.bat (from another window).
echo.

rem Say when it is actually answering, not just launched. This runs beside the
rem server in the same window and gives up after 20 seconds.
set "READY_URL=%url%"
start "" /b powershell -NoProfile -Command "for ($i = 0; $i -lt 80; $i++) { Start-Sleep -Milliseconds 250; & $env:RUN_EXE health *> $null; if ($LASTEXITCODE -eq 0) { Write-Host ''; Write-Host ('Ready: ' + $env:READY_URL); Write-Host ''; exit } }; Write-Host ''; Write-Host ('Not answering on port ' + $env:port + ' after 20 seconds -- see the log above.')"

"%BINARY%"
exit /b %errorlevel%

rem ---------------------------------------------------------------------------
rem read_config sets every value `config shell server` prints (config_file,
rem app_dir, database, url, port, ...), resolved by the binary exactly the way
rem the server resolves them -- nothing here parses YAML.
:read_config
set "config_file="
for /f "usebackq tokens=1,* delims==" %%a in (`"%BUILT%" config shell -format bat server`) do set "%%a=%%b"
if defined config_file exit /b 0
echo.
echo ERROR: the config above does not validate. Fix it and re-run.
exit /b 1

rem config_line KEY sets LINE to that key's line number in config.yaml.
:config_line
set "LINE=?"
for /f "tokens=1 delims=:" %%n in ('findstr /n /r /c:"^ *%1:" "%config_file%"') do (
  set "LINE=%%n"
  exit /b 0
)
exit /b 0
