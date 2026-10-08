@echo off
chcp 65001 > nul
REM ============================================================
REM  LogWatcher.exe 빌드 (Windows, Python 3.8 이상 필요)
REM  빌드하는 PC에만 Python이 있으면 되고, 사용하는 PC에는 필요 없습니다.
REM  (GitHub Actions가 자동으로 빌드한 exe를 받아 써도 됩니다)
REM ============================================================
cd /d %~dp0
call :findpy || goto :nopy
echo [1/2] PyInstaller 설치 중...
%PY% -m pip install --upgrade pyinstaller || goto :err
echo [2/2] LogWatcher.exe 만드는 중...
%PY% -m PyInstaller --noconfirm --clean --onefile --name LogWatcher --add-data "web;web" --add-data "data;data" run.py || goto :err
echo.
echo 완료: dist\LogWatcher.exe
pause
exit /b 0

:findpy
set PY=
python --version > nul 2>&1 && set PY=python && exit /b 0
py -3 --version > nul 2>&1 && set PY=py -3 && exit /b 0
exit /b 1

:nopy
echo Python을 찾을 수 없습니다. https://www.python.org 에서 Python 3.8 이상을 설치하세요.
echo (설치 화면에서 "Add python.exe to PATH"를 체크하세요)
pause
exit /b 1

:err
echo.
echo 빌드 중 오류가 발생했습니다. 위 메시지를 확인하세요.
pause
exit /b 1
