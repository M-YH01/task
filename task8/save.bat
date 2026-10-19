@echo off
rem task8 폴더 변경분을 저장소 맨 위에서 한 번에 add + commit 합니다. (GitHub Desktop의 add 오류 우회)
chcp 65001 >nul
cd /d "%~dp0.."
if not exist .git (
  echo [오류] %cd% 가 git 저장소 맨 위가 아닙니다. task8 폴더가 저장소 바로 아래에 있어야 합니다.
  pause
  exit /b 1
)
rem 세션 파일은 토큰 해시가 들어 있어 올리지 않습니다.
findstr /x /c:"task8/sessions.json" .gitignore >nul 2>&1 || echo task8/sessions.json>> .gitignore
git rm --cached --ignore-unmatch task8/sessions.json >nul 2>&1
git add .gitignore task8
set MSG=%~1
if "%MSG%"=="" set MSG=task8 update
git commit -m "%MSG%"
echo.
git status --short
echo.
echo 커밋이 끝났습니다. 이제 GitHub Desktop에서 Push origin 을 누르세요.
pause
