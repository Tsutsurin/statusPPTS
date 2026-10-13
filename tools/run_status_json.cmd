@echo off
rem Запуск STATUS без веба (ТСУ -> JSON): впишите пути и запустите этот файл.
chcp 65001 >nul
cd /d "%~dp0\.."

set TSU=C:\путь\ТСУ.xlsx
set PPTS_GENERAL=C:\путь\ППТС общий.xlsx
set PPTS_LOCAL=C:\путь\ППТС локальный.xlsx
set KB=C:\путь\knowledge.db
set JOURNAL=C:\путь\Журнал.xlsx
set APP_CONFIG=C:\путь\matcher_config.json
set OUT=result.json

py tools\status_json.py --tsu "%TSU%" --ppts-general "%PPTS_GENERAL%" --ppts-local "%PPTS_LOCAL%" --kb "%KB%" --journal "%JOURNAL%" --app-config "%APP_CONFIG%" --out "%OUT%"
pause
