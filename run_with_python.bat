@echo off
chcp 65001 > nul
cd /d %~dp0
python run.py 2>nul || py -3 run.py || (echo Python 3.8 이상이 필요합니다. https://www.python.org & pause)
