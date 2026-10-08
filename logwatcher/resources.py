"""실행 환경(개발 소스 / PyInstaller exe)에 따른 경로 처리."""
import os
import sys


def _bundle_dir():
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def app_dir():
    """사용자가 수정하는 파일(config.json)이 놓이는 폴더: exe 옆 또는 프로젝트 루트."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resource_path(*parts):
    return os.path.join(_bundle_dir(), *parts)
