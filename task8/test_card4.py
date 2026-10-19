"""카드 5에서 서버가 계정 두 개 구조로 바뀌어, 이 파일의 옛 테스트는 test_all.py 로 합쳤습니다."""
import os, runpy, sys
runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_all.py"), run_name="__main__")
