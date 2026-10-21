# 재현 패키지 안내: 스팀 게임 가격과 평균 플레이 시간

## 구성
- `analyze.py`: 분석 스크립트(기준은 코드 맨 위 상수로 고정)
- `results_summary.txt`: 실행 결과 요약(원본 파일 SHA-256 포함)
- `bin_table.csv`, `genre_table.csv`: 가격대별, 장르별 표
- `result.png`: 산점도와 상자 그림
- `analysis_sample.csv`: 분석에 쓴 원자료(16,911행)
- `explore.py`, `explore_results.txt`, `explore_table.csv`: 사후 탐색 분석(주 분석의 판정을 바꾸지 않음)
- `과제10_참고문헌.md`: 참고문헌과 출처 확인 기록
- `과제10_사전기준.md`: 데이터를 열기 전에 정한 기준

## 원본 데이터(용량 때문에 포함하지 않음)
- 출처: https://huggingface.co/datasets/FronkonGames/steam-games-dataset (MIT 라이선스)
- 파일: `data/train-00000-of-00001.parquet`, 124,146행, 2026-10-21에 내려받음
- 원본을 확인하려면 `analyze.py` 실행 시 출력되는 SHA-256이 `results_summary.txt`의 값과 같은지 본다.

## 다시 실행하기
1. 원본 parquet 파일을 `analyze.py`와 같은 폴더에 둔다.
2. `pip install pandas pyarrow scipy matplotlib`
3. `python analyze.py`

## 핵심 결과만 빠르게 확인하기
```
python -c "import pandas as pd; from scipy.stats import spearmanr; d=pd.read_csv('analysis_sample.csv'); print(len(d), spearmanr(d['price'], d['average_playtime_hours']))"
```
행 수 16,911, 스피어만 상관계수 약 0.306이 나와야 한다.

접은 주제에서 만들었던 수집 도구(전적 수집, 치지직 목록 수집)는 분석에 쓰지 않아 포함하지 않았다.

※ 키나 비밀번호는 이 패키지에 없다.
