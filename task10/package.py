"""제출물 ZIP 만들기와 점검.

사용법: 아래 파일들이 모두 들어 있는 폴더에서  python package.py
결과: 과제10_제출물.zip (만든 뒤 임시 폴더에 풀어서 빠진 파일, 건수, 미완성 표시를 검사한다)
"""
import csv
import os
import re
import shutil
import sys
import tempfile
import zipfile

ZIP_NAME = "과제10_제출물.zip"
ROOT_FILES = ["과제10_논문.md", "AI와_나의_판단_3줄.md"]
PKG_DIR = "재현패키지"
PKG_FILES = [
    "analyze.py", "explore.py", "README.md",
    "results_summary.txt", "bin_table.csv", "genre_table.csv", "result.png",
    "analysis_sample.csv", "explore_results.txt", "explore_table.csv",
    "과제10_사전기준.md", "과제10_참고문헌.md",
]
# 제출물에 남으면 안 되는 표시와 비밀 정보 흔적
BAD = ["______", "(본인", "TODO", "초안", "수정할 수 있음", "RGAPI-", "Client-Secret:", "CLIENT_SECRET=", "API_KEY="]


def main():
    missing = [f for f in ROOT_FILES + PKG_FILES if not os.path.exists(f)]
    if missing:
        sys.exit("현재 폴더에 없는 파일: " + ", ".join(missing))

    with zipfile.ZipFile(ZIP_NAME, "w", zipfile.ZIP_DEFLATED) as z:
        for f in ROOT_FILES:
            z.write(f, f)
        for f in PKG_FILES:
            z.write(f, f"{PKG_DIR}/{f}")
    print(f"{ZIP_NAME} 생성")

    problems = []
    tmp = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(ZIP_NAME) as z:
            z.extractall(tmp)
        for f in ROOT_FILES:
            if not os.path.exists(os.path.join(tmp, f)):
                problems.append(f"압축 안에 없음: {f}")
        for f in PKG_FILES:
            if not os.path.exists(os.path.join(tmp, PKG_DIR, f)):
                problems.append(f"압축 안에 없음: {PKG_DIR}/{f}")

        # 원자료 건수와 결과 요약의 표본 수가 같은지
        with open(os.path.join(tmp, PKG_DIR, "analysis_sample.csv"), encoding="utf-8-sig", newline="") as fh:
            n_rows = sum(1 for _ in csv.reader(fh)) - 1
        summary = open(os.path.join(tmp, PKG_DIR, "results_summary.txt"), encoding="utf-8").read()
        m = re.search(r"n = ([\d,]+)", summary)
        n_sum = int(m.group(1).replace(",", "")) if m else None
        print(f"원자료 행 수 {n_rows:,}, 결과 요약의 표본 수 {n_sum:,}" if n_sum else "표본 수를 찾지 못함")
        if n_sum != n_rows:
            problems.append(f"건수 불일치: 원자료 {n_rows}행, 요약 {n_sum}")
        paper = open(os.path.join(tmp, "과제10_논문.md"), encoding="utf-8").read()
        if f"{n_rows:,}" not in paper:
            problems.append(f"논문에 표본 수 {n_rows:,}이(가) 보이지 않음")

        # 미완성 표시, 비밀 정보 흔적
        for root, _, names in os.walk(tmp):
            for name in names:
                if name.endswith((".md", ".py", ".txt", ".csv")):
                    path = os.path.join(root, name)
                    text = open(path, encoding="utf-8-sig", errors="ignore").read()
                    for b in BAD:
                        if b in text and name != "package.py":
                            problems.append(f"{os.path.relpath(path, tmp)} 에 '{b}' 표시가 있음")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if problems:
        print("\n확인할 것:")
        for p in problems:
            print(" -", p)
    else:
        print("\n점검 통과: 빠진 파일, 건수 불일치, 미완성 표시, 비밀 정보 흔적이 없습니다.")


if __name__ == "__main__":
    main()
