"""스팀 게임 가격과 평균 플레이 시간의 관계 분석.

사용법:
    python analyze.py                 # 같은 폴더의 첫 번째 .parquet(없으면 games.csv)를 읽는다
    python analyze.py 파일이름.parquet

사전 기준(데이터를 열기 전에 고정, 과제10_사전기준.md 와 같아야 한다):
- 포함: 가격 > 0, 긍정+부정 리뷰 >= MIN_REVIEWS, 평균 플레이 시간 > 0
- 지표: 가격과 평균 플레이 시간의 스피어만 순위 상관계수
- 지지 조건: 상관계수 > 0 이고 유의확률 < ALPHA. 그렇지 않으면 기각.
"""
import glob
import hashlib
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.stats import spearmanr

# ---- 사전 고정 기준 ----
MIN_REVIEWS = 100
ALPHA = 0.05
PRICE_BINS = [0, 5, 15, 30, np.inf]
PRICE_LABELS = ["0-5", "5-15", "15-30", "30+"]
TOP_GENRES = 6
# 평균 플레이 시간 단위: 스팀 집계값은 분 단위로 알려져 있다. 데이터 설명서로 확인할 것.
MINUTES_PER_HOUR = 60
# ------------------------

out = []
SRC = {"path": None}


def log(msg=""):
    print(msg)
    out.append(str(msg))


def load():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if path is None:
        files = sorted(glob.glob("*.parquet")) or sorted(glob.glob("games.csv"))
        if not files:
            sys.exit("같은 폴더에 .parquet 또는 games.csv 파일이 없습니다. 파일을 이 폴더에 두거나 파일 이름을 인자로 주세요.")
        path = files[0]
    SRC["path"] = path
    log(f"데이터 파일: {path}")
    df = pd.read_csv(path, index_col=False) if path.lower().endswith(".csv") else pd.read_parquet(path)
    # 열 이름을 소문자·밑줄로 통일 (예: "Average playtime forever" -> average_playtime_forever)
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]
    return df


def genre_list(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [g.strip() for g in v.split(",") if g.strip()]
    try:
        return [str(g) for g in list(v)]
    except TypeError:
        return []


def rho_p(x, y):
    r, p = spearmanr(x, y)
    return float(r), float(p)


def main():
    df = load()
    need = ["price", "average_playtime_forever", "positive", "negative"]
    miss = [c for c in need if c not in df.columns]
    if miss:
        sys.exit(f"필요한 열이 없습니다: {miss}")
    log(f"전체 게임 수: {len(df):,}")
    if "release_date" in df.columns:
        rd = pd.to_datetime(df["release_date"], errors="coerce")
        log(f"출시일 범위: {rd.min()} ~ {rd.max()}  (데이터 기준일의 대략적인 근거)")

    d = df.copy()
    d["reviews"] = d["positive"].fillna(0) + d["negative"].fillna(0)
    d["hours"] = d["average_playtime_forever"] / MINUTES_PER_HOUR

    d = d[d["price"] > 0]
    log(f"가격 > 0 적용 후: {len(d):,}개")
    d = d[d["reviews"] >= MIN_REVIEWS]
    log(f"리뷰 합계 >= {MIN_REVIEWS} 적용 후: {len(d):,}개")
    d = d[d["hours"] > 0]
    log(f"평균 플레이 시간 > 0 적용 후: {len(d):,}개")

    if len(d) < 30:
        sys.exit("분석 대상이 너무 적습니다. 열 이름·단위를 확인하세요.")

    # 원자료(분석에 쓴 게임만)를 파일로 남긴다. 건수는 위의 최종 표본 수와 같아야 한다.
    keep = [c for c in ["appid", "name", "release_date", "price", "average_playtime_forever",
                        "positive", "negative", "genres"] if c in d.columns]
    sample = d[keep].copy()
    sample["average_playtime_hours"] = d["hours"]
    if "genres" in sample.columns:
        sample["genres"] = sample["genres"].apply(lambda v: ",".join(genre_list(v)))
    sample.to_csv("analysis_sample.csv", index=False, encoding="utf-8-sig")
    assert len(sample) == len(d)
    h = hashlib.sha256()
    with open(SRC["path"], "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    log(f"원본 파일 SHA-256: {h.hexdigest()}")
    log(f"analysis_sample.csv 저장: {len(sample):,}행 (표본 수와 일치)")

    log()
    log("== 전체 상관 ==")
    r, p = rho_p(d["price"], d["hours"])
    log(f"스피어만 상관계수 rho = {r:.3f}, 유의확률 p = {p:.3g}, n = {len(d):,}")
    if r > 0 and p < ALPHA:
        verdict = "가설 지지: 가격이 높을수록 평균 플레이 시간이 길다 (효과 크기는 rho 로 해석)"
    else:
        verdict = "가설 기각: 상관이 양(+)이 아니거나 유의하지 않다"
    log(f"판정: {verdict}")
    log("효과 크기 참고(관례): |rho| 0.1 약함, 0.3 중간, 0.5 강함")

    log()
    log("== 가격대별 평균 플레이 시간 (시간) ==")
    d["price_bin"] = pd.cut(d["price"], bins=PRICE_BINS, labels=PRICE_LABELS, right=True)
    tab = d.groupby("price_bin", observed=True)["hours"].agg(["count", "median", "mean"]).round(2)
    log(tab.to_string())
    tab.to_csv("bin_table.csv", encoding="utf-8-sig")

    gen_rows = []
    if "genres" in d.columns:
        e = d[["price", "hours", "genres"]].copy()
        e["genre"] = e["genres"].apply(genre_list)
        e = e.explode("genre").dropna(subset=["genre"])
        top = e["genre"].value_counts().head(TOP_GENRES).index
        log()
        log(f"== 상위 {TOP_GENRES}개 장르별 상관 ==")
        for g in top:
            sub = e[e["genre"] == g]
            gr, gp = rho_p(sub["price"], sub["hours"])
            gen_rows.append({"genre": g, "n": len(sub), "rho": round(gr, 3), "p": gp})
            log(f"{g}: rho = {gr:.3f}, p = {gp:.3g}, n = {len(sub):,}")
        pd.DataFrame(gen_rows).to_csv("genre_table.csv", index=False, encoding="utf-8-sig")

    fig, ax = plt.subplots(1, 2, figsize=(11, 4))
    ax[0].scatter(d["price"], d["hours"], s=4, alpha=0.25)
    ax[0].set_xscale("log")
    ax[0].set_yscale("log")
    ax[0].set_xlabel("Price (USD, log)")
    ax[0].set_ylabel("Average playtime (hours, log)")
    ax[0].set_title(f"Spearman rho = {r:.2f}")
    groups = [d.loc[d["price_bin"] == b, "hours"] for b in PRICE_LABELS]
    ax[1].boxplot(groups, tick_labels=PRICE_LABELS, showfliers=False)
    ax[1].set_xlabel("Price bin (USD)")
    ax[1].set_ylabel("Average playtime (hours)")
    ax[1].set_title("Playtime by price bin (outliers hidden)")
    fig.tight_layout()
    fig.savefig("result.png", dpi=150)

    with open("results_summary.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    log()
    log("저장: results_summary.txt, bin_table.csv, genre_table.csv, result.png, analysis_sample.csv")


if __name__ == "__main__":
    main()
