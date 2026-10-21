"""사후 탐색 분석 (사전 기준에 없던 분석, 주 분석 결과를 바꾸지 않는다).

analyze.py 로 주 분석을 끝낸 뒤, 결과가 얼마나 단단한지와 가설과 다르게 보이는 부분의
이유 후보를 확인하려고 추가한 분석이다. 논문에서는 "사후 탐색"으로 표시하고,
주 분석의 판정(스피어만 0.306 등)은 그대로 둔다.

사용법: analyze.py 와 같은 폴더에서  python explore.py  (같은 .parquet 파일을 읽는다)
결과: explore_results.txt, explore_table.csv
"""
import numpy as np
import pandas as pd
from scipy.stats import rankdata, spearmanr

import analyze  # 같은 폴더의 analyze.py (load, genre_list 재사용)

out = []


def log(msg=""):
    print(msg)
    out.append(str(msg))


def base(df, min_reviews):
    d = df.copy()
    d["reviews"] = d["positive"].fillna(0) + d["negative"].fillna(0)
    d["hours"] = d["average_playtime_forever"] / analyze.MINUTES_PER_HOUR
    return d[(d["price"] > 0) & (d["reviews"] >= min_reviews) & (d["hours"] > 0)]


def rho(x, y):
    r, p = spearmanr(x, y)
    return float(r), float(p)


def partial_spearman(d, controls):
    """순위로 바꾼 뒤 통제 변수의 영향을 뺀 잔차끼리의 상관(편 스피어만 상관)."""
    x = rankdata(d["price"])
    y = rankdata(d["hours"])
    C = np.column_stack([np.ones(len(d))] + [rankdata(d[c]) for c in controls])
    rx = x - C @ np.linalg.lstsq(C, x, rcond=None)[0]
    ry = y - C @ np.linalg.lstsq(C, y, rcond=None)[0]
    return float(np.corrcoef(rx, ry)[0, 1])


def main():
    df = analyze.load()
    rows = []
    log("사후 탐색 분석 (주 분석 기준: 리뷰 100개 이상)")
    log()

    log("== A. 리뷰 수 기준을 바꿔 본 민감도 ==")
    for m in [1, 50, 100, 200, 500, 1000]:
        d = base(df, m)
        r, p = rho(d["price"], d["hours"])
        log(f"리뷰 >= {m}: rho = {r:.3f}, n = {len(d):,}")
        rows.append({"분석": "리뷰 기준", "구분": f">={m}", "n": len(d), "rho": round(r, 3)})

    d = base(df, 100)

    log()
    log("== B. 출시 시기별 상관 ==")
    if "release_date" in d.columns:
        d = d.copy()
        d["year"] = pd.to_datetime(d["release_date"], errors="coerce").dt.year
        dd = d.dropna(subset=["year"])
        bins = [(0, 2014, "~2014"), (2015, 2018, "2015~2018"), (2019, 2022, "2019~2022"), (2023, 9999, "2023~")]
        for lo, hi, name in bins:
            s = dd[(dd["year"] >= lo) & (dd["year"] <= hi)]
            if len(s) >= 30:
                r, p = rho(s["price"], s["hours"])
                log(f"{name}: rho = {r:.3f}, n = {len(s):,}")
                rows.append({"분석": "출시 시기", "구분": name, "n": len(s), "rho": round(r, 3)})
        log()
        log("== C. 출시 연도와 리뷰 수를 통제한 편 스피어만 상관 ==")
        dd = dd.assign(reviews=dd["reviews"])
        pr = partial_spearman(dd, ["year", "reviews"])
        log(f"편 상관(출시 연도, 리뷰 수 통제): {pr:.3f}, n = {len(dd):,}")
        rows.append({"분석": "편 상관", "구분": "출시 연도+리뷰 수 통제", "n": len(dd), "rho": round(pr, 3)})
    else:
        log("release_date 열이 없어 건너뜀")

    log()
    log("== D. 가격대 안의 흩어짐 (플레이 시간, 시간) ==")
    d["price_bin"] = pd.cut(d["price"], bins=analyze.PRICE_BINS, labels=analyze.PRICE_LABELS, right=True)
    q = d.groupby("price_bin", observed=True)["hours"].quantile([0.25, 0.5, 0.75]).unstack().round(2)
    q.columns = ["25%", "50%", "75%"]
    log(q.to_string())
    for b, r_ in q.iterrows():
        rows.append({"분석": "가격대 분위수", "구분": str(b), "n": "", "rho": f'{r_["25%"]}/{r_["50%"]}/{r_["75%"]}'})

    if "categories" in d.columns:
        log()
        log("== E. 멀티플레이 포함 여부별 상관 (categories 열에 'multi-player' 포함 여부) ==")
        cats = d["categories"].apply(lambda v: " ".join(analyze.genre_list(v)).lower())
        mp = cats.str.contains("multi-player")
        for name, mask in [("멀티플레이 포함", mp), ("멀티플레이 없음", ~mp)]:
            s = d[mask]
            if len(s) >= 30:
                r, p = rho(s["price"], s["hours"])
                log(f"{name}: rho = {r:.3f}, n = {len(s):,}")
                rows.append({"분석": "멀티플레이", "구분": name, "n": len(s), "rho": round(r, 3)})

    pd.DataFrame(rows).to_csv("explore_table.csv", index=False, encoding="utf-8-sig")
    with open("explore_results.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    log()
    log("저장: explore_results.txt, explore_table.csv")


if __name__ == "__main__":
    main()
