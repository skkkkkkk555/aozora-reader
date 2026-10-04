#!/usr/bin/env python3
import csv
import io
import json
import re
import urllib.request
import zipfile
from pathlib import Path

SOURCE = "https://www.aozora.gr.jp/index_pages/list_person_all_extended_utf8.zip"
OUT = Path("catalog.json")

def text(v):
    return (v or "").strip()

def make_text_path(url: str) -> str:
    # Keep the same compact path format expected by the web app.
    path = url.split("://", 1)[-1]
    path = re.sub(r"^[^/]+/", "", path)
    path = re.sub(r"\.zip$", "", path, flags=re.I)
    m = re.search(r"([^/]+)$", path)
    if m:
        leaf = m.group(1)
        path = path[:m.start(1)] + leaf + "/" + leaf + ".txt"
    path = path.lstrip("/")
    path = re.sub(r"\.{2,}", "", path)
    path = path.replace("\\", "")
    return path

def main():
    req = urllib.request.Request(
        SOURCE,
        headers={"User-Agent": "aozora-reader-catalog/1.0"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()

    with zipfile.ZipFile(io.BytesIO(data)) as z:
        name = next(
            (n for n in z.namelist()
             if n.lower().endswith("list_person_all_extended_utf8.csv")),
            None,
        )
        if not name:
            raise RuntimeError("catalog CSV not found in ZIP")
        raw = z.read(name).decode("utf-8-sig")

    reader = csv.DictReader(io.StringIO(raw))
    works = {}
    for row in reader:
        wid = text(row.get("作品ID"))
        title = text(row.get("作品名"))
        url = text(row.get("テキストファイルURL"))
        if not wid or not title or not url:
            continue
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,80}", wid):
            continue
        if not url.startswith("https://www.aozora.gr.jp/") or not url.lower().endswith(".zip"):
            continue

        author = " ".join(x for x in (text(row.get("姓")), text(row.get("名"))) if x)
        item = works.get(wid)
        if item is None:
            rights = text(row.get("作品著作権フラグ"))
            item = {
                "id": wid,
                "t": title,
                "a": author,
                "tk": text(row.get("作品名読み")).lower(),
                "ak": text(row.get("姓読み")).lower(),
                "d": text(row.get("公開日")),
                "k": 1 if "新字新仮名" in text(row.get("文字遣い種別")) else 0,
                "c": 1 if rights in {"なし", "1", "1.0"} else 0,
                "ndc": text(row.get("分類番号")),
                "norm": re.sub(r"[\s　]", "", " ".join([
                    title,
                    text(row.get("作品名読み")),
                    author,
                    text(row.get("姓読み")),
                ])).lower(),
                "x": make_text_path(url),
            }
            works[wid] = item
        elif author and author not in item["a"].split("・"):
            item["a"] += "・" + author

    result = list(works.values())
    result = [
        x for x in result
        if x["t"] and x["x"] and re.fullmatch(r"[A-Za-z0-9._/:-]+", x["x"])
    ]
    if len(result) < 1000:
        raise RuntimeError(f"catalog unexpectedly small: {len(result)}")

    OUT.write_text(
        json.dumps(result, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    print(f"generated {OUT}: {len(result)} works")

if __name__ == "__main__":
    main()
