"""Gom nhãn của từng ca kiểm thử thành MỘT file CSV: <thư mục dữ liệu>/labels.csv.

Nhãn gốc vẫn nằm trong manifest.json của từng ca; file CSV chỉ là bản tổng hợp để đọc/nộp.

    .venv\\Scripts\\python.exe core\\export_labels.py data01 data100 data_normal_heavy
"""
import csv
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
FIELDS = ["case_id", "ground_truth", "category", "expected_stages", "sources",
          "security_count", "powershell_count", "actions"]


def export(data_dir: Path) -> None:
    rows = []
    for mf in sorted(data_dir.glob("*/manifest.json")):
        m = json.loads(mf.read_text(encoding="utf-8-sig"))
        m["case_id"] = m.get("case_id") or mf.parent.name
        for k in ("expected_stages", "sources"):
            m[k] = "; ".join(m.get(k) or [])
        rows.append(m)
    out = data_dir / "labels.csv"
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    n_alert = sum(r.get("ground_truth") == "ALERT" for r in rows)
    print(f"{out.relative_to(BASE)}: {len(rows)} ca ({n_alert} ALERT, {len(rows) - n_alert} khác)")


if __name__ == "__main__":
    for name in sys.argv[1:] or ["data01"]:
        export(BASE / name)
