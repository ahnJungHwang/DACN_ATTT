"""
So 2 lượt chạy trên cùng các ca (vd lượt đã khoá full_test và một lượt chạy lại) để đo độ dao động của model.
25/11, 12 ca test: chạy lại y cách cũ lệch 1/24 nhãn; giữ model trong VRAM hoặc chạy 2 model song song lệch 2-3/24
nên không dùng cho số liệu.
- CSV: nhãn, nhãn AI, nguồn quyết định, điểm rủi ro, giai đoạn.
- JSON (results/<ca>/<model>_*.json): lời giải thích từng lô của file CŨ NHẤT so với file MỚI NHẤT. Giống hệt = model
  sinh đúng từng chữ như lượt gốc. Chỉ đúng khi file cũ nhất là của lượt gốc (ca test trên Colab: full_test chạy trước).

Colab: cd /content/winlog-agent && python eval_real/compare_runs.py <gốc.csv> <mới.csv>
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEYS = ("pred", "ai_only", "decision_source", "risk_score", "stages")


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return {(r["tool"], r["case_id"]): r for r in csv.DictReader(f) if r.get("pred")}


def compare(ref: dict, new: dict) -> list[str]:
    diffs = []
    for key, row in new.items():
        if key not in ref:
            diffs.append(f"{key[0]} {key[1]}: không có trong file gốc")
            continue
        changed = [f"{k}: {ref[key].get(k)!r} -> {row.get(k)!r}" for k in KEYS if ref[key].get(k) != row.get(k)]
        if changed:
            diffs.append(f"{key[0]} {key[1]}: " + "; ".join(changed))
    return diffs


def same_reasons(results_dir: Path, case_id: str, tool: str) -> bool | None:
    files = sorted((results_dir / case_id).glob(f"{tool}_*.json"))
    if len(files) < 2:
        return None

    def batches(p: Path) -> list:
        doc = json.loads(p.read_text(encoding="utf-8"))
        return [(b["verdict"].get("label"), b["verdict"].get("reason")) for b in doc["result"].get("batch_results", [])]

    return batches(files[0]) == batches(files[-1])


def main(ref_path: str, new_path: str) -> int:
    ref, new = load(ref_path), load(new_path)
    diffs = compare(ref, new)
    print(f"{len(new)} dòng so sánh, {len(diffs)} dòng khác ở CSV")
    for d in diffs:
        print("  ", d)
    texts = {k: same_reasons(ROOT / "results", k[1], k[0]) for k in new if new[k]["pred"] != "NOISE_ONLY"}
    checked = {k: v for k, v in texts.items() if v is not None}
    print(f"lời giải thích từng lô giống hệt: {sum(checked.values())}/{len(checked)}")
    for k, v in checked.items():
        if not v:
            print("   khác chữ:", k[0], k[1])
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
