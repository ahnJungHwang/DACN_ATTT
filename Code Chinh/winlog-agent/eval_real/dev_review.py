"""
In lý do Qwen / Llama báo ALERT / UNKNOWN / REVIEW ở các ca của một lượt chạy (dùng ở giai đoạn chỉnh dev).
Đọc CSV kết quả + file JSON mới nhất trong results/<ca>/<model>_*.json (analyze_case tự ghi).
Chỉ in mã sự kiện + vài trường ngắn, không in toàn văn script.

Cách chạy (Colab):  python eval_real/dev_review.py /content/drive/MyDrive/DACN_colab/combined_results_full_dev1.csv
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHOW = ("CallerProcessName", "TargetUserName", "SubjectUserName", "NewProcessName", "CommandLine", "HostApplication",
        "PrivilegeList", "SchemaFriendlyName", "LogonType", "IpAddress", "ProcessName")


def short(event: dict) -> str:
    d = event.get("data", {})
    parts = [f"{k}={str(d[k])[:90]}" for k in SHOW if d.get(k)]
    if d.get("ScriptBlockText"):
        parts.append("Script=" + " ".join(d["ScriptBlockText"].split())[:160])
    return f"{event.get('event_ref', '?')} {event['event_id']}: " + "; ".join(parts)


def main(csv_path: str) -> None:
    rows = [r for r in csv.DictReader(open(csv_path, encoding="utf-8"))
            if r.get("pred") in ("ALERT", "UNKNOWN", "REVIEW") and r["tool"] in ("qwen", "llama")]
    print(f"{len(rows)} dòng cần xem")
    for r in rows:
        files = sorted((ROOT / "results" / r["case_id"]).glob(f"{r['tool']}_*.json"))
        if not files:
            print(f"\n=== {r['tool']} {r['case_id']} {r['pred']}: không có JSON")
            continue
        doc = json.loads(files[-1].read_text(encoding="utf-8"))
        v = doc["result"]["verdict"]
        by_ref = {e.get("event_ref"): e for e in doc.get("events", [])}
        print(f"\n=== {r['tool']} {r['case_id']} {r['pred']} (nguồn {v.get('decision_source')}, rủi ro {v.get('risk_score')})")
        print("  giai đoạn:", "; ".join(v.get("detected_stages", [])) or "-")
        print("  lý do:", " ".join(str(v.get("reason", "")).split())[:500])
        for b in doc["result"].get("batch_results", []):
            so = b.get("second_opinion")
            if b["verdict"]["label"] != "NORMAL" or so:
                print(f"  lô {b['batch']}: {b['verdict']['label']} | {' '.join(b['verdict'].get('reason', '').split())[:200]}"
                      + (f" | thẩm định: {so}" if so else ""))
        for ref in v.get("evidence_refs", [])[:6]:
            if ref in by_ref:
                print("   ", short(by_ref[ref]))


if __name__ == "__main__":
    main(sys.argv[1])
