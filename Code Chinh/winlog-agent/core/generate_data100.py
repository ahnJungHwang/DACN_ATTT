"""
Sinh ngẫu nhiên bộ kiểm thử lớn (mặc định 100 ca) cho đánh giá Ollama.

Nguyên tắc:
- KHÔNG tự chế payload mới. Generator chỉ ĐỌC các khối sự kiện có sẵn rồi lắp ghép:
    * attack fragment : các ca ALERT trong data01/ + fragment EVTX thật (data100_fragments/evtx)
    * benign fragment : các ca NORMAL trong data01/ + log thật của client (results/client_*_live)
- Mỗi ca TUNG ĐỒNG XU (p=0.5) để quyết định ALERT hay NORMAL.
    * NORMAL : ghép 1-2 khối lành tính.
    * ALERT  : lấy nền lành tính rồi CHÈN 1-3 khối tấn công vào vị trí ngẫu nhiên.
- Ngẫu nhiên hóa danh tính (user/host/IP), mốc thời gian, RecordID để không ca nào trùng chữ.
  Giữ nguyên CommandLine / ScriptBlockText (đó là hành vi cần phát hiện).
- Nhãn đúng do CẤU TRÚC SINH quyết định (có chèn tấn công hay không), không phụ thuộc
  luật hay AI có bắt được hay không -> vẫn chấm điểm khách quan.
- Seed ngẫu nhiên mỗi lần chạy nhưng được GHI LẠI (manifest + _generation_info.json) để tái lập.

Ví dụ:
    .venv\\Scripts\\python.exe core\\generate_data100.py                 # 100 ca, seed ngẫu nhiên
    .venv\\Scripts\\python.exe core\\generate_data100.py --count 120 --seed 2026
    .venv\\Scripts\\python.exe core\\generate_data100.py --clean
"""
import argparse
import glob
import hashlib
import json
import random
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BASE = Path(__file__).resolve().parent.parent  # thư mục gốc winlog-agent (file này ở core/)
sys.path.insert(0, str(BASE))

from analyze import read_events, correlate_security_events, is_benign_noise  # noqa: E402
from generate_data01 import (  # noqa: E402  (tái sử dụng builder, không viết payload mới)
    create_security_event_xml,
    create_powershell_event_xml,
    format_win_time,
)

TARGET_DIR = BASE / "data100"
XML_HEADER, XML_FOOTER = "<Events>", "</Events>"

# Tài khoản/nhóm dựng sẵn của Windows: giữ nguyên (mang ý nghĩa thật)
BUILTIN = {
    "", "-", "system", "administrator", "administrators", "guest", "root",
    "local service", "network service", "defaultaccount", "anonymous logon",
}
# Dấu vết các lần chạy demo -> loại khỏi kho log nền "bình thường"
DEMO_ARTIFACTS = [
    "hacker_soc_test", "victim_boss", "fake_victim", "apt_admin", "apt-c2",
    "c2-malicious", "securityupdateagent", "mimikatz", "downloadstring",
]


# Từ khóa hành vi tấn công — dùng để LỌC NHÃN (labeling bảo thủ), không phải để chấm điểm
ATTACK_KEYWORDS = [
    "/add", "net user", "net localgroup", "downloadstring", "-enc", "encodedcommand",
    "mimikatz", "iex", "invoke-expression", "frombase64string", "-nop", "-w hidden",
    "procdump", "lsass", "currentversion\\run", "schtasks", "wevtutil", "bitsadmin",
    "certutil", "reg add", "disablerealtimemonitoring",
]


def looks_attacky(events: list[dict]) -> bool:
    """Bảo thủ: coi là CÓ dấu hiệu tấn công nếu luật bắt được HOẶC có từ khóa/nhiều lần 4625.

    Dùng để loại fragment khỏi kho 'bình thường' và để kiểm tra lại ca NORMAL sau khi lắp,
    nhằm tránh gán nhãn NORMAL cho log vốn chứa hành vi độc hại (log client thật có lẫn demo).
    """
    kept = [e for e in events if not is_benign_noise(e)] or events
    if correlate_security_events(kept)["stages"]:
        return True
    if sum(1 for e in events if e.get("event_id") == 4625) >= 3:
        return True
    for e in events:
        d = e.get("data", {})
        blob = (d.get("CommandLine", "") + " " + d.get("ScriptBlockText", "")).lower()
        if any(k in blob for k in ATTACK_KEYWORDS):
            return True
    return False


# ---------------------------------------------------------------------------
# Tải kho fragment
# ---------------------------------------------------------------------------
def load_dir_fragments(pattern: str) -> list[dict]:
    frags = []
    for d in sorted(glob.glob(pattern)):
        p = Path(d)
        try:
            events = read_events(p)
        except Exception:
            continue
        if events:
            frags.append({"name": p.name, "events": events})
    return frags


def load_live_benign(results_glob: str, min_ev: int, max_ev: int) -> list[dict]:
    frags, seen = [], set()
    for f in sorted(glob.glob(results_glob)):
        try:
            d = json.loads(Path(f).read_text(encoding="utf-8"))
        except Exception:
            continue
        events = d.get("events", [])
        if not (min_ev <= len(events) <= max_ev):
            continue
        blob = json.dumps(events, ensure_ascii=False).lower()
        if any(k in blob for k in DEMO_ARTIFACTS):
            continue
        if looks_attacky(events):          # lọc bảo thủ: bỏ log nền có dấu hiệu tấn công
            continue
        h = hashlib.md5(blob.encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        frags.append({"name": Path(f).stem, "events": events})
    return frags


# ---------------------------------------------------------------------------
# Lắp ráp một ca
# ---------------------------------------------------------------------------
def rand_identity(rng: random.Random) -> dict:
    return {
        "user": f"user{rng.randint(1, 60):02d}",
        "host": f"WS-{rng.randint(1000, 9999)}.corp.local",
        "ip": rng.choice([
            f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(2,254)}",
            f"192.168.{rng.randint(0,255)}.{rng.randint(2,254)}",
            f"172.16.{rng.randint(0,255)}.{rng.randint(2,254)}",
        ]),
    }


def event_to_xml(event: dict, time_str: str, rid: int, ident: dict, rng: random.Random) -> tuple[str, bool]:
    """Dựng lại 1 event thành XML, đổi danh tính + thời gian + RecordID. Trả (xml, is_ps)."""
    eid = event["event_id"]
    data = dict(event.get("data", {}))

    # Đổi danh tính ở các trường định danh, KHÔNG đụng CommandLine/ScriptBlockText
    for field in ("TargetUserName", "SubjectUserName"):
        v = data.get(field, "")
        if v and v.strip().lower() not in BUILTIN and not v.endswith("$"):
            data[field] = ident["user"]
    if data.get("IpAddress", "-") not in ("-", "", "127.0.0.1", "::1"):
        data["IpAddress"] = ident["ip"]
    if data.get("WorkstationName"):
        data["WorkstationName"] = ident["host"].split(".")[0]

    if eid == 4104:
        return create_powershell_event_xml(
            data.get("ScriptBlockText", ""), time_str, rid, computer=ident["host"]
        ), True
    return create_security_event_xml(eid, time_str, rid, data, computer=ident["host"]), False


def assemble_case(ordered_events: list[dict], rng: random.Random) -> tuple[list[str], list[str]]:
    """Gán thời gian tăng dần + RecordID + danh tính rồi dựng XML."""
    ident = rand_identity(rng)
    base = datetime(2026, rng.randint(1, 11), rng.randint(1, 28),
                    rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59),
                    tzinfo=timezone.utc)
    sec_xml, ps_xml = [], []
    t = base
    rid = rng.randint(1000, 90000)
    for ev in ordered_events:
        t += timedelta(seconds=rng.randint(1, 45))
        rid += rng.randint(1, 40)
        xml, is_ps = event_to_xml(ev, format_win_time(t), rid, ident, rng)
        (ps_xml if is_ps else sec_xml).append(xml)
    return sec_xml, ps_xml


def interleave(benign: list[dict], attack: list[dict], rng: random.Random) -> list[dict]:
    """Chèn chuỗi tấn công vào vị trí ngẫu nhiên trong log nền, giữ thứ tự nội bộ mỗi khối."""
    if not benign:
        return list(attack)
    pos = rng.randint(0, len(benign))
    return benign[:pos] + list(attack) + benign[pos:]


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Sinh ngẫu nhiên bộ kiểm thử lớn cho Ollama.")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--seed", type=int, default=None, help="Mặc định: ngẫu nhiên (được ghi lại)")
    ap.add_argument("--p-alert", type=float, default=0.5, help="Xác suất coin-flip ra ALERT (mặc định 0.5)")
    ap.add_argument("--out", default="data100")
    ap.add_argument("--clean", action="store_true", help="Xóa data100/ rồi thoát")
    args = ap.parse_args()

    out = (BASE / args.out) if not Path(args.out).is_absolute() else Path(args.out)
    if args.clean:
        if out.exists():
            shutil.rmtree(out)
            print(f"[OK] Đã xóa {out}")
        return 0

    seed = args.seed if args.seed is not None else random.SystemRandom().randint(1, 10**9)
    rng = random.Random(seed)

    # Kho fragment
    attack_d01 = [f for f in load_dir_fragments(str(BASE / "data01" / "case_attack_*"))]
    attack_d01 += load_dir_fragments(str(BASE / "data01" / "case_mixed_*"))
    # Quét MỌI thư mục con trong data100_fragments/ (mỗi dataset trích riêng vào 1 thư mục:
    # vd data100_fragments/evtx, data100_fragments/deepblue). Origin = tên thư mục dataset.
    frag_root = BASE / "data100_fragments"
    attack_evtx = []
    if frag_root.is_dir():
        for ds in sorted(p for p in frag_root.iterdir() if p.is_dir()):
            for f in load_dir_fragments(str(ds / "*")):
                attack_evtx.append({**f, "origin": ds.name})
    benign_d01 = load_dir_fragments(str(BASE / "data01" / "case_normal_*"))
    benign_live = load_live_benign(str(BASE / "results" / "client_*_live" / "*.json"),
                                   min_ev=3, max_ev=80)

    attack_pool = [{**f, "origin": "data01"} for f in attack_d01] + \
                  [{**f, "origin": f.get("origin", "evtx")} for f in attack_evtx]
    benign_pool = [{**f, "origin": "data01"} for f in benign_d01] + \
                  [{**f, "origin": "live"} for f in benign_live]

    if not attack_pool or not benign_pool:
        print(f"[x] Thiếu fragment. attack={len(attack_pool)} benign={len(benign_pool)}")
        print("    Chạy extract_evtx_fragments.ps1 và kiểm tra results/client_*_live.")
        return 2

    import collections
    by_origin = collections.Counter(f["origin"] for f in attack_pool)
    print(f"[i] Seed = {seed}")
    print(f"[i] Kho attack : {len(attack_pool)}  (" +
          ", ".join(f"{k}={v}" for k, v in sorted(by_origin.items())) + ")")
    print(f"[i] Kho benign : {len(benign_d01)} (data01) + {len(benign_live)} (live) = {len(benign_pool)}")

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    n_alert = 0
    rows = []
    for i in range(1, args.count + 1):
        is_alert = rng.random() < args.p_alert
        gt = "ALERT" if is_alert else "NORMAL"

        sources = []
        if is_alert:
            benign_events = []
            for _ in range(rng.randint(1, 2)):
                benign_events += list(rng.choice(benign_pool)["events"])
            n_atk = rng.randint(1, 3)
            attack_events = []
            for _ in range(n_atk):
                frag = rng.choice(attack_pool)
                attack_events += list(frag["events"])
                sources.append(f"{frag['origin']}:{frag['name']}")
            # Đôi khi tấn công "trần" không nền, để có cả ca ngắn
            bg = benign_events if rng.random() < 0.8 else []
            ordered = interleave(bg, attack_events, rng)
            n_alert += 1
        else:
            # NORMAL: thử tối đa 8 lần cho tới khi ca sạch mọi dấu hiệu tấn công
            ordered = None
            for _ in range(8):
                cand = []
                for _ in range(rng.randint(1, 2)):
                    cand += list(rng.choice(benign_pool)["events"])
                if not looks_attacky(cand):
                    ordered = cand
                    break
            if ordered is None:                       # bí quá: dùng đúng 1 khối nền sạch nhất
                ordered = list(min(
                    (rng.choice(benign_pool)["events"] for _ in range(8)),
                    key=lambda ev: (looks_attacky(ev), len(ev)),
                ))
            sources = ["benign-background"]

        sec_xml, ps_xml = assemble_case(ordered, rng)
        if not sec_xml and not ps_xml:
            continue

        case_id = f"case_rnd_{i:03d}_{gt.lower()}"
        cdir = out / case_id
        cdir.mkdir()
        (cdir / "security.xml").write_text(XML_HEADER + "".join(sec_xml) + XML_FOOTER, encoding="utf-8")
        (cdir / "powershell.xml").write_text(XML_HEADER + "".join(ps_xml) + XML_FOOTER, encoding="utf-8")
        manifest = {
            "case_id": case_id,
            "category": "RandomMix",
            "ground_truth": gt,
            "actions": f"Ca sinh ngẫu nhiên (coin-flip). Nguồn khối: {', '.join(sources)}",
            "expected_stages": [],
            "sources": sources,
            "security_count": len(sec_xml),
            "powershell_count": len(ps_xml),
            "seed": seed,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        (cdir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        rows.append((case_id, gt, len(sec_xml), len(ps_xml), sources))

    info = {
        "seed": seed, "count": len(rows), "p_alert": args.p_alert,
        "n_alert": n_alert, "n_normal": len(rows) - n_alert,
        "attack_pool": len(attack_pool), "benign_pool": len(benign_pool),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (out / "_generation_info.json").write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")

    print("-" * 70)
    print(f"[OK] Đã sinh {len(rows)} ca tại {out}  ({n_alert} ALERT / {len(rows)-n_alert} NORMAL)")
    print(f"[OK] Thông tin tái lập: {out / '_generation_info.json'}  (seed = {seed})")
    print()
    print("Chạy đánh giá:")
    print(f"   .venv\\Scripts\\python.exe core\\evaluate.py --data-dir {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
