"""
Tạo bộ kiểm thử MÙ (blind test) từ các ca có nhãn.

- Đổi tên thư mục ca thành mã ngẫu nhiên B001..B0NN (xáo trộn thứ tự).
- Bỏ manifest.json (nhãn, mô tả, expected_stages) khỏi bộ mù.
- Ẩn danh hóa các chuỗi "lộ đáp án" bên trong log: tên user, tên máy,
  tên miền C2, tên file kiểu backdoor.exe / steal_token.ps1...
  KHÔNG sửa lệnh/hành vi (net user /add, DownloadString, mimikatz, -enc...).
- Kiểm chứng: bộ luật tương quan cho kết quả y hệt trước và sau khi ẩn danh.
- Ghi đáp án ra answer_key.csv NẰM NGOÀI thư mục bộ mù (không chép vào máy ảo).

Ví dụ:
    .venv\\Scripts\\python.exe blind_test\\make_blind_set.py
    .venv\\Scripts\\python.exe blind_test\\make_blind_set.py --src data01 --seed 2026
"""
import argparse
import csv
import json
import random
import re
import shutil
import sys
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "core"))  # analyze.py nằm trong core/

from analyze import correlate_security_events, is_benign_noise, read_events  # noqa: E402

# Tài khoản/nhóm có sẵn của Windows: giữ nguyên vì mang ý nghĩa thật (Guest bị dò, SYSTEM...)
BUILTIN_ACCOUNTS = {
    "", "-", "system", "administrator", "administrators", "guest", "root",
    "local service", "network service", "defaultaccount", "wdagutilityaccount",
    "anonymous logon",
}
# Tên miền hợp lệ, không lộ đáp án
DOMAIN_ALLOWLIST = {
    "schemas.microsoft.com", "github.com", "portal.office.com", "www.w3.org",
}
# Từ "lộ đáp án" trong tên file / mật khẩu / tham số
LEAK_WORDS = [
    "evil", "malware", "malicious", "hack", "backdoor", "attacker", "victim",
    "shadow", "steal", "implant", "payload", "exploit", "threat", "compromised",
    "beacon", "reverse", "meterpreter", "hijack", "typo", "nhanvien",
]
# Từ khóa hành vi mà bộ luật/AI cần thấy: tuyệt đối không đụng tới
PROTECTED_KEYWORDS = ["mimikatz", "downloadstring", "encodedcommand", "iex", "http"]

DATA_RE = re.compile(r"(<Data Name='[^']*'>)([^<]*)(</Data>)")
COMPUTER_RE = re.compile(r"(<Computer>)([^<]*)(</Computer>)")
USER_FIELD_RE = re.compile(r"<Data Name='(?:TargetUserName|SubjectUserName)'>([^<]*)</Data>")
NET_USER_RE = re.compile(r"\bnet1? user ([^\s<'\"/]+)", re.IGNORECASE)
WORKSTATION_RE = re.compile(r"<Data Name='WorkstationName'>([^<]*)</Data>")
URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9.-]+)")
IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
LEAK_TOKEN_RE = re.compile(
    r"(?<![\w-])[\w-]*(?:%s)[\w-]*(?![\w-])" % "|".join(LEAK_WORDS), re.IGNORECASE
)


def find_cases(src: Path) -> list[dict]:
    cases = []
    for d in sorted(src.iterdir()):
        manifest = d / "manifest.json"
        if not (d.is_dir() and (d / "security.xml").is_file()
                and (d / "powershell.xml").is_file() and manifest.is_file()):
            continue
        meta = json.loads(manifest.read_text(encoding="utf-8"))
        gt = str(meta.get("ground_truth", "")).upper()
        if gt not in ("ALERT", "NORMAL"):
            print(f"[!] Bỏ qua {d.name}: manifest không có ground_truth ALERT/NORMAL")
            continue
        cases.append({"dir": d, "case_id": d.name, "meta": meta, "ground_truth": gt})
    return cases


def word_pattern(token: str) -> re.Pattern:
    return re.compile(r"(?<![\w.-])" + re.escape(token) + r"(?![\w-])")


def build_mapping(cases: list[dict], rng: random.Random) -> dict:
    users, hosts, domains = set(), set(), set()
    for c in cases:
        for name in ("security.xml", "powershell.xml"):
            text = (c["dir"] / name).read_text(encoding="utf-8")
            users.update(USER_FIELD_RE.findall(text))
            users.update(NET_USER_RE.findall(text))
            hosts.update(WORKSTATION_RE.findall(text))
            for comp in COMPUTER_RE.findall(text):
                hosts.add(comp[1].split(".")[0])
            domains.update(URL_HOST_RE.findall(text))

    users = sorted(u for u in users if u.strip().lower() not in BUILTIN_ACCOUNTS
                   and not u.endswith("$"))
    hosts = sorted(h for h in hosts if h and h != "-")
    domains = sorted(d for d in domains
                     if d.lower() not in DOMAIN_ALLOWLIST and not IP_RE.fullmatch(d))

    def assign(items, fmt):
        shuffled = items[:]
        rng.shuffle(shuffled)
        return {item: fmt.format(i) for i, item in enumerate(shuffled, start=1)}

    return {
        "users": assign(users, "user{:02d}"),
        "hosts": assign(hosts, "WS-" + str(rng.randint(10, 99)) + "{:02d}"),
        "domains": assign(domains, "host{:02d}.net"),
        "tokens": {},  # điền dần khi gặp
    }


def anonymize_text(value: str, mapping: dict) -> str:
    # Thứ tự: tên miền -> tên máy -> user -> token lộ đáp án (dài trước, ngắn sau)
    for group in ("domains", "hosts", "users"):
        for old in sorted(mapping[group], key=len, reverse=True):
            value = word_pattern(old).sub(mapping[group][old], value)

    def repl(m: re.Match) -> str:
        token = m.group(0)
        low = token.lower()
        if any(k in low for k in PROTECTED_KEYWORDS):
            return token
        if low not in mapping["tokens"]:
            mapping["tokens"][low] = f"obj{len(mapping['tokens']) + 1:02d}"
        return mapping["tokens"][low]

    return LEAK_TOKEN_RE.sub(repl, value)


def anonymize_xml(xml: str, mapping: dict) -> str:
    def sub_text(m: re.Match) -> str:
        return m.group(1) + anonymize_text(m.group(2), mapping) + m.group(3)

    xml = DATA_RE.sub(sub_text, xml)
    return COMPUTER_RE.sub(sub_text, xml)


def rule_signature(case_dir: Path) -> tuple:
    events = read_events(case_dir)
    kept = [e for e in events if not is_benign_noise(e)] or events
    findings = correlate_security_events(kept)
    return (len(events), len(kept), tuple(findings["stages"]), tuple(findings["evidence_refs"]))


def main() -> int:
    parser = argparse.ArgumentParser(description="Tạo bộ kiểm thử mù từ các ca có nhãn.")
    parser.add_argument("--src", default="data01", help="Thư mục ca có nhãn (mặc định: data01)")
    parser.add_argument("--out", default="blind_test/blind_set",
                        help="Thư mục bộ mù để chép vào máy ảo")
    parser.add_argument("--key", default="blind_test/answer_key.csv",
                        help="File đáp án (GIỮ trên máy thật)")
    parser.add_argument("--seed", type=int, default=None, help="Seed xáo trộn (mặc định: ngẫu nhiên)")
    parser.add_argument("--no-anonymize", action="store_true",
                        help="Chỉ đổi tên thư mục + bỏ manifest, giữ nguyên nội dung log")
    parser.add_argument("--force", action="store_true", help="Ghi đè bộ mù cũ nếu đã tồn tại")
    args = parser.parse_args()

    src = (ROOT / args.src).resolve()
    out = (ROOT / args.out).resolve()
    key_path = (ROOT / args.key).resolve()

    if out == key_path.parent or out in key_path.parents:
        print("[x] File đáp án không được nằm trong thư mục bộ mù.")
        return 2
    if out.exists():
        if not args.force:
            print(f"[x] {out} đã tồn tại. Thêm --force để tạo lại (bộ cũ sẽ bị xóa).")
            return 2
        shutil.rmtree(out)

    cases = find_cases(src)
    if not cases:
        print(f"[x] Không tìm thấy ca hợp lệ trong {src}")
        return 2

    seed = args.seed if args.seed is not None else random.SystemRandom().randint(1, 10**9)
    rng = random.Random(seed)
    rng.shuffle(cases)
    mapping = build_mapping(cases, rng) if not args.no_anonymize else None

    out.mkdir(parents=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    rows, mismatches = [], []

    for i, c in enumerate(cases, start=1):
        blind_id = f"B{i:03d}"
        dst = out / blind_id
        dst.mkdir()
        for name in ("security.xml", "powershell.xml"):
            text = (c["dir"] / name).read_text(encoding="utf-8")
            if mapping is not None:
                text = anonymize_xml(text, mapping)
            (dst / name).write_text(text, encoding="utf-8")

        if rule_signature(c["dir"]) != rule_signature(dst):
            mismatches.append(f"{blind_id} ({c['case_id']})")

        rows.append({
            "blind_id": blind_id,
            "case_id": c["case_id"],
            "category": c["meta"].get("category", ""),
            "ground_truth": c["ground_truth"],
            "expected_stages": "; ".join(c["meta"].get("expected_stages", [])),
            "actions": c["meta"].get("actions", ""),
        })

    with key_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    info = {"seed": seed, "source": str(src), "anonymized": mapping is not None,
            "count": len(rows)}
    if mapping is not None:
        info["mapping"] = mapping
    map_path = key_path.with_name("anonymization_map.json")
    map_path.write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")

    n_alert = sum(r["ground_truth"] == "ALERT" for r in rows)
    print(f"[OK] Đã tạo {len(rows)} ca mù ({n_alert} ALERT / {len(rows) - n_alert} NORMAL) tại: {out}")
    print(f"[OK] Đáp án   : {key_path}")
    print(f"[OK] Bảng đổi tên + seed: {map_path}  (seed = {seed})")
    if mapping is not None:
        print(f"     Đã ẩn danh: {len(mapping['users'])} user, {len(mapping['hosts'])} tên máy, "
              f"{len(mapping['domains'])} tên miền, {len(mapping['tokens'])} token lộ đáp án")

    if mismatches:
        print("[x] CẢNH BÁO: bộ luật cho kết quả KHÁC sau khi ẩn danh ở các ca:")
        for m in mismatches:
            print("     -", m)
        return 1
    print("[OK] Kiểm chứng: bộ luật cho kết quả giống hệt trước/sau ẩn danh ở tất cả các ca.")
    print()
    print(">>> Chỉ chép thư mục bộ mù + replay_blind.ps1 vào máy ảo. KHÔNG chép answer_key.csv.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
