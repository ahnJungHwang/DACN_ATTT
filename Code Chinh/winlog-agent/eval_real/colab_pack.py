"""
Đóng gói ca + code để chạy Qwen / Llama trên Google Colab (md/THIET_KE_TEST_TOAN_BO_LOG_25112026.md, mục 7b).

- Ca lam_full_* (log thật của thành viên nhóm) được ẨN DANH thêm trước khi rời máy:
  tên tài khoản -> USER01, USER02... (thay ở MỌI chỗ trong XML, kể cả trong script / dòng lệnh),
  SID S-1-5-21-a-b-c-RID -> S-1-5-21-0-0-0-RID (giữ RID: 500 = Administrator dựng sẵn).
  Giữ nguyên tài khoản hệ thống / dựng sẵn / tên nhóm để luật vẫn chạy đúng.
- Ca tấn công <id>_full là dữ liệu công khai (DeepBlueCLI, EVTX-to-MITRE) -> chép nguyên.
- KHÔNG đưa evtx, bảng đổi tên (_anon_map.json chỉ ở máy), .env, khoá.

Cách chạy:  .venv\\Scripts\\python.exe eval_real\\colab_pack.py
"""
import json
import re
import sys
import zipfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "core"))
import analyze as A  # noqa: E402

CASES = HERE / "cases"
XML_FILES = ("security.xml", "powershell.xml", "system.xml")
NAME_FIELDS = ("TargetUserName", "SubjectUserName", "MemberName", "SamAccountName", "Workstation", "WorkstationName")
SID_FIELDS = {"TargetUserName": ("TargetUserSid", "TargetSid"), "SubjectUserName": ("SubjectUserSid",),
              "MemberName": ("MemberSid",)}
KEEP_NAMES = {
    "", "-", "system", "local service", "network service", "anonymous logon", "administrator", "guest",
    "defaultaccount", "wdagutilityaccount", "lab-pc02", "labuser", "localhost",
    "administrators", "users", "guests", "remote desktop users", "power users", "backup operators",
    "event log readers", "performance log users", "performance monitor users", "distributed com users",
    "hyper-v administrators", "device owners", "iis_iusrs", "remote management users", "access control assistance operators",
}
DATA = re.compile(r"<Data Name=['\"]([^'\"]+)['\"]>([^<]*)</Data>")
EVENT = re.compile(r"<Event[ >].*?</Event>", re.S)
DOMAIN_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+-(\d+)")
CODE_FILES = ("core/analyze.py", "core/rule_baselines.py", "eval_real/run_combined_eval.py", "eval_real/run_eval.py",
              "eval_real/compare_runs.py", "eval_real/dev_review.py",
              "eval_real/labels.json", "eval_real/colab_run.ipynb", "requirements.txt")


def _skip(name: str, sid: str) -> bool:
    n = name.strip().lower()
    return (n in KEEP_NAMES or n.endswith("$") or n.startswith(("dwm-", "umfd-", "font driver host"))
            or sid.startswith(("S-1-5-32-", "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-90-", "S-1-5-96-")))


def build_name_map(case_dirs: list[Path]) -> dict[str, str]:
    """Tên tài khoản thật trong các ca -> USER01, USER02... (theo thứ tự chữ cái, không phân biệt hoa thường)."""
    names = set()
    for d in case_dirs:
        for f in XML_FILES:
            p = Path(d) / f
            if not p.is_file():
                continue
            for event in EVENT.findall(p.read_text(encoding="utf-8-sig")):
                fields = dict(DATA.findall(event))
                for key in NAME_FIELDS:
                    value = fields.get(key, "")
                    sid = next((fields[k] for k in SID_FIELDS.get(key, ()) if fields.get(k)), "")
                    if value and not _skip(value, sid):
                        names.add(value.strip().lower())
    return {n: f"USER{i:02d}" for i, n in enumerate(sorted(names), start=1)}


UNNAMED = re.compile(r"<Data>([^<]*)</Data>")


def keep_read_fields(text: str) -> str:
    """Chỉ giữ trường analyze.read_events đọc (FIELDS | NEW_FIELDS; <Data> không tên của 400/800: dòng HostApplication= /
    CommandLine=) -> mô hình và luật thấy y như cũ, các trường khác của log không rời máy."""
    allowed = A.FIELDS | A.NEW_FIELDS
    text = DATA.sub(lambda m: m.group(0) if m.group(1) in allowed else "", text)
    return UNNAMED.sub(lambda m: "<Data>" + "".join(f"\t{n}={v}\r\n" for n, v in A.CLASSIC_PS_FIELD.findall(m.group(1)))
                       + "</Data>", text)


def anonymize_xml(text: str, names: dict[str, str]) -> str:
    """Thay mọi lần xuất hiện của tên (ranh giới từ, không phân biệt hoa thường) và phần định danh máy trong SID."""
    for name in sorted(names, key=len, reverse=True):  # tên dài trước để không thay nửa chừng
        text = re.sub(rf"(?<![\w]){re.escape(name)}(?![\w])", names[name], text, flags=re.IGNORECASE)
    return DOMAIN_SID.sub(r"S-1-5-21-0-0-0-\1", text)


def main() -> None:
    lam = sorted(d for d in CASES.glob("lam_full_*") if d.is_dir())
    labels = json.loads((HERE / "labels.json").read_text(encoding="utf-8"))
    attack = [CASES / (c["case_id"] + "_full") for c in labels["cases"]]
    attack = [d for d in attack if all((d / f).is_file() for f in (*XML_FILES, "manifest.json"))]
    if not lam:
        sys.exit("Chưa có ca lam_full_* (chạy build_normal_cases.ps1 -IdSet Full)")
    names = build_name_map(lam)
    (CASES / "_anon_map.json").write_text(json.dumps(names, ensure_ascii=False, indent=1), encoding="utf-8")

    out = HERE / "colab_pack.zip"
    extra = [p for p in (HERE / "dev_round2.txt",) if p.is_file()]
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for d in lam:
            for f in (*XML_FILES, "manifest.json"):
                p = d / f
                if p.is_file():
                    z.writestr(f"winlog-agent/eval_real/cases/{d.name}/{f}",
                               anonymize_xml(keep_read_fields(p.read_text(encoding="utf-8-sig")), names))
        for d in attack:
            for f in (*XML_FILES, "manifest.json"):
                z.write(d / f, f"winlog-agent/eval_real/cases/{d.name}/{f}")
        for rel in CODE_FILES:
            z.write(ROOT / rel, f"winlog-agent/{rel}")
        for p in extra:
            z.write(p, f"winlog-agent/eval_real/{p.name}")
    bad = [n for n in zipfile.ZipFile(out).namelist()
           if n.endswith((".evtx", ".pem", ".env")) or "_anon_map" in n]
    if bad:
        out.unlink()
        sys.exit(f"Gói chứa file không được phép: {bad}")
    print(f"{out} ({out.stat().st_size / 1e6:.1f} MB): {len(lam)} ca bình thường (ẩn danh {len(names)} tên), "
          f"{len(attack)} ca tấn công, {len(CODE_FILES) + len(extra)} file code")


if __name__ == "__main__":
    main()
