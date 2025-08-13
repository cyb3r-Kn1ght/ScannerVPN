#!/usr/bin/env python3
import argparse, subprocess, sys, json

SEV_ORDER = {"info":0, "low":1, "medium":2, "high":3, "critical":4}

def sev_ok(sev: str, min_sev: str) -> bool:
    s = (sev or "").lower()
    return SEV_ORDER.get(s, 0) >= SEV_ORDER.get(min_sev.lower(), 0)

def pick_json_flag():
    # Ưu tiên -jsonl (v3.x). Nếu không có thì fallback -json (rất cũ).
    try:
        h = subprocess.run(["nuclei", "-h"], capture_output=True, text=True).stdout
        if "-jsonl" in h or "--jsonl" in h:
            return "-jsonl"
        if "-json" in h or "--json" in h:
            return "-json"
    except Exception:
        pass
    return "-jsonl"

def build_cmd(args, json_flag):
    cmd = ["nuclei", json_flag, "-silent", "-nc"]  # -nc: no-color
    # target
    if args.list_file: cmd += ["-list", args.list_file]
    else:              cmd += ["-u", args.target]
    # templates/filters
    def add_multi(flag, val):
        for x in val.split(","):
            x = x.strip()
            if x: cmd.extend([flag, x])
    if args.templates:           add_multi("-t", args.templates)
    if args.workflows:           add_multi("-w", args.workflows)
    if args.tags:                cmd += ["-tags", args.tags]
    if args.severity:            cmd += ["-severity", args.severity]
    if args.exclude_templates:   cmd += ["-exclude-templates", args.exclude_templates]
    if args.exclude_tags:        cmd += ["-exclude-tags", args.exclude_tags]
    if args.exclude_severity:    cmd += ["-exclude-severity", args.exclude_severity]
    # perf
    if args.rate_limit:          cmd += ["-rl", str(args.rate_limit)]
    if args.concurrency:         cmd += ["-c", str(args.concurrency)]
    return cmd

# test nhanh
# docker run --rm nuclei-scan:dev `
#   --target http://testphp.vulnweb.com `
#   --templates /root/nuclei-templates/http `
#   --rate-limit 15 `
#   --concurrency 15 `
#   --compact `
#   --min-severity medium

# quét hết lỗi - khá lâu
# docker run --rm nuclei-scan:dev `
#   --target http://testphp.vulnweb.com `
#   --templates /root/nuclei-templates/http/vulnerabilities `
#   --severity medium,high,critical `
#   --rate-limit 8 `
#   --concurrency 8 | Select-Object -First 30

#scan 1 lỗ hổng cụ thể - xss
# docker run --rm nuclei-scan:dev `
#   --target http://testphp.vulnweb.com `
#   --tags xss `
#   --severity low,medium,high,critical `
#   --headless `
#   --rate-limit 8 `
#   --concurrency 8 `
#   --compact `
#   --min-severity low | Select-Object -First 30

# scan theo tag
# docker run --rm nuclei-scan:dev `
#   --target http://testphp.vulnweb.com `
#   --tags sqli,xss,cmdi `
#   --severity medium,high,critical `
#   --rate-limit 10 `
#   --concurrency 10 `
#   --compact `
#   --min-severity medium | Select-Object -First 30

# các kết quả có thể trống vì --min-severity không có mức info nên nếu muốn thêm thông tin thì có thể thay nó bằng info: ví dụ
# docker run --rm nuclei-scan:dev `
#   --target http://testphp.vulnweb.com `
#   --templates /root/nuclei-templates/http `
#   --rate-limit 15 `
#   --concurrency 15 `
#   --compact `
#   --min-severity info 

parser = argparse.ArgumentParser(description="Wrapper Nuclei -> JSONL (compact option)")
# Target
parser.add_argument("--target", help="URL/IP 1 mục tiêu")
parser.add_argument("--list-file", help="File danh sách mục tiêu, mỗi dòng 1 URL/IP")
# Templates / filter
parser.add_argument("--tags")
parser.add_argument("--severity")
parser.add_argument("--templates")
parser.add_argument("--workflows")
parser.add_argument("--exclude-templates")
parser.add_argument("--exclude-tags")
parser.add_argument("--exclude-severity")
# Hiệu năng
parser.add_argument("--rate-limit", type=int)
parser.add_argument("--concurrency", type=int)
# Output kiểm soát
parser.add_argument("--compact", action="store_true", help="In JSONL tối giản cho pentest")
parser.add_argument("--min-severity", default="info", help="Ngưỡng tối thiểu khi --compact (vd: medium)")
parser.add_argument("--strip-http", action="store_true", help="Bỏ request/response/curl-command trong output đầy đủ")
args = parser.parse_args()

if not args.target and not args.list_file:
    print(json.dumps({"error":"missing --target or --list-file"})); sys.exit(2)

json_flag = pick_json_flag()
cmd = build_cmd(args, json_flag)

# Chạy streaming, chỉ xử lý các dòng JSON hợp lệ
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

dedupe = set()  # chống trùng (id, matched-at)
err_text = []

try:
    for line in p.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            # bỏ qua dòng không phải JSON (bảng update index, banner…)
            continue

        # Tuỳ chọn lọc & tối giản
        if args.compact:
            info = rec.get("info", {}) or {}
            sev  = (info.get("severity") or "").lower()
            if not sev_ok(sev, args.min_severity):
                continue
            out = {
                "id": rec.get("template-id"),
                "name": info.get("name"),
                "sev": sev,
                "host": rec.get("host"),
                "url": rec.get("url"),
                "matched": rec.get("matched-at") or rec.get("url"),
            }
            # bằng chứng/evidence: extracted-results nếu có
            if rec.get("extracted-results"):
                out["evidence"] = rec["extracted-results"]
            # chống trùng theo (id, matched)
            key = (out.get("id"), out.get("matched"))
            if key in dedupe:
                continue
            dedupe.add(key)
            print(json.dumps(out, ensure_ascii=False))
            continue

        # Chế độ đầy đủ: có thể strip HTTP
        if args.strip_http:
            for k in ("request", "response", "curl-command"):
                if k in rec:
                    del rec[k]
        print(json.dumps(rec, ensure_ascii=False))

    p.wait()
finally:
    # gom stderr (nếu fail)
    err_text = p.stderr.read().strip().splitlines() if p.stderr else []

rc = p.returncode
# Nuclei: 0 (không phát hiện), 1 (có phát hiện) → đều là success
if rc not in (0, 1):
    print(json.dumps({
        "error":"nuclei failed",
        "code": rc,
        "stderr": "\n".join(err_text)
    }, ensure_ascii=False))
    sys.exit(rc)
