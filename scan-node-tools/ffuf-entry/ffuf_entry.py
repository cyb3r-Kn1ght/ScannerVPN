#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ffuf-entry v0.2
- Dò endpoint login bằng ffuf, parse form HTML có input[type=password]
- Sinh "targets" dạng http_form đúng schema của bf_runner
- (Tuỳ chọn) --emit-job: xuất thẳng job.json hoàn chỉnh cho bf_runner (gồm strategy/wordlists/limits/targets)

Gợi ý chạy (xuất job.json):
  docker run --rm -v $PWD/wordlists:/wordlists:ro -v $PWD:/out \
    l4sttr4in/scan-tools:ffuf-entry \
    --url http://target/ --emit-job \
    --users /wordlists/users.txt --passwords /wordlists/passwords.txt \
    --strategy dictionary --concurrency 2 --rate-per-min 10 --jitter 100,300 --timeout-sec 15 \
    --out /out/job.json
"""

import argparse, json, os, re, subprocess, tempfile, sys, time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# ====== cấu hình mặc định cho wordlist ffuf ======
DEFAULT_WORDS = [
    "login", "signin", "sign-in", "auth", "account/login", "user/login",
    "wp-login.php", "administrator/index.php", "admin/login", "session",
    "users/sign_in", "auth/login", "members/login", "portal/login"
]

# ====== ffuf runner ======
def run_ffuf(base_url, wordlist, rate, threads, codes, timeout, proxy):
    """
    Chạy ffuf: -u BASE/FUZZ -w wordlist -mc codes -t threads -rate rate -maxtime timeout -x proxy
    Trả về list kết quả JSON (ffuf "results")
    """
    out_json = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name
    cmd = [
        "ffuf",
        "-u", base_url.rstrip("/") + "/FUZZ",
        "-w", wordlist,
        "-of", "json", "-o", out_json,
        "-mc", codes,
        "-maxtime", str(timeout),
        "-t", str(threads),
    ]
    if rate:
        cmd += ["-rate", str(rate)]
    if proxy:
        cmd += ["-x", proxy]

    # Không nổ job nếu ffuf exit!=0; cố đọc file kết quả
    subprocess.run(cmd, capture_output=True, text=True)
    try:
        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {"results": []}
    try:
        os.unlink(out_json)
    except Exception:
        pass
    return data.get("results", [])

# ====== lọc URL ứng viên login ======
def pick_login_candidates(results):
    cands, seen = [], set()
    rx = re.compile(r"(login|sign[\-_ ]?in|auth|wp-login|user/login|account/login)", re.I)
    for r in results:
        url = r.get("url") or r.get("input")
        if not url or url in seen:
            continue
        seen.add(url)
        # Ưu tiên URL có keyword + các mã 200/301/302/401/403
        if rx.search(url) or r.get("status") in [200, 301, 302, 401, 403]:
            cands.append(url)
    return cands

# ====== heuristics lấy tên field ======
def choose_username_field(inputs):
    prefs = re.compile(r"(user(name)?|email|login|account)", re.I)
    text_fields = [i for i in inputs if (i.get("type") or "text").lower() in ("text", "email") and i.get("name")]
    for i in text_fields:
        if prefs.search(i["name"]):
            return i["name"]
    return text_fields[0]["name"] if text_fields else None

def find_csrf_token(inputs, soup):
    cand_names = [
        "csrf", "_csrf", "csrf_token", "_token", "__RequestVerificationToken",
        "xsrf", "X-CSRF-Token", "authenticity_token", "XSRF-TOKEN"
    ]
    for i in inputs:
        n = (i.get("name") or "").strip()
        t = (i.get("type") or "").lower()
        if n and t in ("hidden", "text") and any(n.lower() == cn.lower() for cn in cand_names):
            return n, f"input[name='{n}']@value"
    m = soup.select_one("meta[name=csrf-token], meta[name='xsrf-token'], meta[name='csrf']")
    if m and m.get("content"):
        return "csrf", "meta[name=csrf-token]@content"
    return None, None

# ====== dựng profile http_form từ 1 trang HTML ======
def build_profile_from_form(base_url, url, html, verify_ssl=True):
    soup = BeautifulSoup(html, "lxml")
    forms = soup.find_all("form")
    targets = []

    for form in forms:
        pwd_input = form.select_one("input[type=password]")
        if not pwd_input or not pwd_input.get("name"):
            continue

        inputs = [{
            "name": inp.get("name"),
            "type": (inp.get("type") or "text").lower(),
            "value": inp.get("value") or ""
        } for inp in form.find_all("input")]

        user_field = choose_username_field(inputs)
        pass_field = pwd_input.get("name")
        if not user_field or not pass_field:
            continue

        method = (form.get("method") or "POST").upper()
        action = form.get("action") or url
        action_url = urljoin(url, action)

        csrf_name, csrf_selector = find_csrf_token(inputs, soup)

        parts = [f"{user_field}=§USER§", f"{pass_field}=§PASS§"]
        if csrf_name and csrf_selector:
            parts.append(f"{csrf_name}=§CSRF§")
        body_template = "&".join(parts)

        profile = {
            "protocol": "http_form",
            "host": urlparse(action_url).hostname or urlparse(base_url).hostname,
            "port": urlparse(action_url).port or (443 if action_url.startswith("https") else 80),
            "http": {
                "url": action_url,
                "method": method,
                "content_type": "form",
                "headers": {
                    "Origin": f"{urlparse(action_url).scheme}://{urlparse(action_url).hostname}",
                    "Referer": url
                },
                "body_template": body_template,
                "success": {
                    "any": [
                        {"status": 302, "location_regex": "/(home|dashboard|profile|account)"},
                        {"set_cookie_regex": "(session|auth|token)="}
                    ]
                },
                "failure": {"body_regex": "(Invalid|incorrect|unauthori[sz]ed|sai|không đúng|thất bại)"},
                "mfa_hint_regex": "(OTP|2FA|Authenticator)",
                "verify_ssl": verify_ssl
            }
        }
        pre_login = {"mode": "once", "url": url}
        if csrf_selector:
            pre_login["extract"] = {"csrf": csrf_selector}
            profile["http"]["pre_login_ttl_sec"] = 120
        profile["http"]["pre_login"] = pre_login

        targets.append(profile)
    return targets

# ====== tải HTML một URL ======
def fetch_html(url, headers=None, proxy=None, verify_ssl=True, timeout=10):
    s = requests.Session()
    if headers:
        s.headers.update(headers)
    if proxy:
        s.proxies = proxy if isinstance(proxy, dict) else {"http": proxy, "https": proxy}
    try:
        r = s.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
        ct = (r.headers.get("Content-Type") or "").lower()
        if "text/html" in ct or "<html" in r.text.lower():
            return r.text
        return ""
    except Exception:
        return ""

# ====== helper ======
def parse_jitter(s):
    if not s:
        return [100, 300]
    parts = [p.strip() for p in str(s).split(",")]
    if len(parts) != 2:
        return [100, 300]
    try:
        return [int(parts[0]), int(parts[1])]
    except Exception:
        return [100, 300]

# ====== main ======
def main():
    ap = argparse.ArgumentParser(
        description="ffuf entry → sinh targets HTTP / hoặc job.json hoàn chỉnh cho bf_runner"
    )
    ap.add_argument("--url", required=True, help="Base URL, ví dụ: https://target.tld")
    ap.add_argument("--wordlist", help="Wordlist endpoints cho ffuf; nếu không, dùng danh sách mặc định")
    ap.add_argument("--rate", type=int, default=50, help="req/s cho ffuf (default 50)")
    ap.add_argument("--threads", type=int, default=50, help="threads ffuf (default 50)")
    ap.add_argument("--codes", default="200,301,302,401,403", help="HTTP codes quan tâm để giữ kết quả")
    ap.add_argument("--timeout", type=int, default=60, help="maxtime ffuf (giây)")
    ap.add_argument("--proxy", help="Proxy (http://.., https://.., socks5h://..)")
    ap.add_argument("--insecure", action="store_true", help="Bỏ verify SSL khi crawl")
    ap.add_argument("--out", help="Ghi JSON ra file (mặc định in stdout)")

    # ---- Emit job cho bf_runner ----
    ap.add_argument("--emit-job", action="store_true", help="Xuất thẳng job.json cho bf_runner")
    ap.add_argument("--users", help="Path wordlist users (trong container)")
    ap.add_argument("--passwords", help="Path wordlist passwords (trong container)")
    ap.add_argument("--pairs", help="Path wordlist cặp user:pass (tuỳ chọn)")
    ap.add_argument("--strategy", choices=["dictionary", "spray", "stuffing"], default="dictionary")
    ap.add_argument("--concurrency", type=int, default=2)
    ap.add_argument("--rate-per-min", type=int, default=10)
    ap.add_argument("--jitter", default="100,300", help="ví dụ: 100,300 (ms)")
    ap.add_argument("--timeout-sec", type=int, default=15)
    ap.add_argument("--stop-on-success", action="store_true", default=True)
    ap.add_argument("--no-stop-on-success", dest="stop_on_success", action="store_false")

    args = ap.parse_args()
    base_url = args.url
    verify_ssl = not args.insecure

    # Wordlist endpoint cho ffuf
    if args.wordlist and os.path.exists(args.wordlist):
        wl = args.wordlist
    else:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        tmp.write(("\n".join(DEFAULT_WORDS)).encode("utf-8"))
        tmp.close()
        wl = tmp.name

    # 1) Chạy ffuf để lấy candidates
    ffuf_results = run_ffuf(base_url, wl, args.rate, args.threads, args.codes, args.timeout, args.proxy)
    candidates = pick_login_candidates(ffuf_results)

    # 2) Parse form từng candidate
    targets = []
    for url in candidates:
        html = fetch_html(url, proxy=args.proxy, verify_ssl=verify_ssl)
        if not html:
            continue
        targets.extend(build_profile_from_form(base_url, url, html, verify_ssl=verify_ssl))

    # 3) Xuất JSON
    if not args.emit_job:
        payload = {"job_id": f"ffuf-entry-{int(time.time())}", "targets": targets}
    else:
        # kiểm tra tham số bắt buộc
        if not args.users or (not args.passwords and not args.pairs and args.strategy != "spray"):
            print("ERROR: --emit-job requires --users and (--passwords | --pairs) unless strategy=spray", file=sys.stderr)
            sys.exit(2)
        payload = {
            "job_id": f"bf-from-ffuf-{int(time.time())}",
            "strategy": args.strategy,
            "targets": targets,
            "wordlists": {"users": args.users},
            "limits": {
                "concurrency": args.concurrency,
                "rate_per_min": args.rate_per_min,
                "jitter_ms": parse_jitter(args.jitter),
                "timeout_sec": args.timeout_sec,
                "stop_on_success": args.stop_on_success
            }
        }
        if args.passwords:
            payload["wordlists"]["passwords"] = args.passwords
        if args.pairs:
            payload["wordlists"]["pairs"] = args.pairs

    out = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        print(out)

if __name__ == "__main__":
    main()
