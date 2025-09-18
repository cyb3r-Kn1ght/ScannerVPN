import requests, json, time, sys
from urllib.parse import urlparse

class Colors:
    GREEN = '\033[92m'; RED = '\033[91m'; YELLOW = '\033[93m'; BLUE = '\033[94m'
    PURPLE = '\033[95m'; CYAN = '\033[96m'; WHITE = '\033[97m'; BOLD = '\033[1m'; END = '\033[0m'

def print_colored(t, c): print(f"{c}{t}{Colors.END}")
def print_header(t):
    print_colored("\n" + "="*64, Colors.BLUE)
    print_colored("  " + t, Colors.BOLD + Colors.WHITE)
    print_colored("="*64, Colors.BLUE)
def print_step(t): print_colored(f"\n{t}", Colors.CYAN)
def ok(t): print_colored(f"✅ {t}", Colors.GREEN)
def err(t): print_colored(f"❌ {t}", Colors.RED)
def warn(t): print_colored(f"⚠️  {t}", Colors.YELLOW)
def info(t): print_colored(f"ℹ️  {t}", Colors.BLUE)

CONTROLLER_URL = "http://10.102.199.42:8000"
RAG_SERVER_URL = "http://10.102.199.221:8080"

TOOLS_ORDER = [
    "port-scan",
    "httpx-scan",
    "nuclei-scan",
    "dirsearch-scan",
    "wpscan-scan",
    "sqlmap-scan",
    "bruteforce-scan"
]

DEFAULT_TARGETS = ["scanme.nmap.org"]
POLL_INTERVAL = 5
MAX_WAIT_SECONDS = None
MAX_CHAIN = len(TOOLS_ORDER)

# Tools cần HTTP/HTTPS URLs
WEB_TOOLS = [
    "httpx-scan", "nuclei-scan", "dirsearch-scan", 
    "wpscan-scan", "sqlmap-scan"
]

def prepare_targets_for_tool(targets, tool_id):
    """
    Chuẩn bị targets theo yêu cầu của từng tool:
    - Web tools: cần http:// hoặc https:// prefix
    - Network tools: chỉ cần IP/hostname
    """
    if tool_id in WEB_TOOLS:
        # Ensure HTTP/HTTPS prefix for web tools
        prepared = []
        for target in targets:
            if not target.startswith(('http://', 'https://')):
                # Default to http:// if no protocol specified
                prepared.append(f"http://{target}")
            else:
                prepared.append(target)
        return prepared
    else:
        # Network tools (port-scan, dns-lookup) - remove protocol if present
        prepared = []
        for target in targets:
            if target.startswith(('http://', 'https://')):
                # Extract hostname/IP from URL
                parsed = urlparse(target)
                prepared.append(parsed.hostname or parsed.netloc)
            else:
                prepared.append(target)
        return prepared

def test_rag():
    print_step(1, "Kiểm tra RAG server")
    try:
        r = requests.post(f"{RAG_SERVER_URL}/rag_query", json={"query": "ping"})
        if r.status_code == 200:
            ok("RAG OK")
            return True
        err(f"RAG lỗi: {r.status_code}")
    except Exception as e:
        err(f"RAG không truy cập được: {e}")
    return False

def test_controller():
    print_step(2, "Kiểm tra Controller AI status")
    try:
        r = requests.get(f"{CONTROLLER_URL}/api/ai/status")
        if r.status_code == 200:
            js = r.json()
            ok("Controller AI OK")
            info(f"Auto-workflow: {'ENABLED' if js.get('auto_workflow_enabled') else 'DISABLED'}")
            return True
        err(f"Controller status lỗi: {r.status_code}")
    except Exception as e:
        err(f"Controller không truy cập được: {e}")
    return False

def create_workflow(tool_id, targets, params=None, desc=None):
    # Prepare targets cho tool cụ thể
    prepared_targets = prepare_targets_for_tool(targets, tool_id)
    
    body = {
        "targets": prepared_targets,
        "steps": [{
            "tool_id": tool_id,
            "params": params or {}
        }],
        "description": desc or f"Auto AI chain - {tool_id}"
    }
    try:
        r = requests.post(f"{CONTROLLER_URL}/api/workflow", json=body)
        if r.status_code in [200, 201]:
            js = r.json()
            wf = js.get("workflow_id")
            ok(f"Tạo workflow ({tool_id}) => {wf} | targets: {prepared_targets}")
            return wf
        err(f"Tạo workflow thất bại {tool_id}: {r.status_code} {r.text[:200]}")
    except Exception as e:
        err(f"Lỗi tạo workflow {tool_id}: {e}")
    return None

def wait_workflow_complete(workflow_id):
    start = time.time()
    last_status = None
    while True:
        try:
            r = requests.get(f"{CONTROLLER_URL}/api/workflows/{workflow_id}/status")
            if r.status_code == 200:
                js = r.json()
                wf_status = js.get("workflow", {}).get("status")
                progress = js.get("progress", {})
                sub_jobs = js.get("sub_jobs", [])
                if wf_status != last_status:
                    info(f"Workflow {workflow_id} status: {wf_status} ({progress.get('completed',0)}/{progress.get('total',0)})")
                    last_status = wf_status
                if wf_status in ["completed", "failed", "partially_failed"] or (progress.get("total",0) > 0 and progress.get("completed",0) >= progress.get("total",0)):
                    ok(f"Workflow {workflow_id} kết thúc: {wf_status}")
                    return wf_status, sub_jobs
            else:
                warn(f"Status {r.status_code} khi lấy workflow {workflow_id}")
        except Exception as e:
            warn(f"Lỗi polling workflow {workflow_id}: {e}")
        time.sleep(POLL_INTERVAL)

def get_completed_job(sub_jobs, tool_id):
    for j in sub_jobs:
        if j.get("tool") == tool_id and j.get("status") == "completed":
            return j
    for j in sub_jobs:
        if j.get("tool") == tool_id:
            return j
    return None

def fetch_ai_suggestions(workflow_id, job_id, tool):
    try:
        r = requests.get(f"{CONTROLLER_URL}/api/ai/analyze/{workflow_id}/{job_id}")
        if r.status_code == 200:
            js = r.json()
            analyses = js.get("analyses", [])
            suggestions = []
            for a in analyses:
                analysis = a.get("analysis", {})
                sug = analysis.get("suggested_actions", []) or []
                for s in sug:
                    if s.get("type") == "run_tool":
                        suggestions.append({
                            "tool": s.get("tool"),
                            "confidence": s.get("confidence", 0.0)
                        })
            merged = {}
            for s in suggestions:
                t = s["tool"]
                if not t:
                    continue
                if t not in merged or s["confidence"] > merged[t]["confidence"]:
                    merged[t] = s
            result = sorted(merged.values(), key=lambda x: x["confidence"], reverse=True)
            if result:
                ok(f"AI đề xuất (từ {tool}): " + ", ".join(f"{x['tool']}({x['confidence']:.2f})" for x in result[:5]))
            else:
                warn(f"AI không đề xuất tool mới từ {tool}")
            return result
        warn(f"AI analysis lỗi HTTP {r.status_code}")
    except Exception as e:
        warn(f"Lỗi gọi AI analysis: {e}")
    return []

def pick_next_tool(ai_suggestions, used):
    for s in ai_suggestions:
        if s["tool"] and s["tool"] not in used and s["tool"] in TOOLS_ORDER and s["confidence"] >= 0.3:
            return s["tool"]
    for t in TOOLS_ORDER:
        if t not in used:
            return t
    return None

def run_chain():
    print_header("AI AUTO WORKFLOW CHAIN")
#    if not test_rag():
#        err("Dừng: RAG chưa sẵn sàng"); sys.exit(1)
#    if not test_controller():
#        err("Dừng: Controller AI chưa OK"); sys.exit(1)

    targets = DEFAULT_TARGETS
    used_tools = set()
    chain_history = []
    current_tool = "port-scan"
    iteration = 0

    while iteration < MAX_CHAIN and current_tool:
        iteration += 1
        print_step(f"Iteration {iteration}: chạy {current_tool}")
        wf_id = create_workflow(current_tool, targets, params=_default_params_for_tool(current_tool), desc=f"AI chain step {iteration} - {current_tool}")
        if not wf_id:
            err("Không tạo được workflow, dừng.")
            break
        status, sub_jobs = wait_workflow_complete(wf_id)
        used_tools.add(current_tool)

        job = get_completed_job(sub_jobs, current_tool)
        if not job:
            warn(f"Không tìm thấy job hoàn tất cho {current_tool} => bỏ qua AI step")
            current_tool = pick_next_tool([], used_tools)
            continue

        ai_suggestions = fetch_ai_suggestions(wf_id, job.get("job_id"), current_tool)
        next_tool = pick_next_tool(ai_suggestions, used_tools)

        chain_history.append({
            "workflow_id": wf_id,
            "tool": current_tool,
            "status": status,
            "suggestions": ai_suggestions
        })

        if not next_tool:
            ok("Chuỗi đã hoàn tất: không còn tool mới.")
            break
        current_tool = next_tool

    print_header("TỔNG KẾT CHUỖI")
    for i, step in enumerate(chain_history, 1):
        sug_txt = ", ".join(f"{s['tool']}({s['confidence']:.2f})" for s in step["suggestions"][:3]) or "-"
        print_colored(f"[{i}] {step['tool']} -> WF {step['workflow_id']} | AI: {sug_txt}", Colors.WHITE)

    info("Đã dùng tools: " + ", ".join(sorted(used_tools)))
    remaining = [t for t in TOOLS_ORDER if t not in used_tools]
    if remaining:
        warn("Chưa chạy: " + ", ".join(remaining))
    else:
        ok("ĐÃ CHẠY HẾT DANH SÁCH TOOL")

def _default_params_for_tool(tool):
    if tool == "port-scan":
        return {"ports": "80,443,22,21,25,53,110,143,993,995", "scan_type": "-sS"}
    if tool == "httpx-scan":
        return {"status_code": True, "title": True, "tech_detect": True, "ports": "80,443,8080"}
    if tool == "nuclei-scan":
        return {"severity": ["medium","high","critical"], "rate_limit": 150}
    if tool == "dirsearch-scan":
        return {"extensions": "php,asp,aspx", "threads": 10, "recursive": False, "include_status": "200,204", "wordlist": "/app/dicc.txt", "scanner_count": 1}
    if tool == "wpscan-scan":
        return {"enumerate": ["p","t","u"]}
    if tool == "sqlmap-scan":
        return {"batch": True, "level": 1, "risk": 1}
    if tool == "bruteforce-scan":
        return {"concurrency": 2}
    return {}

if __name__ == "__main__":
    run_chain()
