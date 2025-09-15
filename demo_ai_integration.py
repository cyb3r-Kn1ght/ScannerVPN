import requests
import json
import time
import sys

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_colored(text, color):
    print(f"{color}{text}{Colors.END}")

def print_header(text):
    print_colored(f"\n{'='*60}", Colors.BLUE)
    print_colored(f"  {text}", Colors.BOLD + Colors.WHITE)
    print_colored(f"{'='*60}", Colors.BLUE)

def print_step(step, text):
    print_colored(f"\n[Step {step}] {text}", Colors.CYAN)

def print_success(text):
    print_colored(f"✅ {text}", Colors.GREEN)

def print_error(text):
    print_colored(f"❌ {text}", Colors.RED)

def print_warning(text):
    print_colored(f"⚠️  {text}", Colors.YELLOW)

def print_info(text):
    print_colored(f"ℹ️  {text}", Colors.BLUE)

# Configuration
CONTROLLER_URL = "http://10.102.199.42:8000"
RAG_SERVER_URL = "http://10.102.199.221:8080"

def test_rag_server():
    """Test RAG server functionality"""
    print_step(1, "Testing RAG Server Connection")

    try:
        response = requests.post(
            f"{RAG_SERVER_URL}/rag_query",
            json={"query": "1 + 1 = ?"},
#            timeout=15
        )

        if response.status_code == 200:
            result = response.json()
            answer = result.get('answer', '')
            print_success("RAG server is working correctly")
            print_info(f"Sample answer: {answer[:150]}...")
            return True
        else:
            print_error(f"RAG server returned status: {response.status_code}")
            return False

    except requests.exceptions.ConnectionError:
        print_error("Cannot connect to RAG server")
        print_info("Make sure RAG server is running: python start_rag_server.ps1")
        return False
    except Exception as e:
        print_error(f"RAG server test failed: {e}")
        return False

def test_controller_ai_status():
    """Test controller AI status endpoint"""
    print_step(2, "Testing Controller AI Integration")

    try:
        response = requests.get(f"{CONTROLLER_URL}/api/ai/status")

        if response.status_code == 200:
            result = response.json()
            print_success("Controller AI integration is active")
            print_info(f"Auto workflow: {'ENABLED' if result.get('auto_workflow_enabled') else 'DISABLED'}")
            print_info(f"RAG server status: {result.get('rag_server_status', 'unknown')}")
            print_info(f"Max auto jobs: {result.get('max_auto_jobs', 'unknown')}")
            return True
        else:
            print_error(f"Controller AI status failed: {response.status_code}")
            return False

    except requests.exceptions.ConnectionError:
        print_error("Cannot connect to Controller")
        print_info("Make sure Controller is running: python start_controller_with_ai.ps1")
        return False
    except Exception as e:
        print_error(f"Controller test failed: {e}")
        return False

def create_demo_workflow():
    """Create a demo workflow to trigger AI analysis"""
    print_step(3, "Creating Demo Workflow")

    # Create a simple port scan workflow
    workflow_data = {
        "targets": ["scanme.nmap.org"],
        "steps": [
            {
                "tool_id": "port-scan",
                "params": {
                    "ports": "80,443,22,21,25,53,110,143,993,995",
                    "scan_type": "syn"
                }
            }
        ],
        "description": "AI Demo Workflow - Port Scan"
    }

    try:
        response = requests.post(
            f"{CONTROLLER_URL}/api/workflow",
            json=workflow_data,
 #           timeout=30
        )

        if response.status_code in [200, 201]:
            result = response.json()
            workflow_id = result.get("workflow_id")
            print_success(f"Demo workflow created: {workflow_id}")
            print_info(f"Total steps: {result.get('total_steps', 0)}")
            print_info(f"Status: {result.get('status', 'unknown')}")
            return workflow_id
        else:
            print_error(f"Failed to create workflow: {response.status_code}")
            print_error(f"Response: {response.text}")
            return None

    except Exception as e:
        print_error(f"Workflow creation failed: {e}")
        return None

def monitor_workflow_and_ai(workflow_id):
    """Monitor workflow progress and AI auto-generation"""
    print_step(4, f"Monitoring Workflow: {workflow_id}")

    print_info("Watching for:")
    print_info("  - Job completion")
    print_info("  - AI analysis trigger")
    print_info("  - Auto workflow creation")

    last_job_count = 0
    try:
        while True:
            try:
                # Get workflow status
                response = requests.get(
                    f"{CONTROLLER_URL}/api/workflows/{workflow_id}/status",
  #              timeout=10
                )

                if response.status_code == 200:
                    result = response.json()
                    workflow_status = result.get("workflow", {}).get("status", "unknown")
                    progress = result.get("progress", {})
                    sub_jobs = result.get("sub_jobs", [])

                    completed = progress.get("completed", 0)
                    total = progress.get("total", 0)

                    print(f"\r🔄 Status: {workflow_status} | Progress: {completed}/{total} | Jobs: {len(sub_jobs)}", end="", flush=True)

                    # Check for new jobs (indicates AI auto-workflow)
                    if len(sub_jobs) > last_job_count:
                        new_jobs = len(sub_jobs) - last_job_count
                        if last_job_count > 0:  # Not the initial jobs
                            print_success(f"\n🤖 AI created {new_jobs} new jobs!")
                            for job in sub_jobs[last_job_count:]:
                                print_info(f"   - {job.get('tool', 'unknown')} (Job ID: {job.get('job_id', 'unknown')})")
                        last_job_count = len(sub_jobs)

                    # Check for completion
                    if workflow_status in ["completed", "failed", "partially_failed"] or (total > 0 and completed >= total):
                        if workflow_status == "running" and total > 0 and completed == total:
                            print_warning("\n⚠️  Workflow status still 'running' but all jobs finished -> treat as completed")
                        print_success(f"\n✅ Workflow finished ({completed}/{total})")
                        return True, sub_jobs

                time.sleep(5)

            except KeyboardInterrupt:
                print_warning("\n⏹ Stopped by user")
                return False, []
            except Exception as e:
                print_error(f"\nError monitoring workflow: {e}")
                time.sleep(5)
    except KeyboardInterrupt:
        print_warning("\n⏹ Stopped by user")
        return False, []

def analyze_results(workflow_id, sub_jobs):
    """Analyze the results of the demo"""
    print_step(5, "Analyzing Demo Results")

    initial_jobs = [job for job in sub_jobs if "port-scan" in job.get("tool", "")]
    ai_generated_jobs = [job for job in sub_jobs if "port-scan" not in job.get("tool", "")]

    print_info(f"Initial port-scan jobs: {len(initial_jobs)}")
    print_info(f"AI-generated jobs: {len(ai_generated_jobs)}")

    if ai_generated_jobs:
        print_success("🎉 AI Auto-Workflow is working!")
        print_info("AI suggested these follow-up tools:")
        for job in ai_generated_jobs:
            tool = job.get("tool", "unknown")
            status = job.get("status", "unknown")
            print_info(f"  - {tool} ({status})")
    else:
        print_warning("No AI-generated jobs detected")
        print_info("  - Port scan maybe found nothing interesting")
        print_info("  - AI confidence low or auto workflow disabled")

    # Try to get AI analysis for one of the completed jobs
    for job in sub_jobs:
        if job.get("status") == "completed":
            try:
                job_id = job.get("job_id")
                response = requests.get(
                    f"{CONTROLLER_URL}/api/ai/analyze/{workflow_id}/{job_id}",
    #                timeout=30
                )

                if response.status_code == 200:
                    analysis = response.json()
                    print_success(f"AI Analysis for {job.get('tool')}:")

                    for target_analysis in analysis.get("analyses", []):
                        target = target_analysis.get("target")
                        ai_result = target_analysis.get("analysis", {})
                        summary = ai_result.get("summary", "No summary")
                        suggestions = ai_result.get("suggested_actions", [])

                        print_info(f"Target: {target}")
                        print_info(f"Summary: {summary}")
                        print_info(f"Suggestions: {len(suggestions)} tools recommended")

                        for suggestion in suggestions[:3]:  # Show top 3
                            tool = suggestion.get("tool", "unknown")
                            confidence = suggestion.get("confidence", 0)
                            print_info(f"  - {tool} (confidence: {confidence:.2f})")
                    break

            except Exception as e:
                print_warning(f"Could not get AI analysis: {e}")

def main():
    """Main demo function"""
    print_header("ScannerVPN AI RAG Integration Demo")
    print_colored("This demo will test the complete AI integration workflow", Colors.WHITE)

    # Pre-flight checks
    if not test_rag_server():
        print_error("RAG server is not available. Please start it first.")
        sys.exit(1)

    if not test_controller_ai_status():
        print_error("Controller AI integration is not available.")
        sys.exit(1)

    # Create and monitor demo workflow
    workflow_id = create_demo_workflow()
    if not workflow_id:
        print_error("Failed to create demo workflow")
        sys.exit(1)

    # Monitor workflow execution
    print_info("Monitoring workflow (no time limit; press Ctrl+C to stop)...")
    success, sub_jobs = monitor_workflow_and_ai(workflow_id)

    # Analyze results
    analyze_results(workflow_id, sub_jobs)

    print_header("Demo Completed")
    print_colored("Check controller logs for detailed AI analysis.", Colors.WHITE)

if __name__ == "__main__":
    main()