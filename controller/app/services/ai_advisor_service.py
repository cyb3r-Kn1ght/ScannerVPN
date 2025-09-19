# app/services/ai_advisor_service.py
import requests
import logging
from typing import Dict, List, Any, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

class AIAdvisorService:
    def __init__(self):
        self.rag_url = getattr(settings, 'RAG_SERVER_URL', 'http://10.102.199.221:8080')
    
    def analyze_scan_results(self, scan_results: List[Dict], current_tool: str, target: str) -> Dict[str, Any]:
        """Phân tích kết quả scan và đề xuất bước tiếp theo"""
        
        # Tạo summary từ kết quả scan
        summary = self._create_results_summary(scan_results, current_tool, target)
        
        # Tạo câu hỏi cho RAG dựa trên tool hiện tại
        query = self._create_analysis_query(summary, current_tool, target)
        
        try:
            response = requests.post(
                f"{self.rag_url}/rag_query",
                json={"query": query}
                # Không set timeout - để RAG chạy bao lâu cũng được
            )
            response.raise_for_status()
            result = response.json()
            
            ai_answer = result.get("answer", "")
            
            return {
                "ai_analysis": ai_answer,
                "context": result.get("context", ""),
                "suggested_actions": self._parse_suggested_actions(ai_answer, current_tool),
                "summary": summary,
                "confidence": self._calculate_confidence(ai_answer, scan_results)
            }
        except Exception as e:
            logger.error(f"Error calling RAG service: {e}")
            return {"error": str(e), "summary": summary}
    
    def _create_analysis_query(self, summary: str, tool: str, target: str) -> str:
        """Tạo câu hỏi phù hợp cho RAG dựa trên tool và kết quả"""
        
        base_query = f"""
        Tôi đang thực hiện pentest cho target {target} mục tiêu là tìm được flag và vừa hoàn thành quét bằng {tool}.
        
        Kết quả: {summary}
        
        Dựa trên OWASP Web Security Testing Guide (WSTG), hãy phân tích và đề xuất:
        """
        
        if tool == "port-scan":
            query = base_query + """
            1. Những service nào có thể có lỗ hổng bảo mật
            2. Tool nào nên chạy tiếp theo để test cụ thể (nuclei-scan, httpx-scan, sqlmap-scan, wpscan-scan, dirsearch-scan)
            3. Những WSTG test case nào áp dụng được
            4. Các port/service nào cần ưu tiên test trước
            """
        elif tool == "httpx-scan":
            query = base_query + """
            1. Phân tích các endpoint HTTP đã phát hiện
            2. Technology stack nào đang được sử dụng
            3. Tool nào nên chạy tiếp: nuclei-scan cho vulnerability scan, dirsearch-scan cho directory enumeration, sqlmap-scan cho SQL injection test, wpscan-scan nếu phát hiện WordPress
            4. WSTG test cases nào phù hợp với technology đã phát hiện
            """
        elif tool == "nuclei-scan":
            query = base_query + """
            1. Đánh giá độ nghiêm trọng của các lỗ hổng đã phát hiện
            2. Cần chạy tool gì để khai thác sâu hơn: sqlmap-scan cho SQL injection, dirsearch-scan cho file exposure, wpscan-scan cho WordPress vulnerabilities
            3. Những WSTG test case nào cần verify manual
            4. Lỗ hổng nào cần ưu tiên patch trước
            """
        elif tool == "dirsearch-scan":
            query = base_query + """
            1. Phân tích các file/directory đã phát hiện
            2. File nào có thể chứa thông tin nhạy cảm
            3. Có cần chạy nuclei-scan để test lỗ hổng trên các endpoint mới không
            4. Có file backup, config exposure cần test manual không
            """
        elif tool in ["sqlmap-scan", "wpscan-scan"]:
            query = base_query + """
            1. Đánh giá kết quả test chuyên sâu
            2. Cần verify manual những gì
            3. Có cần chạy thêm tool nào để test vector khác không
            4. Recommendation để fix các issues đã phát hiện
            """
        else:
            query = base_query + """
            1. Phân tích tổng quan kết quả
            2. Tool gì nên chạy tiếp theo
            3. WSTG test cases nào còn thiếu
            """
        
        return query
    
    def _create_results_summary(self, scan_results: List[Dict], tool: str, target: str) -> str:
        """Tạo summary ngắn gọn từ kết quả scan"""
        if not scan_results:
            return f"Không có kết quả từ {tool} scan cho {target}"
        
        if tool == "port-scan":
            open_ports = []
            for result in scan_results:
                ports = result.get('open_ports', [])
                for port in ports:
                    service = port.get('service', 'unknown')
                    version = port.get('version', '')
                    port_info = f"Port {port.get('port')}/{port.get('protocol')} - {service}"
                    if version:
                        port_info += f" ({version})"
                    open_ports.append(port_info)
            return f"Phát hiện {len(open_ports)} port mở: {', '.join(open_ports[:15])}" + ("..." if len(open_ports) > 15 else "")
        
        elif tool == "httpx-scan":
            endpoints = []
            technologies = set()
            for result in scan_results:
                httpx_results = result.get('scan_metadata', {}).get('httpx_results', [])
                for ep in httpx_results:
                    url = ep.get('url', '')
                    status = ep.get('status_code', '')
                    tech = ep.get('tech', [])
                    if tech:
                        technologies.update(tech)
                    endpoints.append(f"{url} ({status})")
            
            summary = f"Phát hiện {len(endpoints)} HTTP endpoint: {', '.join(endpoints[:10])}" + ("..." if len(endpoints) > 10 else "")
            if technologies:
                summary += f". Technologies: {', '.join(list(technologies)[:5])}"
            return summary
        
        elif tool == "nuclei-scan":
            vulns = []
            severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for result in scan_results:
                nuclei_results = result.get('scan_metadata', {}).get('nuclei_results', [])
                for vuln in nuclei_results:
                    template_id = vuln.get('template-id', '')
                    severity = vuln.get('info', {}).get('severity', 'info').lower()
                    severities[severity] = severities.get(severity, 0) + 1
                    vulns.append(f"{template_id} ({severity})")
            
            severity_summary = ", ".join([f"{sev}: {count}" for sev, count in severities.items() if count > 0])
            return f"Nuclei phát hiện {len(vulns)} lỗ hổng - {severity_summary}. Chi tiết: {', '.join(vulns[:8])}" + ("..." if len(vulns) > 8 else "")
        
        elif tool == "dirsearch-scan":
            findings = []
            for result in scan_results:
                dirsearch_results = result.get('scan_metadata', {}).get('dirsearch_results', [])
                for finding in dirsearch_results:
                    url = finding.get('url', '')
                    status = finding.get('status', '')
                    findings.append(f"{url} ({status})")
            return f"Dirsearch phát hiện {len(findings)} file/directory: {', '.join(findings[:10])}" + ("..." if len(findings) > 10 else "")
        
        elif tool == "sqlmap-scan":
            vulns = []
            for result in scan_results:
                sqlmap_results = result.get('scan_metadata', {}).get('sqlmap_results', [])
                for vuln in vulns:
                    vulns.append(f"{vuln.get('parameter')} - {vuln.get('type', '')}")
            return f"SQLMap phát hiện {len(vulns)} SQL injection: {', '.join(vulns[:5])}" + ("..." if len(vulns) > 5 else "")
        
        elif tool == "wpscan-scan":
            findings = []
            for result in scan_results:
                wpscan_results = result.get('scan_metadata', {}).get('wpscan_results', [])
                findings.extend([f"{f.get('type', '')}: {f.get('title', '')}" for f in wpscan_results])
            return f"WPScan phát hiện {len(findings)} issues: {', '.join(findings[:5])}" + ("..." if len(findings) > 5 else "")
        
        return f"Hoàn thành {tool} scan với {len(scan_results)} kết quả"
    
    def _parse_suggested_actions(self, ai_response: str, current_tool: str) -> List[Dict]:
        """Parse AI response để extract suggested actions"""
        suggestions = []
        response_lower = ai_response.lower()
        
        # Mapping tools với confidence dựa trên context
        tool_keywords = {
            "nuclei-scan": ["nuclei", "vulnerability", "lỗ hổng", "vuln scan", "automated scan"],
            "sqlmap-scan": ["sqlmap", "sql injection", "sqli", "database", "injection"],
            "wpscan-scan": ["wpscan", "wordpress", "wp", "cms"],
            "dirsearch-scan": ["dirsearch", "directory", "thư mục", "file", "enumeration", "brute force"],
            "httpx-scan": ["httpx", "http", "web", "endpoint", "service discovery"]
        }
        
        # Tránh suggest lại tool vừa chạy
        available_tools = {k: v for k, v in tool_keywords.items() if k != current_tool}
        
        for tool, keywords in available_tools.items():
            confidence = 0.0
            matches = 0
            
            for keyword in keywords:
                if keyword in response_lower:
                    matches += 1
                    confidence += 0.2
            
            # Bonus confidence dựa trên logic workflow
            if current_tool == "port-scan":
                if tool == "httpx-scan" and any(port in response_lower for port in ["80", "443", "8080", "http"]):
                    confidence += 0.3
                elif tool == "nuclei-scan":
                    confidence += 0.2
            elif current_tool == "httpx-scan":
                if tool == "nuclei-scan":
                    confidence += 0.3
                elif tool == "dirsearch-scan":
                    confidence += 0.2
                elif tool == "wpscan-scan" and "wordpress" in response_lower:
                    confidence += 0.4
            elif current_tool == "nuclei-scan":
                if tool == "sqlmap-scan" and ("sql" in response_lower or "injection" in response_lower):
                    confidence += 0.4
                elif tool == "dirsearch-scan" and ("directory" in response_lower or "file" in response_lower):
                    confidence += 0.3
            
            # Chỉ suggest nếu confidence > threshold
            if confidence >= 0.3:
                suggestions.append({
                    "type": "run_tool",
                    "tool": tool,
                    "confidence": min(confidence, 1.0),
                    "reason": f"AI detected {matches} relevant keywords for {tool}"
                })
        
        # Sort by confidence
        suggestions.sort(key=lambda x: x["confidence"], reverse=True)
        
        # Limit to top 3 suggestions
        return suggestions[:3]
    
    def _calculate_confidence(self, ai_response: str, scan_results: List[Dict]) -> float:
        """Tính confidence score cho analysis"""
        if not ai_response or not scan_results:
            return 0.0
        
        confidence = 0.5  # Base confidence
        
        # Increase confidence if AI mentions specific tools/technologies
        technical_terms = ["wstg", "owasp", "vulnerability", "security", "test", "scan"]
        for term in technical_terms:
            if term.lower() in ai_response.lower():
                confidence += 0.1
        
        # Increase confidence based on result count
        total_results = sum(len(result.get('open_ports', [])) + 
                          len(result.get('scan_metadata', {}).get('httpx_results', [])) +
                          len(result.get('scan_metadata', {}).get('nuclei_results', [])) 
                          for result in scan_results)
        
        if total_results > 0:
            confidence += min(0.2, total_results * 0.02)
        
        return min(confidence, 1.0)
