import re
import os
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, render_template, redirect, url_for
from dotenv import load_dotenv
import certifi
import ssl
import urllib3
import json
from datetime import datetime
from collections import defaultdict

load_dotenv()
app = Flask(__name__)

# ======= LOAD KEYS SAFELY =======
VT_API_KEY = os.environ.get("VT_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
RAPIDAPI_KEY = os.environ.get("RAPIDAPI_KEY")
# ================================

# ======= SSL VERIFICATION CONFIGURATION =======
# Allow disabling SSL verification via environment variable (for corporate proxies)
# WARNING: Only use this if you understand the security implications
# To disable SSL verification, add DISABLE_SSL_VERIFY=true to your .env file
DISABLE_SSL_VERIFY = os.environ.get("DISABLE_SSL_VERIFY", "false").lower() == "true"
CUSTOM_CA_BUNDLE = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE")

# Configure SSL verification with smart fallback
def get_ssl_verify():
    """
    Returns SSL verification setting based on environment configuration.
    Handles corporate proxies and self-signed certificates gracefully.
    """
    if DISABLE_SSL_VERIFY:
        print("[WARNING] SSL verification is DISABLED. This is not recommended for production!")
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except:
            pass
        return False
    
    # Use custom CA bundle if specified
    if CUSTOM_CA_BUNDLE and os.path.exists(CUSTOM_CA_BUNDLE):
        return CUSTOM_CA_BUNDLE
    
    # Try system default certificates first (includes Windows certificate store)
    # This works better in corporate environments where CAs are installed system-wide
    return True  # requests will use system default certificate store
# ================================

# --- 2. פונקציית חדשות מעודכנת (Web Scraping) ---
def get_cyber_news():
    """Fetches top 5 cyber news headlines by scraping The Hacker News."""
    URL = "https://thehackernews.com/"
    news_items = []
    
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    headers = {"User-Agent": user_agent}
    
    # First try with SSL verification
    ssl_verify = get_ssl_verify()
    try:
        print(f"[News] Scraping news from {URL}")
        r = requests.get(URL, headers=headers, timeout=10, verify=ssl_verify)
        
        if r.status_code != 200:
            print(f"[News] Error: Got status code {r.status_code}")
            return []

        soup = BeautifulSoup(r.text, 'html.parser')
        headlines = soup.find_all('h3', class_='home-title', limit=5)
        
        for item in headlines:
            link_tag = item.find_parent('a')
            if link_tag and link_tag.has_attr('href'):
                news_items.append({
                    "title": item.text.strip(),
                    "link": link_tag['href']
                })
                
        print(f"[News] Found {len(news_items)} items via scraping.")
    except requests.exceptions.SSLError as e:
        error_msg = str(e)
        # If SSL verification is already disabled, don't retry
        if not ssl_verify:
            print(f"Error scraping cyber news (SSL verification disabled): {e}")
            return []
        
        # If SSL error occurs and we're using verification, try without verification as fallback
        if "certificate verify failed" in error_msg or "self-signed certificate" in error_msg or "CERTIFICATE_VERIFY_FAILED" in error_msg:
            print(f"[News] SSL verification failed, retrying without verification (corporate proxy detected)")
            try:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                r = requests.get(URL, headers=headers, timeout=10, verify=False)
                print(f"[News] Got status code {r.status_code} (SSL verification disabled)")
                
                if r.status_code != 200:
                    print(f"[News] Error: Got status code {r.status_code}")
                    return []

                soup = BeautifulSoup(r.text, 'html.parser')
                headlines = soup.find_all('h3', class_='home-title', limit=5)
                
                for item in headlines:
                    link_tag = item.find_parent('a')
                    if link_tag and link_tag.has_attr('href'):
                        news_items.append({
                            "title": item.text.strip(),
                            "link": link_tag['href']
                        })
                        
                print(f"[News] Found {len(news_items)} items via scraping.")
            except Exception as retry_e:
                print(f"Error scraping cyber news (retry failed): {retry_e}")
                return []
        else:
            print(f"Error scraping cyber news: {e}")
            return []
    except Exception as e:
        print(f"Error scraping cyber news: {e}")
    return news_items
# --- סוף העדכון ---


# ---------- helpers ----------
_ipv4 = re.compile(r"^((25[0-5]|2[0-4]\d|1?\d?\d)(\.|$)){4}$")
_domain = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
_md5 = re.compile(r"^[A-Fa-f0-9]{32}$")
_sha1 = re.compile(r"^[A-Fa-f0-9]{40}$")
_sha224 = re.compile(r"^[A-Fa-f0-9]{56}$")
_sha256 = re.compile(r"^[A-Fa-f0-9]{64}$")
_sha384 = re.compile(r"^[A-Fa-f0-9]{96}$")
_sha512 = re.compile(r"^[A-Fa-f0-9]{128}$")
_sha3_224 = re.compile(r"^[A-Fa-f0-9]{56}$")  # Same length as SHA-224
_sha3_256 = re.compile(r"^[A-Fa-f0-9]{64}$")  # Same length as SHA-256
_sha3_384 = re.compile(r"^[A-Fa-f0-9]{96}$")  # Same length as SHA-384
_sha3_512 = re.compile(r"^[A-Fa-f0-9]{128}$")  # Same length as SHA-512

def guess_type(q: str) -> str:
    q = (q or "").strip()
    if _ipv4.match(q): return "ip"
    if _domain.match(q): return "domain"
    if (_sha512.match(q) or _sha384.match(q) or _sha256.match(q) or 
        _sha224.match(q) or _sha1.match(q) or _md5.match(q)): return "hash"
    return "domain" if "." in q else "unknown"

def vt_url_for(q: str) -> str:
    t = guess_type(q)
    if t == "ip": return f"https://www.virustotal.com/api/v3/ip_addresses/{q}"
    if t == "domain": return f"https://www.virustotal.com/api/v3/domains/{q}"
    if t == "hash": return f"https://www.virustotal.com/api/v3/files/{q}"
    return f"https://www.virustotal.com/api/v3/search?query={q}"

def safe_text(s, limit=400):
    s = "" if s is None else str(s).strip()
    return (s[:limit] + "…") if len(s) > limit else s

def summarize_vt(payload: dict) -> dict:
    """Summarizes a VT payload, handling both direct lookups and search results."""
    d = (payload or {}).get("data") or {}

    if isinstance(d, list):
        if not d:
            return {"name": "Not Found", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 0, "community_score": 0, "kind": "—", "detections": []}
        d = d[0]

    attr = d.get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    votes = attr.get("total_votes", {})
    name = attr.get("meaningful_name") or d.get("id") or "—"
    kind = d.get("type") or "—"
    
    detections_list = []
    if kind in ('file', 'ip_address', 'domain'):
        last_analysis_results = attr.get("last_analysis_results", {})
        for engine, details in last_analysis_results.items():
            detections_list.append({
                "engine": engine,
                "result": details.get('result'),
                "category": details.get('category', 'unknown')
            })
        
        category_order = {
            "malicious": 1, "suspicious": 2, "harmless": 3,
            "undetected": 4, "timeout": 5, "type-unsupported": 6, "unknown": 7
        }
        
        detections_list.sort(key=lambda x: (category_order.get(x['category'], 99), x['engine']))
    
    return {
        "kind": kind, "name": name,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "timeout": stats.get("timeout", 0),
        "community_score": (votes.get("harmless", 0) - votes.get("malicious", 0)),
        "detections": detections_list
    }

def vt_fetch(query: str):
    if not VT_API_KEY:
        return None, "VT_API_KEY is not configured."
    url = vt_url_for(query)
    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
    
    # First try with SSL verification
    ssl_verify = get_ssl_verify()
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=ssl_verify)
        print(f"[VT] {url} -> {r.status_code}")
        if r.status_code != 200:
            snippet = r.text[:400].replace("\n", " ")
            return None, f"HTTP {r.status_code}: {snippet}"
        try:
            js = r.json()
        except Exception:
            return None, "Invalid JSON from VirusTotal"
        print(f"[VT] sample: {str(js)[:200]}")
        return summarize_vt(js), None
    except requests.exceptions.SSLError as e:
        error_msg = str(e)
        # If SSL verification is already disabled, don't retry
        if not ssl_verify:
            return None, f"SSL Error (verification disabled): {e}"
        
        # If SSL error occurs and we're using verification, try without verification as fallback
        if "certificate verify failed" in error_msg or "self-signed certificate" in error_msg or "CERTIFICATE_VERIFY_FAILED" in error_msg:
            print(f"[VT] SSL verification failed, retrying without verification (corporate proxy detected)")
            try:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                r = requests.get(url, headers=headers, timeout=10, verify=False)
                print(f"[VT] {url} -> {r.status_code} (SSL verification disabled)")
                if r.status_code != 200:
                    snippet = r.text[:400].replace("\n", " ")
                    return None, f"HTTP {r.status_code}: {snippet}"
                try:
                    js = r.json()
                except Exception:
                    return None, "Invalid JSON from VirusTotal"
                print(f"[VT] sample: {str(js)[:200]}")
                return summarize_vt(js), None
            except Exception as retry_e:
                return None, f"SSL Error (retry failed): {retry_e}"
        return None, f"SSL Error: {e}"
    except Exception as e:
        return None, f"Network error: {e}"

def get_abuseipdb_info(ip: str):
    if not ABUSEIPDB_API_KEY:
        return None, "ABUSEIPDB_API_KEY is not configured."
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    
    # First try with SSL verification
    ssl_verify = get_ssl_verify()
    try:
        r = requests.get(url, headers=headers, params=params, timeout=20, verify=ssl_verify)
        print(f"[IPDB] {ip} -> {r.status_code}")
        if r.status_code != 200:
            snippet = r.text[:400].replace("\n", " ")
            return None, f"HTTP {r.status_code}: {snippet}"
        try:
            d = r.json().get("data", {}) or {}
        except Exception:
            return None, "Invalid JSON from AbuseIPDB"
        print(f"[IPDB] sample: {str(d)[:200]}")
        return {
            "abuseScore": d.get("abuseConfidenceScore", "None"),
            "totalReports": d.get("totalReports", "None"),
            "isp": d.get("isp", "None"),
            "country": d.get("countryCode", "None"),
            "domain": d.get("domain", "None"),
            "flag_url": (f"https://flagcdn.com/w40/{(d.get('countryCode') or '').lower()}.png" if d.get("countryCode") else None),
            "reports": (d.get("reports", []) or [])[:5]
        }, None
    except requests.exceptions.SSLError as e:
        error_msg = str(e)
        # If SSL verification is already disabled, don't retry
        if not ssl_verify:
            return None, f"SSL Error (verification disabled): {e}"
        
        # If SSL error occurs and we're using verification, try without verification as fallback
        if "certificate verify failed" in error_msg or "self-signed certificate" in error_msg or "CERTIFICATE_VERIFY_FAILED" in error_msg:
            print(f"[IPDB] SSL verification failed, retrying without verification (corporate proxy detected)")
            try:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                r = requests.get(url, headers=headers, params=params, timeout=20, verify=False)
                print(f"[IPDB] {ip} -> {r.status_code} (SSL verification disabled)")
                if r.status_code != 200:
                    snippet = r.text[:400].replace("\n", " ")
                    return None, f"HTTP {r.status_code}: {snippet}"
                try:
                    d = r.json().get("data", {}) or {}
                except Exception:
                    return None, "Invalid JSON from AbuseIPDB"
                print(f"[IPDB] sample: {str(d)[:200]}")
                return {
                    "abuseScore": d.get("abuseConfidenceScore", "None"),
                    "totalReports": d.get("totalReports", "None"),
                    "isp": d.get("isp", "None"),
                    "country": d.get("countryCode", "None"),
                    "domain": d.get("domain", "None"),
                    "flag_url": (f"https://flagcdn.com/w40/{(d.get('countryCode') or '').lower()}.png" if d.get("countryCode") else None),
                    "reports": (d.get("reports", []) or [])[:5]
                }, None
            except Exception as retry_e:
                return None, f"SSL Error (retry failed): {retry_e}"
        return None, f"SSL Error: {e}"
    except Exception as e:
        return None, f"Network error: {e}"

# ---------- routes ----------
@app.route("/", methods=["GET"])
def home():
    news_data = get_cyber_news()
    missing = []
    if not VT_API_KEY: missing.append("VT_API_KEY")
    if not ABUSEIPDB_API_KEY: missing.append("ABUSEIPDB_API_KEY")
    
    result = ("Missing API keys. Set them in your .env file: " + ", ".join(missing)) if missing else None
    return render_template("index.html", result=result, query="", vt=None, ipdb=None,
                           malicious=0, suspicious=0, harmless=0, undetected=0, timeout=0,
                           news=news_data)

# --- תיקון: החזרת פונקציית החיפוש הראשית (שהייתה חסרה) ---
@app.route("/lookup", methods=["POST"])
def lookup():
    news_data = get_cyber_news()
    query = (request.form.get("query") or "").strip()
    if not query:
        return render_template("index.html", result="No query entered", query="",
                               vt=None, ipdb=None,
                               malicious=0, suspicious=0, harmless=0, undetected=0, timeout=0,
                               news=news_data)

    vt_summary, vt_err = vt_fetch(query)
    if not vt_summary:
        vt_summary = {} 

    ipdb_view = None
    ipdb_err = None
    if guess_type(query) == "ip":
        ipdb_view, ipdb_err = get_abuseipdb_info(query)
        if not ipdb_view:
            ipdb_view = {
                "abuseScore": "None", "totalReports": "None", "country": "None",
                "isp": "None", "domain": "None", "flag_url": None, "reports": []
            }

    malicious = vt_summary.get("malicious", 0)
    suspicious = vt_summary.get("suspicious", 0)
    harmless = vt_summary.get("harmless", 0)
    undetected = vt_summary.get("undetected", 0)
    timeout = vt_summary.get("timeout", 0)

    vt_view = {
        "name": safe_text(vt_summary.get("name", "—")),
        "malicious": malicious,
        "suspicious": suspicious,
        "community_score": vt_summary.get("community_score", 0), 
        "error": vt_err,
        "kind": vt_summary.get("kind", "—"),
        "detections": vt_summary.get("detections", [])
    }

    if ipdb_view is not None:
        ipdb_view["error"] = ipdb_err

    return render_template(
        "index.html",
        result=None,
        query=query,
        vt=vt_view,
        ipdb=ipdb_view,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        timeout=timeout,
        news=news_data
    )
# --- סוף התיקון ---


# ======= COMPREHENSIVE SIEM LOG ANALYZER =======
def parse_siem_log(log_text: str) -> dict:
    """
    Comprehensive SIEM log parser that extracts:
    - IP addresses (source, destination, etc.)
    - Timestamps
    - Protocols and ports
    - URLs and domains
    - User agents
    - HTTP methods and status codes
    - Usernames
    - Event types and actions
    - File paths and process names
    - Risk indicators
    """
    analysis = {
        "timestamp": None,
        "message": None,
        "event_type": None,
        "action": None,
        "username": None,
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "ips": [],
        "urls": [],
        "domains": [],
        "hashes": [],
        "user_agent": None,
        "http_method": None,
        "http_status": None,
        "url": None,
        "file_path": None,
        "process_name": None,
        "risk_level": "low",
        "risk_indicators": [],
        "log_format": "unknown",
        "identifiers": {
            "username": None,
            "emails": [],
            "usernames": []
        },
        "user_information": {
            "username": None,
            "email": None
        }
    }
    
    # IP regex: matches valid IPv4 addresses
    IP_REGEX = r"(?:(25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)"
    PORT_REGEX = r":(\d{1,5})\b"
    DOMAIN_REGEX = r"(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)"
    URL_REGEX = r"https?://[^\s<>\"{}|\\^`\[\]]+"
    USER_AGENT_REGEX = r"User-Agent['\":\s]+([^\n\"']+)"
    HTTP_METHOD_REGEX = r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+"
    HTTP_STATUS_REGEX = r"\s(\d{3})\s"
    EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9_.-]+"
    MOBILEYE_EMAIL_REGEX = re.compile(r"\b([A-Za-z0-9._-]+)@mobileye\.com\b", re.IGNORECASE)
    USERNAME_PATTERNS = [
        re.compile(r"(?:user(?:name)?|account|acct|login|principal|subject|actor)[\s_\-]*(?:name|id)?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.@\\/]+)", re.IGNORECASE),
        re.compile(r"(?:Account Name|TargetUserName|SubjectUserName|TargetUserSid|SubjectUserSid)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.@\\/]+)", re.IGNORECASE),
        re.compile(r"User\s*'([^']+)'", re.IGNORECASE),
        re.compile(r'User\s*"([^"]+)"', re.IGNORECASE)
    ]
    FILE_PATH_REGEX = r"[C-Z]:\\[^\s<>\"|]+\.[a-zA-Z0-9]{1,5}|/(?:[^/\s]+/)+[^/\s]+\.[a-zA-Z0-9]{1,5}"
    PROCESS_REGEX = r"(?:process|exe|program)[\s:=]+([a-zA-Z0-9_\-\.]+\.(exe|dll|bat|sh|py|js))"
    
    def get_nested(data: dict, path: str):
        current = data
        for part in path.split('.'):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    original_log_text = log_text

    try:
        json_data = json.loads(log_text.strip())
        analysis["log_format"] = "json"
        
        # Common JSON log fields
        analysis["timestamp"] = json_data.get("timestamp") or json_data.get("time") or json_data.get("@timestamp") or json_data.get("event_time")
        analysis["message"] = json_data.get("message") or json_data.get("msg") or json_data.get("log")
        analysis["event_type"] = json_data.get("event_type") or json_data.get("event") or json_data.get("type") or json_data.get("event.action")
        analysis["action"] = json_data.get("action") or json_data.get("event.action")

        username_paths = [
            "username",
            "user",
            "user.name",
            "user.username",
            "user.user_name",
            "user.id",
            "user.email",
            "user.identity",
            "userName",
            "user_name",
            "userid",
            "userId",
            "principal.name",
            "principal.username",
            "actor.user",
            "actor.name",
            "actor.username",
            "identity.user",
            "identity.username",
            "identity.userName",
            "winlog.event_data.SubjectUserName",
            "winlog.event_data.TargetUserName",
            "winlog.event_data.TargetDomainName",
            "winlog.event_data.SubjectDomainName",
            "target.user.name",
            "target.user",
            "SubjectUserName",
            "TargetUserName"
        ]
        for path in username_paths:
            candidate = get_nested(json_data, path) if '.' in path else json_data.get(path)
            if isinstance(candidate, dict):
                continue
            if isinstance(candidate, str) and candidate.strip():
                analysis["username"] = candidate.strip()
                break

        analysis["src_ip"] = json_data.get("src_ip") or json_data.get("source.ip") or json_data.get("src") or json_data.get("source_address")
        analysis["dst_ip"] = json_data.get("dst_ip") or json_data.get("destination.ip") or json_data.get("dst") or json_data.get("dest_ip") or json_data.get("destination_address")
        analysis["protocol"] = json_data.get("protocol") or json_data.get("network.protocol") or json_data.get("network.transport")
        analysis["src_port"] = json_data.get("src_port") or json_data.get("source.port") or json_data.get("source_port")
        analysis["dst_port"] = json_data.get("dst_port") or json_data.get("destination.port") or json_data.get("dest_port") or json_data.get("destination_port")
        analysis["http_method"] = json_data.get("http.request.method") or json_data.get("method") or json_data.get("http_method")
        analysis["http_status"] = json_data.get("http.response.status_code") or json_data.get("status_code") or json_data.get("response_code")
        analysis["url"] = json_data.get("url") or json_data.get("http.request.original") or json_data.get("request")
        analysis["user_agent"] = json_data.get("user_agent") or json_data.get("user_agent.original") or json_data.get("http.request.headers.user-agent")
        analysis["file_path"] = json_data.get("file.path") or json_data.get("filepath") or json_data.get("file_name") or json_data.get("winlog.event_data.TargetFilename")
        analysis["process_name"] = json_data.get("process.name") or json_data.get("process_name") or json_data.get("process") or json_data.get("winlog.event_data.Image")
        
        # Extract from nested structures
        if "source" in json_data and isinstance(json_data["source"], dict):
            if not analysis["src_ip"]:
                analysis["src_ip"] = json_data["source"].get("ip")
            if not analysis["src_port"]:
                analysis["src_port"] = json_data["source"].get("port")
        
        if "destination" in json_data and isinstance(json_data["destination"], dict):
            if not analysis["dst_ip"]:
                analysis["dst_ip"] = json_data["destination"].get("ip")
            if not analysis["dst_port"]:
                analysis["dst_port"] = json_data["destination"].get("port")
            
        if "http" in json_data and isinstance(json_data["http"], dict):
            if not analysis["http_method"]:
                analysis["http_method"] = json_data["http"].get("request", {}).get("method")
            if not analysis["http_status"]:
                analysis["http_status"] = json_data["http"].get("response", {}).get("status_code")
            if not analysis["url"]:
                analysis["url"] = json_data["http"].get("request", {}).get("original")
            
        # Continue parsing from the message field if it exists, but keep original for display
        if analysis["message"]:
            log_text_for_parsing = analysis["message"]
        else:
            log_text_for_parsing = log_text
    except (json.JSONDecodeError, AttributeError):
        # Not JSON, continue with regex parsing
        log_text_for_parsing = log_text
    
    # Extract IPs with context - parse both original text and message field if it exists
    # This ensures we catch IPs in structured logs (JSON) and unstructured logs
    texts_to_parse = [original_log_text]  # Always parse original log
    if 'log_text_for_parsing' in locals() and log_text_for_parsing != original_log_text:
        texts_to_parse.append(log_text_for_parsing)  # Also parse message field if different
    
    seen_ips = set()
    
    # Improved patterns that handle camelCase, quoted values, and various separators
    # Pattern matches: sourceIp="1.2.3.4", sourceIp='1.2.3.4', sourceIp=1.2.3.4, source IP="1.2.3.4", source=1.2.3.4, source: 1.2.3.4, etc.
    # Also handles: sourceIp="1.2.3.4" (camelCase with equals and quotes)
    src_ip_camel_pattern = re.compile(rf"(?:src|source)[Ii][Pp]\s*[:=]\s*['\"]?({IP_REGEX})['\"]?", re.IGNORECASE)
    dst_ip_camel_pattern = re.compile(rf"(?:dst|dest|destination)[Ii][Pp]\s*[:=]\s*['\"]?({IP_REGEX})['\"]?", re.IGNORECASE)
    src_ip_pattern = re.compile(rf"(?:src|source)(?:\s+ip|\s+_ip|\s+_address|\s+address)?\s*[:=]\s*['\"]?({IP_REGEX})['\"]?", re.IGNORECASE)
    dst_ip_pattern = re.compile(rf"(?:dst|dest|destination)(?:\s+ip|\s+_ip|\s+_address|\s+address)?\s*[:=]\s*['\"]?({IP_REGEX})['\"]?", re.IGNORECASE)
    
    # Extract source and destination IPs from all texts
    for parsing_text in texts_to_parse:
        # Try camelCase pattern first (e.g., "sourceIp="), then regular pattern
        src_match = src_ip_camel_pattern.search(parsing_text) or src_ip_pattern.search(parsing_text)
        if src_match:
            ip = src_match.group(1)  # Group 1 contains the IP address
            if ip and ip not in seen_ips:
                analysis["ips"].append({"type": "Source", "ip": ip, "context": "src"})
                analysis["src_ip"] = ip
                seen_ips.add(ip)
        
        dst_match = dst_ip_camel_pattern.search(parsing_text) or dst_ip_pattern.search(parsing_text)
        if dst_match:
            ip = dst_match.group(1)  # Group 1 contains the IP address
            if ip and ip not in seen_ips:
                analysis["ips"].append({"type": "Destination", "ip": ip, "context": "dst"})
                analysis["dst_ip"] = ip
                seen_ips.add(ip)
    
    # Extract all remaining IPs that weren't already found (use original log text)
    all_ips = re.finditer(IP_REGEX, original_log_text)
    for match in all_ips:
        ip = match.group(0)  # Group 0 is the full match (the IP address)
        # Filter out localhost, private ranges that are likely false positives, and already seen IPs
        if (ip and 
            ip not in seen_ips and 
            not ip.startswith("127.") and 
            not ip.startswith("0.") and
            not ip.startswith("0.0.0.") and
            len(ip.split('.')) == 4):  # Ensure it's a valid 4-part IP
            analysis["ips"].append({"type": "Network", "ip": ip, "context": "generic"})
            seen_ips.add(ip)
    
    # Extract ports - search in all texts
    if not analysis["src_port"]:
        for text in texts_to_parse:
            src_port_match = re.search(rf"src[^:]*:{PORT_REGEX}", text, re.IGNORECASE)
            if src_port_match:
                analysis["src_port"] = src_port_match.group(1)
                break
    
    if not analysis["dst_port"]:
        for text in texts_to_parse:
            dst_port_match = re.search(rf"dst[^:]*:{PORT_REGEX}", text, re.IGNORECASE)
            if dst_port_match:
                analysis["dst_port"] = dst_port_match.group(1)
                break
    
    # Extract protocol
    if not analysis["protocol"]:
        for text in texts_to_parse:
            protocol_match = re.search(r"\b(TCP|UDP|ICMP|HTTP|HTTPS|FTP|SSH|TLS|SSL|SMTP|DNS)\b", text, re.IGNORECASE)
            if protocol_match:
                analysis["protocol"] = protocol_match.group(1).upper()
                break
    
    # Extract URLs - search in all texts
    all_urls = []
    for text in texts_to_parse:
        urls = re.findall(URL_REGEX, text)
        all_urls.extend(urls)
    analysis["urls"] = list(set(all_urls))
    
    # Extract domains - search in all texts
    all_domains = []
    for text in texts_to_parse:
        domains = re.findall(DOMAIN_REGEX, text)
        all_domains.extend(domains)
    analysis["domains"] = list(set([d.lower() for d in all_domains if "." in d and len(d) > 3]))[:10]
    
    # Extract hashes - search in all texts
    # Hash patterns: MD5 (32), SHA-1 (40), SHA-224 (56), SHA-256 (64), SHA-384 (96), SHA-512 (128)
    # Also supports SHA3 variants with same lengths
    HASH_REGEX = r"\b[A-Fa-f0-9]{32,128}\b"
    seen_hashes = set()
    all_hashes = []
    
    def identify_hash_type(hash_str: str) -> str:
        """Identify the type of hash based on its length."""
        length = len(hash_str)
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA-1"
        elif length == 56:
            return "SHA-224/SHA3-224"
        elif length == 64:
            return "SHA-256/SHA3-256"
        elif length == 96:
            return "SHA-384/SHA3-384"
        elif length == 128:
            return "SHA-512/SHA3-512"
        else:
            return f"Hash ({length} chars)"
    
    for text in texts_to_parse:
        # Find all potential hash strings
        hash_matches = re.finditer(HASH_REGEX, text)
        for match in hash_matches:
            hash_candidate = match.group(0)
            # Only consider valid hash lengths (32, 40, 56, 64, 96, 128)
            if len(hash_candidate) in [32, 40, 56, 64, 96, 128]:
                # Filter out false positives (e.g., long hex strings that aren't hashes)
                # Skip if it looks like an IP address in hex or other common false positives
                if hash_candidate not in seen_hashes:
                    # Additional validation: check if it's not part of a larger hex string
                    start_pos = match.start()
                    end_pos = match.end()
                    # Check boundaries to ensure it's a standalone hash
                    if (start_pos == 0 or not text[start_pos-1:start_pos].isalnum()) and \
                       (end_pos >= len(text) or not text[end_pos:end_pos+1].isalnum()):
                        hash_type = identify_hash_type(hash_candidate)
                        all_hashes.append({
                            "hash": hash_candidate,
                            "type": hash_type,
                            "length": len(hash_candidate)
                        })
                        seen_hashes.add(hash_candidate)
    
    # Also check for hashes in common JSON fields
    try:
        json_data = json.loads(original_log_text.strip())
        hash_fields = [
            "hash", "file_hash", "md5", "sha1", "sha256", "sha512", 
            "sha-1", "sha-256", "sha-512", "sha384", "sha-384",
            "sha224", "sha-224", "checksum", "digest", "fingerprint"
        ]
        for field in hash_fields:
            # Check direct field
            if field in json_data and isinstance(json_data[field], str):
                hash_val = json_data[field].strip()
                if hash_val and hash_val not in seen_hashes:
                    if len(hash_val) in [32, 40, 56, 64, 96, 128] and re.match(r"^[A-Fa-f0-9]+$", hash_val):
                        hash_type = identify_hash_type(hash_val)
                        all_hashes.append({
                            "hash": hash_val,
                            "type": hash_type,
                            "length": len(hash_val)
                        })
                        seen_hashes.add(hash_val)
            # Check nested fields (e.g., file.hash, file.md5)
            for key_path in ["file.hash", "file.md5", "file.sha1", "file.sha256", 
                           "event.file.hash", "event.file.md5", "event.file.sha256"]:
                parts = key_path.split(".")
                current = json_data
                for part in parts:
                    if isinstance(current, dict) and part in current:
                        current = current[part]
                    else:
                        current = None
                        break
                if isinstance(current, str) and current.strip() and current.strip() not in seen_hashes:
                    hash_val = current.strip()
                    if len(hash_val) in [32, 40, 56, 64, 96, 128] and re.match(r"^[A-Fa-f0-9]+$", hash_val):
                        hash_type = identify_hash_type(hash_val)
                        all_hashes.append({
                            "hash": hash_val,
                            "type": hash_type,
                            "length": len(hash_val)
                        })
                        seen_hashes.add(hash_val)
    except (json.JSONDecodeError, AttributeError, TypeError):
        pass  # Not JSON or parsing failed, continue
    
    analysis["hashes"] = all_hashes
    
    # Extract user agent
    if not analysis["user_agent"]:
        for text in texts_to_parse:
            ua_match = re.search(USER_AGENT_REGEX, text, re.IGNORECASE)
            if ua_match:
                analysis["user_agent"] = ua_match.group(1).strip()
                break
    
    # Extract HTTP method
    if not analysis["http_method"]:
        for text in texts_to_parse:
            method_match = re.search(HTTP_METHOD_REGEX, text)
            if method_match:
                analysis["http_method"] = method_match.group(1)
                break
    
    # Extract HTTP status
    if not analysis["http_status"]:
        for text in texts_to_parse:
            status_match = re.search(HTTP_STATUS_REGEX, text)
            if status_match:
                analysis["http_status"] = status_match.group(1)
                break
    
    # Extract username
    if not analysis["username"]:
        for text in texts_to_parse:
            for pattern in USERNAME_PATTERNS:
                user_match = pattern.search(text)
                if user_match:
                    username_candidate = user_match.group(1).strip()
                    if username_candidate:
                        analysis["username"] = username_candidate
                        break
            if analysis["username"]:
                break

    def add_unique(collection, value):
        if value and value not in collection:
            collection.append(value)

    for text in texts_to_parse:
        for pattern in USERNAME_PATTERNS:
            user_match = pattern.search(text)
            if user_match:
                username_candidate = user_match.group(1).strip()
                add_unique(analysis["identifiers"]["usernames"], username_candidate)

        for email_match in re.finditer(EMAIL_REGEX, text):
            add_unique(analysis["identifiers"]["emails"], email_match.group(0).strip())

        for mobileye_match in MOBILEYE_EMAIL_REGEX.finditer(text):
            mobileye_username = mobileye_match.group(1).strip()
            mobileye_email = mobileye_match.group(0).strip()
            if mobileye_username:
                analysis["user_information"]["username"] = mobileye_username
                analysis["user_information"]["email"] = mobileye_email
                add_unique(analysis["identifiers"]["usernames"], mobileye_username)
                add_unique(analysis["identifiers"]["emails"], mobileye_email)
                analysis["username"] = mobileye_username

    if not analysis["username"] and analysis["identifiers"]["emails"]:
        analysis["username"] = analysis["identifiers"]["emails"][0]

    # Extract file paths
    if not analysis["file_path"]:
        for text in texts_to_parse:
            file_match = re.search(FILE_PATH_REGEX, text)
            if file_match:
                analysis["file_path"] = file_match.group(0)
                break
    
    # Extract process name
    if not analysis["process_name"]:
        for text in texts_to_parse:
            process_match = re.search(PROCESS_REGEX, text, re.IGNORECASE)
            if process_match:
                analysis["process_name"] = process_match.group(1)
                break
    
    # Extract timestamp (various formats) - check all texts
    if not analysis["timestamp"]:
        timestamp_patterns = [
            r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
            r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})",
            r"(\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
            r"(\d{10,13})"  # Unix timestamp
        ]
        for text in texts_to_parse:
            for pattern in timestamp_patterns:
                ts_match = re.search(pattern, text)
                if ts_match:
                    analysis["timestamp"] = ts_match.group(1)
                    break
            if analysis["timestamp"]:
                break
    
    # Extract event type and action - search in all texts
    if not analysis["event_type"]:
        event_keywords = ["login", "logout", "access", "denied", "allowed", "blocked", "failed", "success", "error", "alert", "attack", "malware", "virus", "firewall", "intrusion"]
        for text in texts_to_parse:
            for keyword in event_keywords:
                if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
                    analysis["event_type"] = keyword.upper()
                    break
            if analysis["event_type"]:
                break
    
    # Risk assessment - use original log text for comprehensive risk analysis
    risk_keywords_high = ["denied", "blocked", "failed", "attack", "malware", "virus", "intrusion", "exploit", "breach", "unauthorized", "suspicious"]
    risk_keywords_medium = ["error", "warning", "alert", "unusual", "anomaly", "abnormal"]
    
    risk_score = 0
    for keyword in risk_keywords_high:
        if re.search(rf"\b{keyword}\b", original_log_text, re.IGNORECASE):
            risk_score += 3
            analysis["risk_indicators"].append(keyword.upper())
    
    for keyword in risk_keywords_medium:
        if re.search(rf"\b{keyword}\b", original_log_text, re.IGNORECASE):
            risk_score += 1
            analysis["risk_indicators"].append(keyword.upper())
    
    # Check for suspicious ports
    if analysis["dst_port"]:
        suspicious_ports = ["4444", "5555", "6666", "6667", "12345", "31337"]
        if analysis["dst_port"] in suspicious_ports:
            risk_score += 2
            analysis["risk_indicators"].append(f"SUSPICIOUS_PORT:{analysis['dst_port']}")
    
    # Check for suspicious HTTP status codes
    if analysis["http_status"]:
        if analysis["http_status"].startswith("4") or analysis["http_status"].startswith("5"):
            risk_score += 1
    
    # Determine risk level
    if risk_score >= 5:
        analysis["risk_level"] = "high"
    elif risk_score >= 2:
        analysis["risk_level"] = "medium"
    else:
        analysis["risk_level"] = "low"
    
    # Generate activity summary
    activity_parts = []
    if analysis["event_type"]:
        activity_parts.append(analysis["event_type"])
    if analysis["protocol"]:
        activity_parts.append(analysis["protocol"])
    if analysis["src_ip"] and analysis["dst_ip"]:
        activity_parts.append(f"{analysis['src_ip']} → {analysis['dst_ip']}")
    elif analysis["src_ip"]:
        activity_parts.append(f"From {analysis['src_ip']}")
    elif analysis["dst_ip"]:
        activity_parts.append(f"To {analysis['dst_ip']}")
    if analysis["dst_port"]:
        activity_parts.append(f"Port {analysis['dst_port']}")
    if analysis["http_method"]:
        activity_parts.append(analysis["http_method"])
    
    analysis["activity_summary"] = " | ".join(activity_parts) if activity_parts else "Log entry analyzed"
    
    # Store original log text for display
    analysis["text"] = original_log_text
    
    return analysis

@app.route("/analyze_log", methods=["POST"])
def analyze_log():
    """
    Analyzes SIEM log entries comprehensively and returns detailed analysis.
    """
    log_text = request.form.get("log_text", "")
    if not log_text:
        return redirect(url_for('home'))

    # Parse the log
    analysis = parse_siem_log(log_text)
    
    print(f"[LogAnalyzer] Analysis complete - Risk: {analysis['risk_level']}, IPs: {len(analysis['ips'])}, Format: {analysis['log_format']}")

    news_data = get_cyber_news()
    
    return render_template(
        "index.html",
        result=None,
        query="",
        vt=None,
        ipdb=None,
        malicious=0,
        suspicious=0,
        harmless=0,
        undetected=0,
        timeout=0,
        news=news_data,
        log_analysis_results=analysis
    )
# ================================


# ---------- run ----------
if __name__ == "__main__":
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    print(">>> Flask starting on http://127.0.0.1:5000")
    print(">>> NOTE: Make sure you have created a .env file with your API keys.")
    print(">>> DEBUG MODE IS ON. Server will auto-reload on code changes.")
    app.run(host="127.0.0.1", port=5000, debug=True)