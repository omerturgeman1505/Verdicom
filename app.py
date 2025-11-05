import re
import os
import requests
from bs4 import BeautifulSoup  # <-- 1. ייבוא חדש
from flask import Flask, request, render_template
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

# ======= LOAD KEYS SAFELY =======
VT_API_KEY = os.environ.get("VT_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
RAPIDAPI_KEY = os.environ.get("RAPIDAPI_KEY") # (כרגע לא בשימוש לחדשות)
# ================================

# --- 2. פונקציית חדשות מעודכנת (Web Scraping) ---
def get_cyber_news():
    """Fetches top 5 cyber news headlines by scraping The Hacker News."""
    URL = "https://thehackernews.com/"
    news_items = []
    
    try:
        print(f"[News] Scraping news from {URL}")
        
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
        headers = {"User-Agent": user_agent}
        
        r = requests.get(URL, headers=headers, timeout=10)
        
        if r.status_code != 200:
            print(f"[News] Error: Got status code {r.status_code}")
            return []

        # ניתוח ה-HTML שהורדנו
        soup = BeautifulSoup(r.text, 'html.parser')
        
        # חיפוש כל הכותרות. (זהו ה-selector הנכון לאתר הזה)
        headlines = soup.find_all('h3', class_='home-title', limit=5)
        
        for item in headlines:
            link_tag = item.find_parent('a')
            if link_tag and link_tag.has_attr('href'):
                news_items.append({
                    "title": item.text.strip(), # .strip() מנקה רווחים מיותרים
                    "link": link_tag['href']
                })
            
        print(f"[News] Found {len(news_items)} items via scraping.")
    except Exception as e:
        print(f"Error scraping cyber news: {e}")
    return news_items
# --- סוף העדכון ---


# ---------- helpers ----------
_ipv4 = re.compile(r"^((25[0-5]|2[0-4]\d|1?\d?\d)(\.|$)){4}$")
_domain = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
_md5 = re.compile(r"^[A-Fa-f0-9]{32}$")
_sha1 = re.compile(r"^[A-Fa-f0-9]{40}$")
_sha256 = re.compile(r"^[A-Fa-f0-9]{64}$")

def guess_type(q: str) -> str:
    q = (q or "").strip()
    if _ipv4.match(q): return "ip"
    if _domain.match(q): return "domain"
    if _sha256.match(q) or _sha1.match(q) or _md5.match(q): return "hash"
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

    # Handle search result (data is a list)
    if isinstance(d, list):
        if not d: # Empty search result
            return {"name": "Not Found", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 0, "community_score": 0, "kind": "—", "detections": []}
        d = d[0] # Take the first result

    # Handle single entity (data is a dict)
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
                "result": details.get('result'), # Can be None if clean
                "category": details.get('category', 'unknown') # e.g., 'harmless', 'malicious'
            })
        
        # Custom sorting logic for detections
        category_order = {
            "malicious": 1,
            "suspicious": 2,
            "harmless": 3,
            "undetected": 4,
            "timeout": 5, 
            "type-unsupported": 6,
            "unknown": 7
        }
        
        detections_list.sort(key=lambda x: (category_order.get(x['category'], 99), x['engine']))
    
    return {
        "kind": kind,
        "name": name,
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
    try:
        r = requests.get(url, headers=headers, timeout=20)
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
    except Exception as e:
        return None, f"Network error: {e}"

def get_abuseipdb_info(ip: str):
    if not ABUSEIPDB_API_KEY:
        return None, "ABUSEIPDB_API_KEY is not configured."
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=20)
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
    except Exception as e:
        return None, f"Network error: {e}"

# ---------- routes ----------
@app.route("/", methods=["GET"])
def home():
    news_data = get_cyber_news()
    missing = []
    if not VT_API_KEY: missing.append("VT_API_KEY")
    if not ABUSEIPDB_API_KEY: missing.append("ABUSEIPDB_API_KEY")
    # אין צורך לבדוק את RAPIDAPI_KEY כרגע
    
    result = ("Missing API keys. Set them in your .env file: " + ", ".join(missing)) if missing else None
    return render_template("index.html", result=result, query="", vt=None, ipdb=None,
                           malicious=0, suspicious=0, harmless=0, undetected=0, timeout=0,
                           news=news_data)

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
        vt_summary = {} # Will use defaults below

    ipdb_view = None
    ipdb_err = None
    if guess_type(query) == "ip":
        ipdb_view, ipdb_err = get_abuseipdb_info(query)
        if not ipdb_view:
            ipdb_view = {
                "abuseScore": "None", "totalReports": "None", "country": "None",
                "isp": "None", "domain": "None", "flag_url": None, "reports": []
            }

    # Get all chart data directly from the summary
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