from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import requests
import urllib.parse
import email
from email.policy import default
import re

app = FastAPI()

# This tells the backend it is allowed to talk to your HTML file
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ⚠️ ENTER YOUR REAL VIRUSTOTAL API KEY HERE
VIRUSTOTAL_API_KEY = "f4817bac524d80eee5f4cdfbbdb493751910594f7ce0ea37d61a88a957fbc0d9"

@app.post("/analyze-full-email/")
async def analyze_full_email(request: Request):
    """
    Receives raw email text from the frontend, parses the true sender, 
    extracts links, and checks live threat feeds.
    """
    data = await request.json()
    raw_email_text = data.get("email_content", "")
    
    if not raw_email_text:
        raise HTTPException(status_code=400, detail="No email content provided")

    # 1. Parse the Raw Email Headers
    msg = email.message_from_string(raw_email_text, policy=default)
    
    sender = msg.get('From', 'Unknown Sender')
    auth_results = msg.get('Authentication-Results', 'No Auth Headers Found')
    
    # 2. Extract Body Text
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode(errors="ignore")
                break
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")
        
    if not body:
        body = raw_email_text

    # 3. Extract Links
    url_regex = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    links = list(set(re.findall(url_regex, body)))
    
    # 4. Live VirusTotal Intel (Checking the first found link)
    vt_results = {"status": "clean", "details": "No links scanned"}
    if links and VIRUSTOTAL_API_KEY != "YOUR_VIRUSTOTAL_API_KEY_HERE":
        domain = urllib.parse.urlparse(links[0]).netloc
        vt_url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}"
        headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
        
        try:
            response = requests.get(vt_url, headers=headers)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                if malicious > 0:
                    vt_results = {"status": "malicious", "details": f"Flagged by {malicious} security vendors"}
                else:
                    vt_results = {"status": "clean", "details": f"Scanned clean by VirusTotal"}
        except Exception as e:
            vt_results = {"status": "error", "details": "Failed to reach threat feed"}

    # 5. Check Authentication (SPF/DKIM)
    failed_auth = "fail" in auth_results.lower() or "softfail" in auth_results.lower()

    # 6. Send the parsed data back to the JavaScript Frontend
    return {
        "metadata": {
            "sender": sender,
            "auth_status": "FAILED" if failed_auth else "PASSED",
            "raw_auth_header": auth_results
        },
        "links_found": links,
        "threat_intel": vt_results
    }
