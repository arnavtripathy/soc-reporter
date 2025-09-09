# soc_dashboard/services.py
import base64
import requests

def _b64_urlsafe_nopad(s: str) -> str:
    """VT url_id = base64url(no padding) of the literal URL string."""
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8").rstrip("=")

def vt_domain(domain, vt_key):
    """
    Returns: {
      "data": <raw VT JSON>,
      "gui_url": "https://www.virustotal.com/gui/domain/<domain>"
    }
    """
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": vt_key}
    r = requests.get(url, headers=headers, timeout=20)
    out = r.json()
    return {
        "data": out,
        "gui_url": f"https://www.virustotal.com/gui/domain/{domain}",
    }

def vt_url_scan(u, vt_key):
    """
    Submits the URL to VT, then fetches the analysis once (no polling loop).
    Returns: {
      "data": <analysis JSON or submit JSON>,
      "gui_url": "https://www.virustotal.com/gui/url/<url_id>",
      "analysis_url": "https://www.virustotal.com/gui/analysis/<analysis_id>"  # when available
    }
    """
    submit_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"accept": "application/json", "x-apikey": vt_key}
    submit = requests.post(submit_url, headers=headers, data={"url": u}, timeout=20)
    submit_json = submit.json()

    url_id = _b64_urlsafe_nopad(u)
    gui_url = f"https://www.virustotal.com/gui/url/{url_id}"

    analysis_id = submit_json.get("data", {}).get("id")
    if not analysis_id:
        # Return submit response + GUI link to the URL item
        return {
            "data": submit_json,
            "gui_url": gui_url,
        }

    analysis_url = f"https://www.virustotal.com/gui/analysis/{analysis_id}"
    fetch_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    analysis = requests.get(fetch_url, headers=headers, timeout=20).json()

    return {
        "data": analysis,
        "gui_url": gui_url,
        "analysis_url": analysis_url,
    }




def abuseipdb_check(ip, abuse_key):
    """
    Returns: {
      "data": <raw AbuseIPDB JSON>,
      "gui_url": "https://www.abuseipdb.com/check/<ip>"
    }
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": abuse_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(url, headers=headers, params=params, timeout=20)
    out = r.json()
    return {
        "data": out,
        "gui_url": f"https://www.abuseipdb.com/check/{ip}",
    }

def abuseipdb_reports(ip, abuse_key, per_page=10):
    """
    Fetch up to `per_page` recent reports for an IP from AbuseIPDB.
    Returns {
        "data": <raw API response>,
        "results": [ { reportedAt, comment, country }, ... ],
        "gui_url": "https://www.abuseipdb.com/check/<ip>"
    }
    """
    url = "https://api.abuseipdb.com/api/v2/reports"
    headers = {"Key": abuse_key, "Accept": "application/json"}
    params = {
        "ipAddress": ip,
        "perPage": per_page,
        "maxAgeInDays": 180,
        "page": 1
    }

    r = requests.get(url, headers=headers, params=params, timeout=20)
    out = r.json()

    results = []
    for row in out.get("data", {}).get("results", []):
        results.append({
            "reportedAt": row.get("reportedAt"),
            "comment": row.get("comment"),
            "country": row.get("reporterCountryName"),
        })

    return {
        "data": out,
        "results": results,
        "gui_url": f"https://www.abuseipdb.com/check/{ip}",
    }


def defang(value: str) -> str:
    """
    Defang URLs and IP addresses to make them safe for reports.
    Examples:
        http://malicious.com → hxxp://malicious[.]com
        https://1.2.3.4 → hxxps://1[.]2[.]3[.]4
    """
    if not value:
        return value

    # Defang protocols
    value = value.replace("http://", "hxxp://")
    value = value.replace("https://", "hxxps://")

    # Defang IPs/domains
    value = value.replace(".", "[.]")

    return value
