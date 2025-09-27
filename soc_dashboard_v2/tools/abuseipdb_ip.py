import requests

def abuseipdb_check(ip, abuseibdb_key):
    """
    Returns: {
      "data": <raw AbuseIPDB JSON>,
      "gui_url": "https://www.abuseipdb.com/check/<ip>"
    }
    """
    url = "https://api.abuseipdb.com/api/v2/check" #IP details
    headers = {"Key": abuseibdb_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    abuseipdb_json = requests.get(url, headers=headers, params=params, timeout=20).json()
    results = abuseipdb_parse(abuseipdb_json)
    report_results = abuseipdb_reports(ip, abuseibdb_key, per_page=5)
    return {
        "asset": ip,
        "ip_results": results,
        "report_results": report_results,
        "gui_url": f"https://www.abuseipdb.com/check/{ip}",
    }

def abuseipdb_reports(ip, abuseibdb_key, per_page=10):
    """
    Fetch up to `per_page` recent reports for an IP from AbuseIPDB.
    Returns {
        "data": <raw API response>,
        "results": [ { reportedAt, comment, country }, ... ],
        "gui_url": "https://www.abuseipdb.com/check/<ip>"
    }
    """
    url = "https://api.abuseipdb.com/api/v2/reports"
    headers = {"Key": abuseibdb_key, "Accept": "application/json"}
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


def abuseipdb_parse(abuseipdb_json):
    """
    Parses the AbuseIPDB JSON response and returns a dictionary with relevant information.
    """
    if "data" not in abuseipdb_json:
        return {"error": "No data found in AbuseIPDB response"}

    data = abuseipdb_json["data"]
    
    results = {
        "abuseConfidenceScore": data.get("abuseConfidenceScore"),
        "countryCode": data.get("countryCode"),
        "usageType": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "totalReports": data.get("totalReports"),
        "lastReportedAt": data.get("lastReportedAt"),
    }
    
    return results