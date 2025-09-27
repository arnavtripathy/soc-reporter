import requests
def vt_ip(ip, vt_key):
    """
    Returns: {
      "data": <raw VT JSON>,
      "gui_url": "https://www.virustotal.com/gui/ip-address/<ip>"
    }
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": vt_key}
    vt_ip_json = requests.get(url, headers=headers, timeout=20).json()
    results = vt_ip_parse(vt_ip_json)
    return {
        "asset": ip,
        "results": results,
        "gui_url": f"https://www.virustotal.com/gui/ip-address/{ip}",
    }

def vt_ip_parse(vt_ip_json):
    """
    Parses the VT IP JSON response and returns a dictionary with relevant information.
    """
    if "data" not in vt_ip_json:
        return {"error": "No data found in VT response"}

    data = vt_ip_json["data"]
    attributes = data.get("attributes", {})
    
    results = {
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "network": attributes.get("network"),
        "whois": attributes.get("whois"),
    }
    
    return results