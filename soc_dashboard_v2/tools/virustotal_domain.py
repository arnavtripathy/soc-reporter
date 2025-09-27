import requests
def vt_domain(domain, vt_key):
    """
    Returns: {
      "data": <raw VT JSON>,
      "gui_url": "https://www.virustotal.com/gui/domain/<domain>"
    }
    """
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": vt_key}
    vt_domain_json = requests.get(url, headers=headers, timeout=20).json()
    results = vt_domain_parse(vt_domain_json)
    return {
        "asset": domain,
        "results": results,
        "gui_url": f"https://www.virustotal.com/gui/domain/{domain}",
    }

def vt_domain_parse(vt_domain_json):
    """
    Parses the VT domain JSON response and returns a dictionary with relevant information.
    """
    if "data" not in vt_domain_json:
        return {"error": "No data found in VT response"}

    data = vt_domain_json["data"]
    attributes = data.get("attributes", {})
    
    results = {
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
        "last_analysis_date": attributes.get("last_analysis_date", {}),
        "creation_date": attributes.get("creation_date"),
        "registrar": attributes.get("registrar"),
        "last_modification_date": attributes.get("last_modification_date"),
        "whois": attributes.get("whois"),
    }
    
    return results
