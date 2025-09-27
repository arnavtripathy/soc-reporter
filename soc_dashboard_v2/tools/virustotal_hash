import requests

def vt_hash(file_hash, vt_key):
    """
    Returns: {
      "data": <raw VT JSON>,
      "gui_url": "https://www.virustotal.com/gui/file/<hash>"
    }
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "x-apikey": vt_key}
    vt_hash_json = requests.get(url, headers=headers, timeout=20).json()
    results = vt_hash_parse(vt_hash_json)
    return {
        "asset": file_hash,
        "results": results,
        "gui_url": f"https://www.virustotal.com/gui/file/{file_hash}",
    }

def vt_hash_parse(vt_hash_json):
    """
    Parses the VT file hash JSON response and returns a dictionary with relevant information.
    """
    if "data" not in vt_hash_json:
        return {"error": "No data found in VT response"}

    data = vt_hash_json["data"]
    attributes = data.get("attributes", {})

    results = {
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "first_submission_date": attributes.get("first_submission_date"),
        "last_submission_date": attributes.get("last_submission_date"),
        "times_submitted": attributes.get("times_submitted"),
        "magic": attributes.get("magic"),  # file magic string
        "meaningful_name": attributes.get("meaningful_name"),  # filename if available
        "type_description": attributes.get("type_description"),  # file type
        "size": attributes.get("size"),
        "md5": attributes.get("md5"),
        "sha1": attributes.get("sha1"),
        "sha256": attributes.get("sha256"),
    }

    return results