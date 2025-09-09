# views.py
import requests
from datetime import datetime

from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt

from django.conf import settings



# 🔹 use the service wrappers that add gui_url etc.
from .services import vt_domain, abuseipdb_check, abuseipdb_reports, vt_url_scan, defang


ABUSEIPDB_API_KEY = settings.ABUSEIPDB_API_KEY
VIRUSTOTAL_API_KEY = settings.VIRUSTOTAL_API_KEY

@csrf_exempt
def check_abuseipdb_ip(request):
    """
    Renders soc_dashboard/check_ip.html with:
      - result   : inner AbuseIPDB "data" object
      - gui_url  : link to open the IP on abuseipdb.com
      - error    : error string if any
    """
    context = {}

    if request.method == "POST":
        ip_address = request.POST.get("ip", "").strip()

        if not ip_address:
            context["error"] = "No IP address provided"
            return render(request, "check_ip.html", context)

        try:
            summary = abuseipdb_check(ip_address, ABUSEIPDB_API_KEY)
            summary_raw = summary.get("data", {})          # full JSON
            inner = summary_raw.get("data", {})            # AbuseIPDB inner "data"
            reports_resp = abuseipdb_reports(ip_address, ABUSEIPDB_API_KEY, per_page=10)
            reports = reports_resp.get("results", [])


            context.update({
                "result": inner,                           # existing table uses this
                "reports": reports,                        # <-- add reports
                "gui_url": summary.get("gui_url"),         # link to AbuseIPDB site
            })
        except Exception as e:
            context["error"] = str(e)

    # NOTE: make sure your template path matches your files
    return render(request, "check_ip.html", context)


def phishing_form(request):
    # Just render the phishing investigation form template
    return render(request, "phishing_form.html")


@csrf_exempt
def vt_domain_lookup(request):
    """
    Renders soc_dashboard/vt_domain_report.html with:
      - result / flagged_vendors
      - creation/expiration/last_update/last_modification/last_analysis dates (converted)
      - registration_date from RDAP if present
      - crowdsourced_context list
      - whois raw text
      - gui_url (VT web link)
    """
    context = {}

    if request.method == "POST":
        domain = request.POST.get("domain", "").strip()

        if not domain:
            context["error"] = "No domain provided"
            return render(request, "vt_domain_report.html", context)

        try:
            resp = vt_domain(domain, VIRUSTOTAL_API_KEY)
            # resp = {"data": <VT raw top-level JSON>, "gui_url": ".../gui/domain/<domain>"}
            vt_raw_top = resp.get("data", {})
            result = vt_raw_top.get("data", {})   # VT's 'data' node
            context["gui_url"] = resp.get("gui_url")

            if "attributes" in result:
                attrs = result["attributes"]

                # Vendors flagged
                stats = attrs.get("last_analysis_stats", {}) or {}
                flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))

                # Dates (UNIX -> datetime)
                def as_dt(key):
                    v = attrs.get(key)
                    return datetime.utcfromtimestamp(v) if isinstance(v, (int, float)) else None

                last_analysis_date     = as_dt("last_analysis_date")
                creation_date          = as_dt("creation_date")
                expiration_date        = as_dt("expiration_date")
                last_update_date       = as_dt("last_update_date")
                last_modification_date = as_dt("last_modification_date")

                # WHOIS
                whois_raw = attrs.get("whois", "")

                # Registration date from RDAP (string like "1995-04-06T00:00:00Z")
                registration_date = None
                for event in (attrs.get("rdap", {}) or {}).get("events", []):
                    if event.get("event_action") == "registration":
                        registration_date = event.get("event_date")
                        break

                # Crowdsourced context
                crowd_context = attrs.get("crowdsourced_context", []) or []

                context.update({
                    "result": result,  # keep original structure for template fields already using it
                    "flagged_vendors": flagged,
                    "last_analysis_date": last_analysis_date,
                    "registration_date": registration_date,
                    "creation_date": creation_date,
                    "expiration_date": expiration_date,
                    "last_update_date": last_update_date,
                    "last_modification_date": last_modification_date,
                    "whois": whois_raw,
                    "crowdsourced_context": crowd_context,
                })
            else:
                context["error"] = "No attributes found in VirusTotal response."
        except Exception as e:
            context["error"] = str(e)

    return render(request, "vt_domain_report.html", context)

@csrf_exempt
def vt_url_lookup(request):
    """
    Submit a URL to VirusTotal, fetch one analysis, and render a copy-paste friendly table.
    Context:
      - stats (harmless/malicious/suspicious/undetected/flagged)
      - status (queued/completed)
      - analysis_date (UTC)
      - gui_url (VT URL item page)
      - analysis_url (VT analysis page, when available)
      - raw (full API JSON in case you want to debug)
    """
    context = {}
    if request.method == "POST":
        url_input = (request.POST.get("url") or "").strip()
        if not url_input:
            context["error"] = "No URL provided"
            return render(request, "vt_url_report.html", context)

        try:
            resp = vt_url_scan(url_input, VIRUSTOTAL_API_KEY)
            context["gui_url"] = resp.get("gui_url")
            context["analysis_url"] = resp.get("analysis_url")
            analysis = resp.get("data", {})  # this is the /analyses/<id> JSON (or submit JSON fallback)

            # When we got an analysis JSON, VT shape is: data -> attributes
            data_node = analysis.get("data", {})
            attrs = data_node.get("attributes", {}) if isinstance(data_node, dict) else {}

            # Stats can appear as 'stats' (analyses) or 'last_analysis_stats' (entities); handle both.
            raw_stats = attrs.get("stats") or attrs.get("last_analysis_stats") or {}
            stats = {
                "harmless": raw_stats.get("harmless", 0),
                "malicious": raw_stats.get("malicious", 0),
                "suspicious": raw_stats.get("suspicious", 0),
                "undetected": raw_stats.get("undetected", 0),
            }
            stats["flagged"] = int(stats["malicious"]) + int(stats["suspicious"])

            # Analysis status & date (analysis attributes usually contain status + date UNIX)
            status = attrs.get("status")
            analysis_date = None
            if isinstance(attrs.get("date"), (int, float)):
                analysis_date = datetime.utcfromtimestamp(attrs["date"])

            context.update({
                "input_url": url_input,
                "status": status,
                "analysis_date": analysis_date,
                "stats": stats,
                "raw": analysis,  # optional: handy for debug
            })

            # If we didn’t get an analysis (e.g., submit error), surface that
            if not data_node and not attrs:
                context["info"] = "Submitted to VT. Analysis might still be queued. Use the link to check later."
        except Exception as e:
            context["error"] = str(e)

    return render(request, "vt_url_report.html", context)

@csrf_exempt
def dynamic_scan_form(request):
    return render(request, "soc_form.html")


@csrf_exempt
def submit_dynamic_scan(request):
    results = []

    if request.method == "POST":
        fields = []
        for key, value in request.POST.items():
            if key.startswith("field_name_"):
                suffix = key.split("_")[-1]
                fields.append({
                    "name": value.strip(),
                    "type": request.POST.get(f"asset_type_{suffix}", "").lower(),
                    "value": defang(request.POST.get(f"field_value_{suffix}", "").strip()),
                })

        for f in fields:
            r = {"field": f, "error": None}

            try:
                if f["type"] == "ip":
                    # AbuseIPDB only
                    abuse_data = abuseipdb_check(f["value"], ABUSEIPDB_API_KEY)
                    inner = abuse_data.get("data", {}).get("data", {})  # IP info is inside data.data
                    reports_resp = abuseipdb_reports(f["value"], ABUSEIPDB_API_KEY, per_page=10)
                    reports = reports_resp.get("results", [])  # if using verbose

                    r.update({
                        "template": "partials/abuseipdb_partial.html",
                        "result": inner,
                        "reports": reports,
                        "gui_url": abuse_data.get("gui_url"),
                    })

                elif f["type"] == "domain":
                    vt_data = vt_domain(f["value"], VIRUSTOTAL_API_KEY)
                    result = vt_data.get("data", {}).get("data", {})
                    attrs = result.get("attributes", {})
                    registration_date = None
                    for event in (attrs.get("rdap", {}) or {}).get("events", []):
                        if event.get("event_action") == "registration":
                            registration_date = event.get("event_date")
                            break

                    flagged = int(attrs.get("last_analysis_stats", {}).get("malicious", 0)) + \
                              int(attrs.get("last_analysis_stats", {}).get("suspicious", 0))

                    r.update({
                        "template": "partials/vt_domain_partial.html",
                        "result": result,
                        "flagged_vendors": flagged,
                        "registration_date": registration_date,
                        "last_analysis_date": attrs.get("last_analysis_date"),
                        "crowdsourced_context": attrs.get("crowdsourced_context", []),
                        "whois": attrs.get("whois", ""),
                        "gui_url": vt_data.get("gui_url"),
                    })

                elif f["type"] == "url":
                    vt_data = vt_url_scan(f["value"], VIRUSTOTAL_API_KEY)
                    analysis = vt_data.get("data", {})
                    data_node = analysis.get("data", {})
                    attrs = data_node.get("attributes", {}) if isinstance(data_node, dict) else {}

                    raw_stats = attrs.get("stats") or attrs.get("last_analysis_stats") or {}
                    stats = {
                        "harmless": raw_stats.get("harmless", 0),
                        "malicious": raw_stats.get("malicious", 0),
                        "suspicious": raw_stats.get("suspicious", 0),
                        "undetected": raw_stats.get("undetected", 0),
                    }
                    stats["flagged"] = int(stats["malicious"]) + int(stats["suspicious"])

                    r.update({
                        "template": "partials/vt_url_partial.html",
                        "status": attrs.get("status"),
                        "analysis_date": datetime.utcfromtimestamp(attrs["date"]), #attrs.get("date"),
                        "stats": stats,
                        "gui_url": vt_data.get("gui_url"),
                        "analysis_url": vt_data.get("analysis_url"),
                    })

                else:
                    r["template"] = None
                    r["error"] = "No scan for text input."

            except Exception as e:
                r["error"] = str(e)

            results.append(r)

    return render(request, "soc_report.html", {"results": results})
