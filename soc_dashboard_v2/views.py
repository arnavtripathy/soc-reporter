from django.shortcuts import render
from django.conf import settings
import json
from .forms import VTHashLookupForm

ABUSEIPDB_API_KEY = settings.ABUSEIPDB_API_KEY
VIRUSTOTAL_API_KEY = settings.VIRUSTOTAL_API_KEY

# import the vt helper you already wrote
from .tools.virustotal_hash import vt_hash

def vt_hash_lookup_view(request):
    """
    Show a small form to input a VirusTotal file hash and display results.
    """
    api_key = VIRUSTOTAL_API_KEY
    form = VTHashLookupForm(request.POST or None)
    context = {"form": form, "results": None, "results_json": None, "gui_url": None, "error": None}

    if request.method == "POST" and form.is_valid():
        file_hash = form.cleaned_data["file_hash"].strip()
        if not api_key:
            context["error"] = "VirusTotal API key not configured. Set settings.VIRUSTOTAL_API_KEY or VT_API_KEY env var."
        else:
            try:
                response = vt_hash(file_hash, api_key)
            except Exception as e:
                context["error"] = f"Error while calling VT API: {e}"
            else:
                # vt_hash should ideally return dict with results or error
                if not isinstance(response, dict):
                    context["error"] = "Unexpected response from vt_hash (expected dict)."
                elif response.get("error"):
                    context["error"] = response.get("error")
                else:
                    # Pick common fields for nicer display and also keep pretty JSON
                    context["results"] = response.get("results", {}) or {}
                    context["asset"] = response.get("asset", file_hash)
                    context["gui_url"] = response.get("gui_url")
                    try:
                        context["results_json"] = json.dumps(context["results"], indent=2, sort_keys=True)
                    except Exception:
                        context["results_json"] = str(context["results"])

    return render(request, "vt_hash_lookup.html", context)
