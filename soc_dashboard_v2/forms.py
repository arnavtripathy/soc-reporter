from django import forms

class VTHashLookupForm(forms.Form):
    file_hash = forms.CharField(
        label="VirusTotal file hash (MD5/SHA1/SHA256)",
        max_length=200,
        widget=forms.TextInput(attrs={
            "placeholder": "Enter file hash (e.g. 44d88612fea8a8f36de82e1278abb02f)",
            "class": "form-control",
            "autocomplete": "off"
        })
    )