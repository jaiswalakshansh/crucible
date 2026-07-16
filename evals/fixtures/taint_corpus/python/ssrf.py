import requests


def fetch(request):
    url = request.args.get("url")
    return requests.get(url)  # sink: SSRF
