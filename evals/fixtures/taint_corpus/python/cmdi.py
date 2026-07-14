import os


def ping(request):
    host = request.args.get("host")
    os.system("ping -c 1 " + host)  # sink
