import os


def handler(request):
    forward(request.args.get("host"))


def forward(h):
    do_ping(h)


def do_ping(host):
    os.system("ping -c1 " + host)  # sink (line 13)
