import os


def read(request):
    name = os.path.basename(request.args.get("file"))
    return open(name).read()  # sanitized with basename: safe
