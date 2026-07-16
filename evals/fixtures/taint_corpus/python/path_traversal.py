def read(request):
    name = request.args.get("file")
    return open(name).read()  # sink: path traversal
