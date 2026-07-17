from db import run_query


def handler(request):
    return run_query(request.args.get("id"))
