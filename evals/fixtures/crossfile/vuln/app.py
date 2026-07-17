from db import run_query


def handler(request):
    user_id = request.args.get("id")
    return run_query(user_id)  # taint crosses into db.py
