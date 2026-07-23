from flask import redirect


def go(request):
    return redirect(request.args.get("next"))  # sink (line 5): open redirect
