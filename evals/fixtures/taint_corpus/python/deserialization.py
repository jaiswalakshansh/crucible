import pickle


def load(request):
    data = request.args.get("blob")
    return pickle.loads(data)  # sink (line 6): insecure deserialization
