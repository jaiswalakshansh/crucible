def run(client):
    resp = client.messages.create(model="m", messages=[])
    code = resp.content[0].text
    return eval(code)  # sink: insecure LLM output handling
