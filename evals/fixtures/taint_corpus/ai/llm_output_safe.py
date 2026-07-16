def run(client):
    resp = client.messages.create(model="m", messages=[])
    text = resp.content[0].text
    return text.upper()  # LLM output only formatted, not executed: safe
