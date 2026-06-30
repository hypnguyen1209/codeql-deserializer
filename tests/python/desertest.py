import pickle
import marshal
import yaml

from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def vulnerable():
    payload = request.args.get("payload")
    pickle.loads(payload)      # NOT OK - chain
    yaml.load(payload)         # NOT OK - chain (no SafeLoader)
    marshal.loads(payload)     # NOT OK - chain
    return "ok"


def safe_constant():
    # Safe: hardcoded constant -> chain query should NOT flag (sink still listed)
    data = b"\x80\x04\x95"
    return pickle.loads(data)  # OK


@app.route("/safe")
def safe_yaml():
    payload = request.args.get("payload")
    return yaml.load(payload, Loader=yaml.SafeLoader)  # OK - SafeLoader
