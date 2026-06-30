import pickle
import cPickle  # py2 alias name only (static analysis recognizes it)
import marshal
import yaml
import shelve
import dill
import jsonpickle
import pandas

from flask import Flask, request

app = Flask(__name__)


@app.route("/a")
def vuln_pickle():
    data = request.get_data()
    return pickle.loads(data)            # NOT OK - chain + sink


@app.route("/b")
def vuln_cpickle():
    data = request.get_data()
    return cPickle.loads(data)           # NOT OK - chain + sink


@app.route("/c")
def vuln_marshal():
    data = request.get_data()
    return marshal.loads(data)           # NOT OK - chain + sink


@app.route("/d")
def vuln_yaml_unsafe():
    data = request.get_data(as_text=True)
    return yaml.load(data)               # NOT OK - chain + sink (no Loader)


@app.route("/e")
def safe_yaml_safeloader():
    data = request.get_data(as_text=True)
    return yaml.load(data, Loader=yaml.SafeLoader)      # OK


@app.route("/f")
def safe_yaml_csafeloader():
    data = request.get_data(as_text=True)
    return yaml.load(data, Loader=yaml.CSafeLoader)     # OK


@app.route("/g")
def vuln_dill():
    data = request.get_data()
    return dill.loads(data)              # NOT OK - chain + sink


@app.route("/h")
def vuln_jsonpickle():
    data = request.get_data(as_text=True)
    return jsonpickle.decode(data)       # claim: NOT OK - chain + sink


@app.route("/i")
def vuln_pandas():
    data = request.get_data()
    return pandas.read_pickle(data)      # NOT OK - chain + sink


@app.route("/j")
def sink_only_shelve():
    # shelve.open takes a filename; no remote flow -> chain should NOT fire,
    # but it is a deserialization sink (uses pickle) -> sink enumeration MAY flag.
    db = shelve.open("/tmp/x")
    return db


@app.route("/k")
def safe_pickle_constant():
    return pickle.loads(b"\x80\x04\x95")  # OK - constant, no remote flow (sink still listed)


@app.route("/l")
def safe_pickle_safeload():
    data = request.get_data()
    # pickle.loads is never "safe" regardless of input; this is a sink + chain.
    return pickle.loads(data)            # NOT OK (control: same as /a)
