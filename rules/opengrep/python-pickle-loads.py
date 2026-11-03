# Annotated test file for python-pickle-loads. Deliberately vulnerable: do not run.
import json
import pickle


def restore(request):
    # ruleid: python-pickle-loads
    return pickle.loads(request.data)


def restore_file(path):
    with open(path, "rb") as f:
        # ruleid: python-pickle-loads
        return pickle.load(f)


def save(obj):
    # ok: python-pickle-loads
    return pickle.dumps(obj)


def restore_json(request):
    # ok: python-pickle-loads
    return json.loads(request.data)
