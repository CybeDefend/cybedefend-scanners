# Annotated test file for python-exec. Deliberately vulnerable: do not run.


def run_snippet(request):
    # ruleid: python-exec
    exec(request.form["code"])


def run_built(name):
    source = "result = " + name
    # ruleid: python-exec
    exec(source, {})


def run_constant():
    # ok: python-exec
    exec("x = 1")
