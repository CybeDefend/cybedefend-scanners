# Annotated test file for python-eval. Deliberately vulnerable: do not run.
import ast


def calc(request):
    # ruleid: python-eval
    return eval(request.args["q"])


def calc_with_globals(expr):
    # ruleid: python-eval
    return eval(expr, {"__builtins__": {}})


def constant():
    # ok: python-eval
    return eval("1 + 1")


def literal(text):
    # ok: python-eval
    return ast.literal_eval(text)
