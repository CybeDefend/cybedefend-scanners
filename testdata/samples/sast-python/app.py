# Deliberately vulnerable sample for the opengrep integration test: do not deploy.
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    # Code injection: the query string is evaluated as Python.
    return str(eval(request.args["q"]))


@app.route("/ping")
def ping():
    # Command injection: a request value reaches a shell.
    cmd = "ping -c 1 " + request.args["host"]
    subprocess.run(cmd, shell=True)
    return "ok"
