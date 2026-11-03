# Annotated test file for python-flask-debug-true. Deliberately vulnerable: do not deploy.
import os

from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    # ruleid: python-flask-debug-true
    app.run(host="0.0.0.0", debug=True)

if os.environ.get("RUN_PROD"):
    # ok: python-flask-debug-true
    app.run(host="0.0.0.0", debug=False)

if os.environ.get("RUN_DEFAULT"):
    # ok: python-flask-debug-true
    app.run()
