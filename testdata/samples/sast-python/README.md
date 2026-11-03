# sast-python

Deliberately vulnerable, do not deploy.

A two-route Flask application for the `opengrep` integration test: one route
passes a query parameter to `eval`, the other builds a shell command from one
and runs it with `subprocess.run(..., shell=True)`.
