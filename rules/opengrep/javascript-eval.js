// Annotated test file for javascript-eval. Deliberately vulnerable: do not run.

function calc(req, res) {
  // ruleid: javascript-eval
  res.send(String(eval(req.query.q)));
}

function fromHash() {
  const expr = window.location.hash.slice(1);
  // ruleid: javascript-eval
  return eval(expr);
}

function constant() {
  // ok: javascript-eval
  return eval("1 + 1");
}

function parse(text) {
  // ok: javascript-eval
  return JSON.parse(text);
}
