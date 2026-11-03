// Annotated test file for javascript-child-process-exec-concat. Deliberately vulnerable: do not run.
const cp = require("child_process");
const { exec, execFile } = require("child_process");

function ping(host) {
  // ruleid: javascript-child-process-exec-concat
  cp.exec("ping -c 1 " + host, () => {});
}

function archive(name) {
  // ruleid: javascript-child-process-exec-concat
  return cp.execSync(`tar czf ${name}.tgz ${name}`);
}

function list(dir) {
  // ruleid: javascript-child-process-exec-concat
  exec("ls -l " + dir, () => {});
}

function pingSafe(host) {
  // ok: javascript-child-process-exec-concat
  execFile("ping", ["-c", "1", host], () => {});
}

function constant() {
  // ok: javascript-child-process-exec-concat
  cp.exec("ls -l /tmp", () => {});
}
