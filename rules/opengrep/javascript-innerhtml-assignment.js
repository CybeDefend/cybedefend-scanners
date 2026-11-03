// Annotated test file for javascript-innerhtml-assignment. Deliberately vulnerable: do not run.

function greet(name) {
  const el = document.getElementById("greeting");
  // ruleid: javascript-innerhtml-assignment
  el.innerHTML = "<b>Hello " + name + "</b>";
}

function append(list, item) {
  // ruleid: javascript-innerhtml-assignment
  list.innerHTML += `<li>${item}</li>`;
}

function greetText(name) {
  const el = document.getElementById("greeting");
  // ok: javascript-innerhtml-assignment
  el.textContent = "Hello " + name;
}

function clear(el) {
  // ok: javascript-innerhtml-assignment
  el.innerHTML = "";
}
