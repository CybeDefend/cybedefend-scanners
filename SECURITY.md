# Security policy

## Reporting a vulnerability

Please report a vulnerability in this repository, in its container images or in the GitHub Action and GitLab CI template to **security@cybedefend.com**. Do not open a public issue, pull request or discussion for it.

Include what you can of:

- the affected component (the `appsec-scanner` program, an image and its tag, the action, the template);
- the steps to reproduce it, or a proof of concept;
- the impact you expect.

We acknowledge a report within 3 working days and keep you informed until it is fixed.

## Disclosure

We follow a **90-day coordinated disclosure** policy: we ask you not to disclose a vulnerability publicly until it is fixed or 90 days after your report, whichever comes first. We may agree with you on a different date when a fix needs more time or is already released. We credit reporters who wish it in the release notes.

## Scope

A vulnerability in a tool an image runs (Opengrep, Gitleaks, Trivy, zizmor) belongs to that tool's project; we update the image once the tool is fixed. A report about how an image runs the tool, or about what it uploads, is in scope here.
