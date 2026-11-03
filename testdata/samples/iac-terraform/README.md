# iac-terraform sample

Deliberately misconfigured, do not deploy. `main.tf` opens SSH to `0.0.0.0/0`
and declares an S3 bucket without encryption; `Dockerfile` runs as root. The
`trivy-config` integration test expects Trivy's findings on both files.
