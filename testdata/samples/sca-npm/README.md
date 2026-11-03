# sca-npm sample

Deliberately vulnerable, do not deploy.

This npm project depends on `lodash` `4.17.20`, which carries CVE-2021-23337
(GHSA-35jh-r3h4-6jhm, command injection in `_.template`). The `trivy-fs`
integration test scans this directory and expects that finding at
`package-lock.json`. The trivy-image sample copies the same two files into its image.

Nothing here is installed or run: Trivy reads the lockfile only.
