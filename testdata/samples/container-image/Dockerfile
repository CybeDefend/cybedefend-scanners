# Deliberately vulnerable sample image, do not deploy or push.
#
# test/integration/trivyimage_test.go builds it from a temporary context that
# holds this file, package.json and package-lock.json copied from
# testdata/samples/sca-npm (never committed twice), and the installed
# metadata of lodash 4.17.20 (node_modules/lodash/package.json), written by
# the test. In an image, Trivy reads installed packages, not lockfiles: the
# lodash result (CVE-2021-23337) is reported at
# app/node_modules/lodash/package.json, and the OS packages of Alpine 3.18.0
# at the image target.
FROM alpine:3.18.0@sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11
COPY package.json package-lock.json /app/
COPY node_modules /app/node_modules
# Never run, only scanned; still not root.
USER 65532:65532
