# secret-config sample

A sample for the `gitleaks` adapter. It holds no secret: `settings.example.env`
has only placeholders.

The integration test (`test/integration/gitleaks_test.go`) copies this
directory to a temporary one and writes a `settings.env` there with a
Stripe-shaped key generated at run time, then checks that the uploaded SARIF
names the finding but never holds the key. Never commit a `settings.env` or
any real-looking credential here.
