# Deliberately misconfigured Terraform, used by the trivy-config integration
# test. Do not apply it.

resource "aws_security_group" "ssh_from_anywhere" {
  name        = "ssh-from-anywhere"
  description = "Sample: SSH open to the whole internet"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "unencrypted" {
  bucket = "cybedefend-scanners-sample-unencrypted"
}
