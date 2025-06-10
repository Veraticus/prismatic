# Vulnerable Terraform configuration for testing Checkov

# S3 bucket without encryption
resource "aws_s3_bucket" "test_bucket" {
  bucket = "my-test-bucket"
}

# Security group with unrestricted ingress
resource "aws_security_group" "wide_open" {
  name = "allow_all"
  
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM policy attached directly to user (bad practice)
resource "aws_iam_user_policy" "test_policy" {
  name = "test"
  user = "testuser"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

# RDS instance without encryption
resource "aws_db_instance" "test_db" {
  identifier     = "test-db"
  engine         = "mysql"
  engine_version = "5.7"
  instance_class = "db.t2.micro"
  
  # No encryption
  storage_encrypted = false
  
  # Publicly accessible
  publicly_accessible = true
}