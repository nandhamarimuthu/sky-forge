resource "aws_instance" "api" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "m5.2xlarge"

  tags = {
    Name    = "demo-shop-api"
    Project = "demo-shop"
  }
}

resource "aws_instance" "worker" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "m5.xlarge"

  tags = {
    Name    = "demo-shop-worker"
    Project = "demo-shop"
  }
}

resource "aws_security_group" "bastion" {
  name = "bastion"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "assets" {
  bucket = "demo-shop-assets"
  acl    = "public-read"
}

resource "aws_db_instance" "main" {
  identifier          = "demo-shop-db"
  engine              = "postgres"
  instance_class      = "db.r5.xlarge"
  storage_encrypted   = false
  publicly_accessible = true
}
