terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_instance" "web" {
  ami                         = "ami-0c1c30571d2dae5c9"
  instance_type               = "c5.2xlarge"
  associate_public_ip_address = true

  tags = {
    Name    = "orders-api-web"
    Project = "orders-api"
  }
}

resource "aws_instance" "worker" {
  ami           = "ami-0c1c30571d2dae5c9"
  instance_type = "r5.xlarge"

  tags = {
    Name    = "orders-api-worker"
    Project = "orders-api"
  }
}

resource "aws_db_instance" "main" {
  identifier        = "orders-api-db"
  engine            = "postgres"
  instance_class    = "db.m5.xlarge"
  allocated_storage = 500
  multi_az          = true
  storage_encrypted = true
}

resource "aws_db_instance" "reporting" {
  identifier          = "orders-api-reporting"
  engine              = "postgres"
  instance_class      = "db.r5.large"
  allocated_storage   = 300
  storage_encrypted   = false
  publicly_accessible = true
}

resource "aws_security_group" "db" {
  name = "orders-api-db"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "exports" {
  bucket = "orders-api-exports"
}

resource "aws_iam_policy" "worker" {
  name = "orders-api-worker"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      "Effect"   = "Allow"
      "Action"   = "*"
      "Resource" = "*"
    }]
  })
}
