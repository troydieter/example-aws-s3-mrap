resource "random_id" "rando" {
  byte_length = 2
}

provider "aws" {
  region = "us-east-1"
  alias  = "primary_region"
    default_tags {
    tags = {
      "project"     = "example-aws-s3-mrap"
      "id"          = random_id.rando.hex
    }
  }
}

provider "aws" {
  region = "us-east-2"
  alias  = "secondary_region"
      default_tags {
    tags = {
      "project"     = "example-aws-s3-mrap"
      "id"          = random_id.rando.hex
    }
  }
}

data "external" "current_ip" {
  program = ["powershell", "-Command", "(Invoke-WebRequest -Uri 'https://ifconfig.io').Content.Trim() | ConvertTo-Json -Compress | % { '{\"ip\":\"' + ($_ -replace '\"','') + '/32\"}' }"]
}

########################

resource "aws_s3_bucket" "primary_bucket" {
  provider = aws.primary_region
  bucket_prefix =    "primary-bucket"
}

resource "aws_s3_bucket" "secondary_bucket" {
  provider = aws.secondary_region
  bucket_prefix =    "secondary-bucket"
}

resource "aws_s3control_multi_region_access_point" "example" {
  details {
    name = "${random_id.rando.hex}-example"

    region {
      bucket = aws_s3_bucket.primary_bucket.id
    }

    region {
      bucket = aws_s3_bucket.secondary_bucket.id
    }
  }
}

data "aws_vpc" "selected" {
  id = var.vpc
}

data "aws_subnets" "all" {
  filter {
    name   = "tag:Reach"
    values = ["public"]
  }
}

resource "aws_security_group" "ec2_sg" {
  provider = aws.primary_region
  name     = "ec2-sg"
  vpc_id   = data.aws_vpc.selected.id # Replace with your VPC ID

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [data.external.current_ip.result.ip]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SSM
data "aws_iam_policy" "required-policy" {
  name = "AmazonSSMManagedInstanceCore"
}

# IAM Role
resource "aws_iam_role" "example-role" {
  name = "example-${random_id.rando.hex}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "bucket_full_access" {
  name        = "bucket-full-access"
  description = "Allows all actions on the S3 bucket defined in module.s3_bucket"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "FullAccessToprimaryBucket",
        Effect   = "Allow",
        Action   = "s3:*",
        Resource = [
          "${aws_s3_bucket.primary_bucket.arn}",
          "${aws_s3_bucket.primary_bucket.arn}/*"
        ]
      },
      {
        Sid      = "FullAccessToMRAP",
        Effect   = "Allow",
        Action   = "s3:*",
        Resource = [
          "arn:aws:s3:::${aws_s3control_multi_region_access_point.example.alias}",
          "arn:aws:s3:::${aws_s3control_multi_region_access_point.example.alias}/*"
        ]
      }
    ]
  })
}

# Attach the policy to the role
resource "aws_iam_role_policy_attachment" "attach-ssm" {
  role       = aws_iam_role.example-role.name
  policy_arn = data.aws_iam_policy.required-policy.arn
}

resource "aws_iam_role_policy_attachment" "attach-s3" {
  role       = aws_iam_role.example-role.name
  policy_arn = aws_iam_policy.bucket_full_access.arn
}

resource "aws_iam_instance_profile" "ec2_ssm" {
  name = "aws_ssm_example-${random_id.rando.hex}"
  role = aws_iam_role.example-role.name
}

resource "aws_instance" "test_instance" {
  provider          = aws.primary_region
  ami              = var.ami
  instance_type    = "t3.micro"
  security_groups  = [aws_security_group.ec2_sg.name]
  associate_public_ip_address = true
  key_name         = "example-aws-s3-mrap" # Replace with your key pair name
  iam_instance_profile = aws_iam_instance_profile.ec2_ssm.name

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y python3-pip git
              pip3 install boto3 requests
              
              MRAP_ALIAS="${aws_s3control_multi_region_access_point.example.alias}"

              cat <<EOT > /home/ec2-user/sigv4a_sign.py
              import boto3
              import botocore.auth
              import botocore.session
              import requests

              class SigV4ASign:
                  def __init__(self, session=None):
                      self.session = session or boto3.Session()
                      self.credentials = self.session.get_credentials()

                  def get_headers_basic(self, service, region, method, url):
                      request = botocore.awsrequest.AWSRequest(method=method, url=url)
                      signer = botocore.auth.SigV4Auth(self.credentials, service, region)
                      signer.add_auth(request)
                      return dict(request.headers)
              EOT

              cat <<EOT > /home/ec2-user/test_mrap.py
              from sigv4a_sign import SigV4ASign
              import requests

              service = 's3'
              region = '*'
              method = 'PUT'
              url = f'https://$MRAP_ALIAS.accesspoint.s3-global.amazonaws.com/test-object'
              data = 'hello world'

              aws_request_config = {
                  'method': 'PUT',
                  'url': url,
                  'data': data
              }

              headers = SigV4ASign().get_headers(service, region, aws_request_config)
              r = requests.put(url, data=data, headers=headers)
              print(f'status_code: {r.status_code}')
              EOT

              echo "Setup complete. Ready to test MRAP."
              EOF
}