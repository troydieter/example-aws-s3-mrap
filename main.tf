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

variable "vpc" {
  type        = string
  description = "VPC to deploy test instance to"
}

variable "ami" {
  type = string
  description = "AMI to use"
  default = "ami-0c614dee691cbbf37"
}

data "external" "current_ip" {
  program = ["powershell", "-Command", "(Invoke-WebRequest -Uri 'https://ifconfig.io').Content.Trim() | ConvertTo-Json -Compress | % { '{\"ip\":\"' + ($_ -replace '\"','') + '/32\"}' }"]
}

########################

resource "aws_s3_bucket" "primary_bucket" {
  provider = aws.primary_region
  bucket_prefix =    "primary-bucket"
}

resource "aws_s3_bucket" "sec_bucket" {
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
      bucket = aws_s3_bucket.sec_bucket.id
    }
  }
}

resource "aws_security_group" "ec2_sg" {
  provider = aws.primary_region
  name     = "ec2-sg"
  vpc_id   = var.vpc # Replace with your VPC ID

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

resource "aws_instance" "test_instance" {
  provider          = aws.primary_region
  ami              = var.ami
  instance_type    = "t3.micro"
  security_groups  = [aws_security_group.ec2_sg.name]
  key_name         = "example-aws-s3-mrap" # Replace with your key pair name

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