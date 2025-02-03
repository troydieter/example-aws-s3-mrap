variable "vpc" {
  type        = string
  description = "VPC to deploy test instance to"
}

variable "ami" {
  type        = string
  description = "AMI to use"
  default     = "ami-0c614dee691cbbf37"
}