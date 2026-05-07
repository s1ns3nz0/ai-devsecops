terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket = "ai-devsecops-tfstate-106760547719"
    key    = "dashboard/terraform.tfstate"
    region = "ap-northeast-1"
  }
}

# Tokyo — primary region for compute/API
provider "aws" {
  region = "ap-northeast-1"
}

# Virginia — required for CloudFront ACM certificates
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

locals {
  project     = "ai-devsecops"
  domain      = "security.miata.cloud"
  account_id  = "106760547719"
  github_org  = "s1ns3nz0"
  github_repo = "ai-devsecops"
  hosted_zone_id = "Z1005313325AQ3N0OP1EQ"

  tags = {
    Project   = local.project
    ManagedBy = "terraform"
  }
}
