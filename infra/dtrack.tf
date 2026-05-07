# ─────────────────────────────────────────────────────
# Dependency-Track on EC2 (t3.medium, Amazon Linux 2023)
# Caddy reverse proxy with automatic Let's Encrypt HTTPS
# ─────────────────────────────────────────────────────

# Latest Amazon Linux 2023 AMI via SSM parameter
data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# ── Security Group ──────────────────────────────────
resource "aws_security_group" "dtrack" {
  name        = "${local.project}-dtrack"
  description = "Dependency-Track: HTTPS + SSH"

  # HTTPS
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP (Caddy redirect to HTTPS)
  ingress {
    description = "HTTP for ACME + redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH (for initial setup)
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.project}-dtrack" })
}

# ── IAM Role for SSM ───────────────────────────────
resource "aws_iam_role" "dtrack" {
  name = "${local.project}-dtrack-ec2"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "dtrack_ssm" {
  role       = aws_iam_role.dtrack.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "dtrack" {
  name = "${local.project}-dtrack"
  role = aws_iam_role.dtrack.name
  tags = local.tags
}

# ── Key Pair ────────────────────────────────────────
variable "dtrack_ssh_public_key" {
  description = "SSH public key for the Dependency-Track EC2 instance"
  type        = string
  default     = ""
}

resource "aws_key_pair" "dtrack" {
  count      = var.dtrack_ssh_public_key != "" ? 1 : 0
  key_name   = "${local.project}-dtrack"
  public_key = var.dtrack_ssh_public_key
  tags       = local.tags
}

# ── EC2 Instance ────────────────────────────────────
resource "aws_instance" "dtrack" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = "t3.medium"
  key_name               = var.dtrack_ssh_public_key != "" ? aws_key_pair.dtrack[0].key_name : null
  vpc_security_group_ids = [aws_security_group.dtrack.id]
  iam_instance_profile   = aws_iam_instance_profile.dtrack.name

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = <<-USERDATA
    #!/bin/bash
    set -euo pipefail

    # ── Install Docker ──
    dnf install -y docker
    systemctl enable --now docker
    usermod -aG docker ec2-user

    # ── Install Docker Compose plugin ──
    mkdir -p /usr/local/lib/docker/cli-plugins
    curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

    # ── Install Caddy ──
    dnf install -y 'dnf-command(copr)'
    dnf copr enable -y @caddy/caddy
    dnf install -y caddy

    # ── Docker Compose file for Dependency-Track ──
    mkdir -p /opt/dtrack
    cat > /opt/dtrack/docker-compose.yml << 'COMPOSE'
    services:
      dtrack-postgres:
        image: postgres:16-alpine
        environment:
          POSTGRES_DB: dtrack
          POSTGRES_USER: dtrack
          POSTGRES_PASSWORD: dtrack
        volumes:
          - dtrack-postgres-data:/var/lib/postgresql/data
        restart: unless-stopped
        healthcheck:
          test: ["CMD-SHELL", "pg_isready -U dtrack"]
          interval: 10s
          timeout: 5s
          retries: 5

      dtrack-apiserver:
        image: dependencytrack/apiserver:4.12.3
        depends_on:
          dtrack-postgres:
            condition: service_healthy
        environment:
          ALPINE_DATABASE_MODE: external
          ALPINE_DATABASE_URL: jdbc:postgresql://dtrack-postgres:5432/dtrack
          ALPINE_DATABASE_DRIVER: org.postgresql.Driver
          ALPINE_DATABASE_USERNAME: dtrack
          ALPINE_DATABASE_PASSWORD: dtrack
        volumes:
          - dtrack-data:/data
        restart: unless-stopped
        ports:
          - "127.0.0.1:8081:8080"

      dtrack-frontend:
        image: dependencytrack/frontend:4.12.3
        depends_on:
          - dtrack-apiserver
        environment:
          API_BASE_URL: https://dtrack.miata.cloud
        ports:
          - "127.0.0.1:8082:8080"
        restart: unless-stopped

    volumes:
      dtrack-postgres-data:
      dtrack-data:
    COMPOSE

    # ── Caddyfile ──
    cat > /etc/caddy/Caddyfile << 'CADDYFILE'
    dtrack.miata.cloud {
        handle /api/* {
            reverse_proxy localhost:8081
        }
        handle {
            reverse_proxy localhost:8082
        }
    }
    CADDYFILE

    # ── Start services ──
    cd /opt/dtrack
    docker compose up -d

    systemctl enable --now caddy
  USERDATA

  tags = merge(local.tags, { Name = "${local.project}-dtrack" })
}

# ── Elastic IP ──────────────────────────────────────
resource "aws_eip" "dtrack" {
  instance = aws_instance.dtrack.id
  tags     = merge(local.tags, { Name = "${local.project}-dtrack" })
}

# ── Route53 A record ───────────────────────────────
resource "aws_route53_record" "dtrack" {
  zone_id = local.hosted_zone_id
  name    = "dtrack.miata.cloud"
  type    = "A"
  ttl     = 300
  records = [aws_eip.dtrack.public_ip]
}

# ── Outputs ─────────────────────────────────────────
output "dtrack_url" {
  value = "https://dtrack.miata.cloud"
}

output "dtrack_instance_id" {
  value = aws_instance.dtrack.id
}

output "dtrack_public_ip" {
  value = aws_eip.dtrack.public_ip
}
