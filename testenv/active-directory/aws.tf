variable "public_ip" {}
provider "aws" {
  region     = "eu-west-1"
}

resource "aws_vpc" "gokrb5" {
  cidr_block           = "192.168.88.0/23"
  enable_dns_hostnames = true
  enable_dns_support   =  true
  tags = {
    Name = "gokrb5"
  }
}

resource "aws_subnet" "public" {
  cidr_block = "192.168.89.0/24"
  vpc_id = "${aws_vpc.gokrb5.id}"
  availability_zone = "eu-west-1c"
  tags = {
    Name = "gokrb5"
    Purpose = "public"
  }
}

resource "aws_subnet" "private" {
  cidr_block = "192.168.88.0/24"
  vpc_id = "${aws_vpc.gokrb5.id}"
  availability_zone = "eu-west-1c"
  tags = {
    Name = "gokrb5"
    Purpose = "private"
  }
}

resource "aws_internet_gateway" "gokrb5" {
  vpc_id = "${aws_vpc.gokrb5.id}"
}

resource "aws_eip" "gokrb5" {
  tags = {
    Name = "gokrb5"
  }
}
resource "aws_nat_gateway" "gokrb5" {
  allocation_id = "${aws_eip.gokrb5.id}"
  subnet_id = "${aws_subnet.public.id}"
  depends_on = ["aws_internet_gateway.gokrb5"]
  tags = {
    Name = "gokrb5"
  }
}

resource "aws_route_table" "public" {
  vpc_id = "${aws_vpc.gokrb5.id}"
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.gokrb5.id}"
  }
  tags = {
    Name = "gokrb5-public"
  }
}
resource "aws_route_table_association" "public" {
  subnet_id = "${aws_subnet.public.id}"
  route_table_id = "${aws_route_table.public.id}"
}

resource "aws_route_table" "private" {
  vpc_id = "${aws_vpc.gokrb5.id}"
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_nat_gateway.gokrb5.id}"
  }
  route {
    cidr_block = "192.168.80.0/24"
    gateway_id = "${aws_vpn_gateway.gokrb5.id}"
  }
  tags = {
    Name = "gokrb5-private"
  }
}
resource "aws_route_table_association" "private" {
  subnet_id = "${aws_subnet.private.id}"
  route_table_id = "${aws_route_table.private.id}"
}


resource "aws_vpn_gateway" "gokrb5" {
  vpc_id = "${aws_vpc.gokrb5.id}"
  availability_zone = "eu-west-1c"
  tags = {
    Name = "gokrb5"
  }
}

resource "aws_customer_gateway" "gokrb5" {
  bgp_asn    = 65000
  ip_address = "${var.public_ip}"
  type       = "ipsec.1"
}

resource "aws_vpn_connection" "main" {
  vpn_gateway_id      = "${aws_vpn_gateway.gokrb5.id}"
  customer_gateway_id = "${aws_customer_gateway.gokrb5.id}"
  type                = "ipsec.1"
  static_routes_only  = true
  tunnel1_inside_cidr = "169.254.103.22/30"
  tunnel2_inside_cidr = "169.254.208.238/30"
}

resource "aws_vpn_connection_route" "local" {
  destination_cidr_block = "192.168.80.0/24"
  vpn_connection_id      = "${aws_vpn_connection.main.id}"
}

resource "aws_key_pair" "gokrb5" {
  key_name = "gokrb5"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzdyrY9CfVPKs5VWnMeVXT5/uRD84/sOhXmuN6Z2V2bMUMKcJ1srGZFDanu58zBfjA6TSJLdFhHNLyCc4zHEXkkkXFmv5h4DwJEe3cVdsX60uX/AUn+9d8FN4Rz3tqtGfqcU3jj5noLNoHHs29muTJHZRYLHxJy5zz2rr60Ug72wk4o4/k15Q9p6lFRYRZ2l/V4y8Mnm42aELkhSLmm/h//gH2+fCr8Xn/jhvyTmXXa/ZQHzvqM7I2UafoP6gLgW++oaDCk7Rpyq7wY89lVuOWg2MDMWofsMrWCLaFgqZF6Zy3M1NsDOn4c6KpJRuwJ7A9NUKYgXC3COxkxJuzhrnH turnerj@jtserver.jtlan.co.uk"
}

resource "aws_instance" "user_gokrb5" {
  ami = "ami-0d7624414846e2cf6" # Microsoft Windows Server 2012 R2 Base
  instance_type = "t2.micro"
  availability_zone = "eu-west-1c"
  get_password_data = true
  vpc_security_group_ids = ["${aws_security_group.gokrb5.id}"]
  subnet_id = "${aws_subnet.private.id}"
  associate_public_ip_address = false
  private_ip = "192.168.88.100"
  user_data = "${file("user-gokrb5.ps1")}"
  iam_instance_profile = "gokrb5_profile"
  key_name = "${aws_key_pair.gokrb5.key_name}"
  tags = {
    Name = "user.gokrb5"
    gokrb5-stage = "0"
  }
  depends_on = ["aws_nat_gateway.gokrb5"]
}

resource "aws_instance" "res_gokrb5" {
  ami = "ami-0d7624414846e2cf6" # Microsoft Windows Server 2012 R2 Base
  instance_type = "t2.micro"
  availability_zone = "eu-west-1c"
  get_password_data = true
  vpc_security_group_ids = ["${aws_security_group.gokrb5.id}"]
  subnet_id = "${aws_subnet.private.id}"
  associate_public_ip_address = false
  private_ip = "192.168.88.101"
  user_data = "${file("res-gokrb5.ps1")}"
  iam_instance_profile = "gokrb5_profile"
  key_name = "${aws_key_pair.gokrb5.key_name}"
  tags = {
    Name = "res.gokrb5"
    gokrb5-stage = "0"
  }
  depends_on = ["aws_instance.user_gokrb5"]
}

resource "aws_security_group" "gokrb5" {
  name        = "allow_home_network"
  description = "Allow home network inbound traffic"
  vpc_id      = "${aws_vpc.gokrb5.id}"

  ingress {
    description = "From Home Network"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["192.168.80.0/24"]
  }
  ingress {
    description = "Other DCs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self = true
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "gokrb5"
  }
}

resource "aws_iam_role" "gokrb5" {
  name = "gokrb5"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

data "aws_iam_policy_document" "tagEdit" {
  statement {
    sid = "tagEdit"
    actions = [
      "ec2:CreateTags"
    ]
    resources = [
      "${aws_instance.user_gokrb5.arn}",
      "${aws_instance.res_gokrb5.arn}"
    ]
  }
  statement {
    sid = "Desribe"
    actions = [
      "ec2:Describe*"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "gokrb5" {
  name   = "gokrb5_TagEC2"
  path   = "/"
  policy = "${data.aws_iam_policy_document.tagEdit.json}"
}

resource "aws_iam_role_policy_attachment" "ec2tag" {
  role       = "${aws_iam_role.gokrb5.name}"
  policy_arn = "${aws_iam_policy.gokrb5.arn}"
}

resource "aws_iam_instance_profile" "gokrb5" {
  name = "gokrb5_profile"
  role = "${aws_iam_role.gokrb5.name}"
}