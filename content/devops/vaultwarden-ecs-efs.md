---
title: "Setting up self-hosted Vaultwarden on ECS/EFS using Terraform"
date: 2022-05-01T19:16:12Z

categories: ['DevOps']
tags: ['Terraform', 'AWS']
author: "jsfan"
featuredImage: "/images/tbd.jpg"
---
Vaultwarden is a rewrite and drop-in replacement for Bitwarden which itself is an open-source
online password vault. While I have not tested that claim, Vaultwarden claims that its reimplementation
in Rust is much less resource intensive than the original Bitwarden implementation in .NET Core.

## Why use an online password manager?
The answer to this question probably consists of  two parts. The first part being why you should
use a password manager and the second one why you would use an online one rather than an offline
one.

### Why use a password manager?
As a lot of services today have shifted from single computers into networked services (servers and "the cloud"),
we all have to secure many services with passwords. Passwords that are easy to remember tend to
also be easy to guess (by the standards of modern computers). Reusing the same password for multiple
independent services comes with the risk of a compromise of one service leading to the compromise of
multiple other services.

A password manager allows you to use unique passwords which are hard to guess (and possibly very long) for
every service you use and not have to remember them. Instead, you have to only think of one good password
which becomes the key to your password manager. So, while you still put all your eggs in one basket, so to speak,
you make sure that you spend all your effort watching that one basket.

### Why use an _online_ password manager?
While offline password managers make your passwords less accessible to hackers, they are also less
accessible to you. You will have to have a copy of your password file on every device you might ever
need it and make sure that you keep all copies in sync.

There is a simple security principle that security that creates too much inconvenience is likely to fail.
The inconvenience creates an incentive to circumvent security measures and overall weaken the security posture.
In the case of an offline password manager that may e.g. be that you leave permanent copies of your password
file in untrusted places and may eventually give an attacker a large amount of time to crack it because they own
a copy of the complete password file.

While an online password manager creates a larger attack surface for unknown attackers, it also means that you
once again have a central point of defence. Furthermore, you have the convenience of being able to use the password
manager from any networked device without storing permanent copies elsewhere.

## Setting up Vaultwarden
Vaultwarden needs to run an HTTP service and have a storage backend. That could be provided via an EC2, but it is
significantly easier to set that up with ECS Fargate and an EFS storage backend.

To make things portable, the following assembles a Terraform module which you can just be included in an existing
configuration. That saves copying and pasting between multiple environments and allows for global changes across
environments where desired.

To start off, we set up the provider configuration. We will only need an AWS provider in the target AZ, so all that's
required is this:

    terraform {
      required_providers {
        aws = {
          source                = "hashicorp/aws"
          version               = "~> 4.0"
          configuration_aliases = [aws]
        }
      }
    }

Next, we set up some roles and policies we will use for the ECS setup later.

    resource "aws_iam_role" "vaultwarden" {
      name = "VaultwardenRole"
      assume_role_policy = jsonencode(
      {
        Statement = [
          {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Principal = {
              Service = [
                "ecs.amazonaws.com",
                "ecs-tasks.amazonaws.com",
              ]
            }
          }
        ]
        Version = "2012-10-17"
      }
      )
      max_session_duration = 7200
    }
    
    resource "aws_iam_policy" "vaultwarden" {
      name = "VaultwardenRolePolicy"
      policy = jsonencode({
        Version = "2012-10-17",
        Statement = [
          {
            Effect = "Allow",
            Action = [
              "ecr:GetAuthorizationToken",
              "ecr:BatchCheckLayerAvailability",
              "ecr:GetDownloadUrlForLayer",
              "ecr:BatchGetImage",
              "logs:CreateLogStream",
              "logs:PutLogEvents",
            ],
            Resource = "*"
          }
        ]
      })
    }
    
    resource "aws_iam_role_policy_attachment" "vaultwarden" {
      policy_arn = aws_iam_policy.vaultwarden.arn
      role       = aws_iam_role.vaultwarden.name
    }
