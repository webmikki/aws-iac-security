# AWS Security Infrastructure (Java CDK)

This Java CDK project creates a secure AWS infrastructure with a VPC and EC2 instance.

## Architecture

- **VPC**: `aws-security-vpc` with public and private subnets across 2 AZs
- **EC2 Instance**: t2.micro (free tier eligible) with SSM access
- **Security Groups**: Configured for SSH, HTTP, and HTTPS access
- **IAM Role**: EC2 instance role with SSM and CloudWatch permissions

## Prerequisites

1. **Java 11+** installed
2. **Maven 3.6+** installed
3. **AWS CLI** installed and configured
4. **Node.js** and **npm** installed
5. **AWS CDK** installed globally

## Quick Start

### Windows
```cmd
deploy.bat
```

### Linux/macOS
```bash
chmod +x deploy.sh
./deploy.sh
```

### Manual Deployment

1. **Compile the project:**
   ```bash
   mvn clean compile
   ```

2. **Bootstrap CDK (first time only):**
   ```bash
   cdk bootstrap
   ```

3. **Deploy infrastructure:**
   ```bash
   cdk deploy
   ```

4. **Connect to EC2 instance:**
   ```bash
   aws ssm start-session --target <instance-id>
   ```

## Manual Commands

- **Compile**: `mvn clean compile`
- **Deploy**: `cdk deploy`
- **Destroy**: `cdk destroy`
- **Synthesize**: `cdk synth`
- **Diff**: `cdk diff`

## Project Structure

```
infra/
├── src/main/java/com/aws-iac-security/
│   ├── AwsIacSecurityApp.java      # Main CDK app
│   └── AwsIacSecurityStack.java    # Infrastructure stack
├── pom.xml                      # Maven configuration
├── cdk.json                     # CDK configuration
├── deploy.bat                   # Windows deployment script
├── deploy.sh                    # Linux/macOS deployment script
└── README.md                    # This file
```

## Resources Created

- VPC with public/private subnets
- Internet Gateway
- NAT Gateway (for private subnets)
- Security Group for EC2
- EC2 instance (t2.micro)
- IAM role for EC2

## Security Features

- EC2 instance uses SSM Session Manager (no SSH keys needed)
- Security groups with minimal required access
- IAM role with least privilege access
- VPC with proper subnet isolation

## Cost

This infrastructure uses free tier eligible resources:
- t2.micro EC2 instance (750 hours/month free)
- VPC and networking (free)
- NAT Gateway has charges (consider removing if not needed)

## Cleanup

To destroy all resources:
```bash
cdk destroy
```

## Troubleshooting

### Common Issues

1. **Java version**: Ensure Java 11+ is installed
2. **Maven not found**: Install Maven and add to PATH
3. **CDK not found**: Install with `npm install -g aws-cdk`
4. **AWS credentials**: Configure with `aws configure`

### Development

To modify the infrastructure:
1. Edit `AwsIacSecurityStack.java`
2. Run `mvn clean compile`
3. Run `cdk deploy`
