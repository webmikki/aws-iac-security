package com.aws-iac-security;

import software.amazon.awscdk.CfnOutput;
import software.amazon.awscdk.Stack;
import software.amazon.awscdk.StackProps;
import software.amazon.awscdk.services.ec2.*;
import software.amazon.awscdk.services.iam.*;
import software.constructs.Construct;

/**
 * AWS Security Infrastructure Stack
 * 
 * This CDK stack creates a secure AWS infrastructure consisting of:
 * - A VPC with public and private subnets across multiple availability zones
 * - An EC2 instance (t2.micro) that is free tier eligible
 * - Security groups with appropriate ingress rules
 * - IAM roles with least privilege access
 * - CloudWatch integration for monitoring
 * 
 * The infrastructure follows AWS security best practices and is designed
 * to be cost-effective using free tier resources where possible.
 */
public class AwsIacSecurityStack extends Stack {
    
    /**
     * Constructor for AwsIacSecurityStack with default properties
     * 
     * This constructor creates a new stack with default AWS account and region
     * settings. It delegates to the main constructor with null properties.
     * 
     * @param scope The parent construct (usually the App)
     * @param id The unique identifier for this stack
     */
    public AwsIacSecurityStack(final Construct scope, final String id) {
        this(scope, id, null);
    }

    /**
     * Main constructor for AwsIacSecurityStack
     * 
     * This constructor initializes the AWS Security infrastructure stack.
     * It creates all the necessary AWS resources including VPC, EC2 instance,
     * security groups, and IAM roles.
     * 
     * @param scope The parent construct (usually the App)
     * @param id The unique identifier for this stack
     * @param props Optional stack properties (account, region, etc.)
     */
    public AwsIacSecurityStack(final Construct scope, final String id, final StackProps props) {
        super(scope, id, props);

        // ============================================================================
        // VPC CREATION
        // ============================================================================
        // Create a Virtual Private Cloud (VPC) with the name "aws-security-vpc"
        // The VPC provides an isolated network environment for our AWS resources
        Vpc vpc = Vpc.Builder.create(this, "AwsIacSecurityVPC")
                .vpcName("aws-security-vpc")                    // Human-readable name for the VPC
                .cidr("10.0.0.0/16")                          // IP address range: 10.0.0.0 to 10.0.255.255 (65,536 IPs)
                .maxAzs(2)                                     // Use 2 Availability Zones for high availability
                .subnetConfiguration(java.util.Arrays.asList(
                        // Public Subnet Configuration
                        // Public subnets have direct access to the Internet Gateway
                        // Resources in public subnets can have public IP addresses
                        SubnetConfiguration.builder()
                                .name("aws-security-public")    // Logical name for public subnets
                                .subnetType(SubnetType.PUBLIC) // Subnet type: PUBLIC
                                .cidrMask(24)                  // Each subnet gets /24 (256 IPs): 10.0.1.0/24, 10.0.2.0/24
                                .build(),
                        // Private Subnet Configuration  
                        // Private subnets have no direct internet access
                        // They use NAT Gateway for outbound internet access
                        SubnetConfiguration.builder()
                                .name("aws-security-private")   // Logical name for private subnets
                                .subnetType(SubnetType.PRIVATE_WITH_EGRESS) // Private with NAT Gateway
                                .cidrMask(24)                  // Each subnet gets /24 (256 IPs): 10.0.11.0/24, 10.0.12.0/24
                                .build()
                ))
                .enableDnsHostnames(true)                      // Enable DNS hostnames for EC2 instances
                .enableDnsSupport(true)                        // Enable DNS resolution within the VPC
                .build();

        // ============================================================================
        // SECURITY GROUP CREATION
        // ============================================================================
        // Create a security group to control inbound and outbound traffic for EC2 instances
        // Security groups act as virtual firewalls for EC2 instances
        SecurityGroup ec2SecurityGroup = SecurityGroup.Builder.create(this, "AwsIacSecurityEC2SG")
                .vpc(vpc)                                       // Associate with our VPC
                .securityGroupName("aws-security-ec2-sg")       // Human-readable name for the security group
                .description("Security group for AWS Security EC2 instance")
                .allowAllOutbound(true)                         // Allow all outbound traffic by default
                .build();

        // ============================================================================
        // INGRESS RULES (INBOUND TRAFFIC RULES)
        // ============================================================================
        // Configure what traffic is allowed TO the EC2 instance from external sources
        
        // SSH Access Rule (Port 22)
        // Allows SSH connections from anywhere (0.0.0.0/0)
        // This enables remote administration of the EC2 instance
        ec2SecurityGroup.addIngressRule(
                Peer.anyIpv4(),                                 // Allow from any IPv4 address
                Port.tcp(22),                                   // TCP port 22 (SSH)
                "Allow SSH access"                              // Description for this rule
        );

        // HTTP Access Rule (Port 80)
        // Allows HTTP web traffic from anywhere
        // This enables web server access for the EC2 instance
        ec2SecurityGroup.addIngressRule(
                Peer.anyIpv4(),                                 // Allow from any IPv4 address
                Port.tcp(80),                                   // TCP port 80 (HTTP)
                "Allow HTTP access"                             // Description for this rule
        );

        // HTTPS Access Rule (Port 443)
        // Allows HTTPS encrypted web traffic from anywhere
        // This enables secure web server access for the EC2 instance
        ec2SecurityGroup.addIngressRule(
                Peer.anyIpv4(),                                 // Allow from any IPv4 address
                Port.tcp(443),                                  // TCP port 443 (HTTPS)
                "Allow HTTPS access"                            // Description for this rule
        );

        // ============================================================================
        // IAM ROLE CREATION
        // ============================================================================
        // Create an IAM role that the EC2 instance will assume
        // IAM roles provide temporary credentials and permissions to AWS services
        Role ec2Role = Role.Builder.create(this, "AwsIacSecurityEC2Role")
                .roleName("aws-security-ec2-role")              // Human-readable name for the IAM role
                .assumedBy(new ServicePrincipal("ec2.amazonaws.com"))  // Allow EC2 service to assume this role
                .managedPolicies(java.util.Arrays.asList(
                        // Attach AWS managed policy for Systems Manager (SSM)
                        // This enables SSM Session Manager for secure access without SSH keys
                        ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore")
                ))
                .build();

        // ============================================================================
        // ADDITIONAL IAM PERMISSIONS
        // ============================================================================
        // Add CloudWatch Logs permissions to the EC2 role
        // This allows the EC2 instance to send logs to CloudWatch
        // Useful for centralized logging and monitoring
        ec2Role.addManagedPolicy(
                ManagedPolicy.fromAwsManagedPolicyName("CloudWatchAgentServerPolicy")
        );

        // ============================================================================
        // EC2 INSTANCE CREATION
        // ============================================================================
        // Create an EC2 instance that is free tier eligible
        // This instance will be our main compute resource in the VPC
        Instance ec2Instance = Instance.Builder.create(this, "AwsIacSecurityEC2Instance")
                .instanceName("aws-security-ec2-instance")      // Human-readable name for the EC2 instance
                .instanceType(InstanceType.of(InstanceClass.T2, InstanceSize.MICRO)) // t2.micro: 1 vCPU, 1 GB RAM (free tier)
                .machineImage(MachineImage.latestAmazonLinux2())                     // Latest Amazon Linux 2 AMI
                .vpc(vpc)                                                             // Deploy in our custom VPC
                .vpcSubnets(SubnetSelection.builder()
                        .subnetType(SubnetType.PUBLIC)                               // Place in public subnet for internet access
                        .build())
                .securityGroup(ec2SecurityGroup)                                     // Apply our security group
                .role(ec2Role)                                                       // Attach the IAM role
                .userData(UserData.forLinux())                                       // Enable user data scripts
                .build();

        // ============================================================================
        // USER DATA CONFIGURATION
        // ============================================================================
        // User data scripts run when the EC2 instance first starts
        // These commands will be executed as root during instance initialization
        ec2Instance.getUserData().addCommands(
                "yum update -y",                                                      // Update all packages to latest versions
                "yum install -y htop nano wget curl",                               // Install useful system utilities
                "echo 'AWS Security EC2 Instance is ready!' > /var/www/html/index.html" // Create a simple web page
        );

        // ============================================================================
        // RESOURCE TAGGING
        // ============================================================================
        // Add consistent tags to all resources for better organization and cost tracking
        // Tags help identify resources and can be used for billing, automation, and governance
        
        // Tag the VPC with both Name and Project tags
        Tags.of(vpc).add("Name", "aws-security-vpc");                    // Tag the VPC with Name
        Tags.of(vpc).add("Project", "aws-security-oculus");              // Tag the VPC with Project
        
        // Tag the EC2 instance with both Name and Project tags
        Tags.of(ec2Instance).add("Name", "aws-security-ec2-instance");   // Tag the EC2 instance with Name
        Tags.of(ec2Instance).add("Project", "aws-security-oculus");      // Tag the EC2 instance with Project
        
        // Tag the security group with both Name and Project tags
        Tags.of(ec2SecurityGroup).add("Name", "aws-security-ec2-sg");    // Tag the security group with Name
        Tags.of(ec2SecurityGroup).add("Project", "aws-security-oculus"); // Tag the security group with Project
        
        // Tag the IAM role with both Name and Project tags
        Tags.of(ec2Role).add("Name", "aws-security-ec2-role");           // Tag the IAM role with Name
        Tags.of(ec2Role).add("Project", "aws-security-oculus");          // Tag the IAM role with Project
        
        // Tag VPC subnets with both Name and Project tags
        // Note: CDK automatically creates subnets, so we tag them after creation
        vpc.getPublicSubnets().forEach(subnet -> {
            Tags.of(subnet).add("Name", "aws-security-public-subnet");    // Tag public subnets
            Tags.of(subnet).add("Project", "aws-security-oculus");        // Tag public subnets with Project
        });
        
        vpc.getPrivateSubnets().forEach(subnet -> {
            Tags.of(subnet).add("Name", "aws-security-private-subnet");   // Tag private subnets
            Tags.of(subnet).add("Project", "aws-security-oculus");        // Tag private subnets with Project
        });

        // ============================================================================
        // STACK OUTPUTS
        // ============================================================================
        // Define outputs that will be displayed after successful deployment
        // These outputs provide important information for accessing and managing resources
        
        // VPC ID Output
        // This is the unique identifier for the VPC that was created
        CfnOutput.Builder.create(this, "VPCId")
                .value(vpc.getVpcId())                                    // Get the VPC ID
                .description("VPC ID")                                    // Human-readable description
                .build();

        // EC2 Instance ID Output
        // This is the unique identifier for the EC2 instance
        CfnOutput.Builder.create(this, "InstanceId")
                .value(ec2Instance.getInstanceId())                       // Get the instance ID
                .description("EC2 Instance ID")                           // Human-readable description
                .build();

        // EC2 Instance Public IP Output
        // This is the public IP address assigned to the EC2 instance
        // Use this IP to access web services running on the instance
        CfnOutput.Builder.create(this, "InstancePublicIP")
                .value(ec2Instance.getInstancePublicIp())                 // Get the public IP
                .description("EC2 Instance Public IP")                    // Human-readable description
                .build();

        // SSM Connection Command Output
        // This provides the exact command to connect to the instance via SSM Session Manager
        // SSM provides secure access without needing SSH keys or direct network access
        CfnOutput.Builder.create(this, "SSMConnectCommand")
                .value("aws ssm start-session --target " + ec2Instance.getInstanceId()) // Build the SSM command
                .description("Command to connect to instance via SSM")    // Human-readable description
                .build();
    }
}
