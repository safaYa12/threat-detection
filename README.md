# AWS Incident Response & Threat Detection Lab

> Hands-on cloud security project demonstrating Server-Side Request Forgery (SSRF), EC2 instance credential compromise, AWS IAM permission-denied events, CloudFormation abuse attempts, Systems Manager (SSM) remote command execution, forensic investigation, and AWS WAF protections.

## Table of Contents

- [Project Overview](#project-overview)
- [Objectives](#objectives)
- [Architecture and Technologies](#architecture-and-technologies)
- [Prerequisites](#prerequisites)
- [1. Infrastructure Setup and Validation](#1-infrastructure-setup-and-validation)
- [2. Vulnerable Web Application Testing](#2-vulnerable-web-application-testing)
- [3. Simulating Unauthorized IAM Activity](#3-simulating-unauthorized-iam-activity)
- [4. Simulating CloudFormation Abuse](#4-simulating-cloudformation-abuse)
- [5. Simulating SSM Remote Command Execution](#5-simulating-ssm-remote-command-execution)
- [6. Investigating Events with CloudTrail and Athena](#6-investigating-events-with-cloudtrail-and-athena)
- [7. Investigating Findings with GuardDuty](#7-investigating-findings-with-guardduty)
- [8. Configuring AWS WAF Protections](#8-configuring-aws-waf-protections)
- [9. Validation Checklist](#9-validation-checklist)
- [Security Findings and Recommendations](#security-findings-and-recommendations)
- [Cleanup and Cost Management](#cleanup-and-cost-management)
- [Lessons Learned](#lessons-learned)

## Project Overview

This project explores how an attacker could abuse a vulnerable image-rendering web application to access internal resources, obtain EC2-associated temporary credentials, and attempt unauthorized actions in an AWS environment.

The lab demonstrates how to identify suspicious activity using AWS CloudTrail, Amazon Athena, Amazon GuardDuty, and Application Load Balancer logs, followed by implementing AWS WAF rules to restrict selected malicious requests.

The project follows a defensive security workflow:

1. Deploy and validate the lab infrastructure.
2. Simulate controlled attack scenarios.
3. Generate security telemetry.
4. Investigate suspicious events.
5. Implement and validate protective controls.

**Environment:** AWS security workshop lab

**Scope:** Authorized testing of dedicated lab resources only.

## Objectives

- Understand SSRF vulnerabilities in web applications.
- Explore the security risks associated with EC2 instance metadata.
- Understand temporary AWS role credentials and IAM least privilege.
- Generate and investigate denied IAM and CloudFormation API requests.
- Examine the security impact of excessive AWS Systems Manager permissions.
- Investigate CloudTrail events using Amazon Athena.
- Review EC2 credential misuse findings in Amazon GuardDuty.
- Analyze Application Load Balancer access logs.
- Configure AWS WAF rules to block selected requests and restrict user agents.
- Document defensive improvements and incident response findings.

## Architecture and Technologies

### Lab architecture

```text
                 Tester / Browser
                        |
                        v
             Application Load Balancer
                        |
                        v
             Vulnerable PHP Web App
                  /demo.php?site=
                        |
                        v
               EC2 Instance Metadata
                        |
                 Temporary Role
                  Credentials
                        |
                        v
                 AWS API Requests
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
       AWS IAM     CloudFormation    AWS SSM
          |             |             |
          +-------------+-------------+
                        |
                        v
                   CloudTrail
                        |
                        v
                 Amazon Athena
                        |
             +----------+----------+
             |                     |
             v                     v
          GuardDuty          ALB Access Logs

        AWS WAF protects the web application
        by filtering matching incoming requests.
```

*Conceptual architecture illustrating the lab's attack and detection paths.*

### Technologies used

| Technology | Purpose |
|---|---|
| Amazon EC2 | Hosts the vulnerable web application |
| Application Load Balancer | Provides the application's HTTP entry point |
| AWS CloudFormation | Deploys the lab infrastructure |
| EC2 Instance Metadata Service | Supplies instance metadata and potentially temporary credentials |
| AWS IAM | Controls permissions for AWS API operations |
| AWS Systems Manager | Demonstrates the risk of excessive remote command permissions |
| AWS CloudTrail | Records AWS API activity |
| Amazon Athena | Queries CloudTrail and load balancer logs |
| AWS Glue Data Catalog | Provides the database and table definitions used by Athena |
| Amazon GuardDuty | Detects suspicious credential use |
| Amazon S3 | Stores log data used by the lab |
| AWS WAF | Filters requests reaching the protected application |
| AWS CLI | Executes and validates lab operations |

## Prerequisites

Before starting, ensure that you have:

- An AWS account authorized to run the workshop.
- Access to the AWS Management Console.
- The lab's CloudFormation infrastructure deployed.
- An initialized EC2 instance hosting the web application.
- The workshop's logging and detection services configured.
- AWS CLI access, where required.
- Amazon Athena configured with the workshop's database and workgroup.
- Permission to view CloudTrail, GuardDuty, Application Load Balancer logs, and AWS WAF resources.

**Important:** This lab intentionally uses vulnerable infrastructure and temporary role credentials. Do not reproduce these tests against production systems or systems you do not own or have explicit permission to assess.

## 1. Infrastructure Setup and Validation

### 1.1 Retrieve the Application Load Balancer URL

1. Sign in to the AWS Management Console.
2. Open **CloudFormation**.
3. Select the workshop's deployed stack.
4. Open the **Outputs** tab.
5. Locate the `LoadBalancerUrl` output.
6. Copy its value and save it for subsequent tests.

The URL should resemble:

```text
http://<load-balancer-dns-name>
```

Use the actual DNS name provided by CloudFormation, rather than the example placeholder.

### 1.2 Verify EC2 initialization

1. Open the EC2 console.
2. Select the instance hosting the vulnerable web application.
3. Check the instance status.
4. Wait until **2/2 status checks passed**.

### 1.3 Verify application availability

Open the load balancer URL in a browser.

Expected result: the application loads and displays the **Image Rendering Page** heading.

Record the application URL in your private lab notes. Avoid committing account-specific resource identifiers or sensitive information to the repository.

## 2. Vulnerable Web Application Testing

### 2.1 Understand the application

The application accepts an image URL and attempts to retrieve and render the image on the application page.

The vulnerable PHP endpoint uses the following parameter:

```text
/demo.php?site=
```

The complete endpoint has this format:

```text
http://<load-balancer-dns-name>/demo.php?site=
```

Because the server retrieves a user-supplied URL, inadequate URL validation can allow Server-Side Request Forgery (SSRF).

### 2.2 Test normal image rendering

1. Open the application home page.
2. Find an image hosted on a public website.
3. Copy its direct image URL.
4. Paste the URL into the application's input field.
5. Select **Show Image!**.
6. Confirm that the image appears.

**Expected result:** The image is retrieved and rendered by the application.

This establishes a baseline for normal application functionality before investigating suspicious requests.

### 2.3 Understand the SSRF risk

An SSRF vulnerability can allow a remote user to make the server issue requests to destinations selected by the user.

Potential targets include:

- Internal web services.
- Private network addresses.
- Cloud instance metadata endpoints.
- Services that trust requests originating from the application server.

For this AWS lab, the EC2 metadata endpoint is:

```text
http://169.254.169.254/
```

The metadata service may expose information about the instance and, depending on configuration, temporary credentials associated with its IAM role.

**Security note:** The ability to retrieve metadata does not automatically mean credentials can be obtained. Metadata service configuration, including whether IMDSv2 is enforced, affects exploitability.

### 2.4 Record the observation

Document:

- The endpoint tested.
- Whether normal image rendering worked.
- Whether unexpected internal destinations were accessible.
- HTTP status codes and relevant application responses.
- Corresponding load balancer logs and timestamps.

Do not include actual access keys, secret keys, or session tokens in screenshots, reports, or Git commits.

## 3. Simulating Unauthorized IAM Activity

This phase demonstrates how compromised temporary credentials may be used to attempt administrative actions.

### 3.1 Configure the lab credentials

Use the temporary credentials obtained through the preceding workshop exercise in an isolated terminal session. Never place credentials directly in this README.

For an authorized lab session, the workshop's Linux shell instructions use these environment variables:

```bash
export AWS_ACCESS_KEY_ID="<temporary-access-key-id>"
export AWS_SECRET_ACCESS_KEY="<temporary-secret-access-key>"
export AWS_DEFAULT_REGION="<lab-region>"
export AWS_SESSION_TOKEN="<temporary-session-token>"
```

These values are placeholders, not valid credentials.

Environment variables are preferable to committing secrets into files, but they can still be exposed through shell history, process environments, debugging, or terminal logs. Use a dedicated, temporary shell and clear the variables when finished.

### 3.2 Verify the active identity

Run:

```bash
aws sts get-caller-identity
```

Inspect the returned account and ARN.

**Expected result:** The ARN identifies the workshop's assumed `webdev` role.

If the identity is incorrect, stop and verify the active credential source before continuing. Do not run the lab actions against another AWS account.

### 3.3 Attempt to create an IAM user

Run the following command in the designated lab account:

```bash
aws iam create-user --user-name adm1n
```

The workshop expects this request to fail because the `webdev` role does not have permission to create IAM users.

Repeat the denied request three additional times, as specified by the workshop, to generate enough CloudTrail events for investigation.

**Expected security observation:** The API calls are recorded even though the operations are denied.

The denial is a useful security control. The unusual attempt itself remains an event that defenders can investigate.

## 4. Simulating CloudFormation Abuse

This phase demonstrates attempts to create AWS infrastructure using compromised credentials.

### 4.1 Obtain the sample template

Download the `samplestack.template` file from the official workshop materials and save it in a dedicated lab directory.

Official workshop resource:

[Sample CloudFormation template](https://static.us-east-1.prod.workshops.aws/37fbd01c-0949-4f68-83c4-6379f7746b46/static/samplestack.template)

### 4.2 Attempt to create a stack

From the directory containing the downloaded template, run:

```bash
aws cloudformation create-stack \
  --stack-name badstack \
  --template-body file://samplestack.template
```

The workshop expects this operation to be denied because the assumed role lacks the necessary permissions.

Repeat the attempt three additional times to generate further CloudTrail events.

### 4.3 Security observations

Review the results and record:

- The attempted API operation.
- The denied status and error message.
- The identity associated with the request.
- The event timestamp and source IP address.
- Whether the expected CloudTrail records appear.

A denied API request is not equivalent to a successful resource creation. Verify the recorded outcome rather than assuming that a resource was deployed.

## 5. Simulating SSM Remote Command Execution

This phase demonstrates the consequences of excessive AWS Systems Manager permissions.

### 5.1 Identify managed EC2 instances

After confirming that the active credentials belong to the intended workshop role, run:

```bash
aws ssm describe-instance-information \
  --output text \
  --query "InstanceInformationList[*]"
```

Identify the relevant lab instance and record its instance ID.

If the command fails with an authorization error, inspect the error and role policy. Do not expand permissions simply to force the test to succeed.

### 5.2 Understand the command execution path

The workshop demonstrates the use of `AWS-RunShellScript` with `ssm:SendCommand` to execute a harmless identity-check command on the designated EC2 instance.

The demonstration uses:

```text
whoami
```

If executed successfully in the workshop's configured environment, the output is expected to identify the execution user, which the workshop reports as `root`.

This highlights the potential impact of remote command permissions: an AWS API credential can become a path to operating-system command execution.

Only perform this exercise against the dedicated lab instance and under the workshop's explicit authorization.

### 5.3 Retrieve the execution results

The workshop records a command ID for the submitted SSM operation. Use that ID to inspect the corresponding command and invocation details in Systems Manager.

The relevant API operations are:

- `SendCommand`
- `ListCommands`
- `ListCommandInvocations`

Record the command ID, target instance, execution status, and output needed for the investigation. Treat command IDs and instance IDs as lab evidence, not as credentials.

## 6. Investigating Events with CloudTrail and Athena

Amazon Athena allows the workshop's CloudTrail records to be queried using SQL.

### 6.1 Open the Athena query editor

In the AWS Management Console:

1. Open Amazon Athena.
2. Select workgroup `IRWorkshopAthenaWorkgroup`.
3. Select database `irworkshopgluedatabase`.
4. Use table `irworkshopgluetablecloudtrail`.
5. Run the following queries to investigate the generated events.

The SQL below follows the workshop's table names and schema. If your environment uses a different schema, adapt the queries to the actual columns.

### 6.2 Investigate IAM user creation attempts

Start with all matching `CreateUser` events:

```sql
SELECT *
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE eventname = 'CreateUser';
```

Narrow the query to activity associated with EC2 assumed-role sessions:

```sql
SELECT *
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE eventname = 'CreateUser'
  AND useridentity.principalid LIKE '%i-%';
```

Inspect these fields:

- `eventtime`
- `eventname`
- `useridentity`
- `sourceipaddress`
- `useragent`
- `errorcode`
- `errormessage`
- `requestparameters`

**Expected observation:** The unauthorized user creation attempts should be visible, and denied attempts should have corresponding error information.

### 6.3 Investigate CloudFormation stack creation attempts

Search all `CreateStack` events:

```sql
SELECT *
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE eventname = 'CreateStack';
```

Narrow the query to EC2-associated assumed-role activity:

```sql
SELECT *
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE eventname = 'CreateStack'
  AND useridentity.principalid LIKE '%i-%';
```

Inspect the identity, event time, error code, error message, and request parameters.

**Expected observation:** The workshop's unauthorized stack creation attempts should be recorded with evidence of the denied operation.

### 6.4 Investigate AWS Management Console login events

Use the following query:

```sql
SELECT *
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE eventname = 'ConsoleLogin'
  AND useridentity.principalid LIKE '%i-%';
```

Review the identity and response fields to determine whether a login succeeded or failed.

A console login using an EC2-associated role identity is unusual and warrants investigation. Interpret results in the context of the actual identity and event details rather than treating every match as malicious.

### 6.5 Investigate Systems Manager command execution

Search for `SendCommand` events:

```sql
SELECT *
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE eventname = 'SendCommand'
  AND useridentity.principalid LIKE '%i-%';
```

Review:

- `useridentity`
- `eventtime`
- `requestparameters`
- `responseelements`
- `errorcode`
- `sourceipaddress`

Use the command ID returned in the event to inspect the associated SSM command in the AWS console or through the Systems Manager APIs.

CloudTrail establishes which AWS API action was requested. Systems Manager command and invocation records provide additional evidence about the command and its execution outcome.

### 6.6 Investigate Application Load Balancer logs

The workshop also uses Athena to analyze Application Load Balancer access logs.

Identify observed browser user agents:

```sql
SELECT DISTINCT user_agent
FROM "irworkshopgluedatabase"."irworkshopgluetablealb";
```

Review requests that contain the EC2 metadata endpoint in the request URL:

```sql
SELECT client_ip, user_agent
FROM "irworkshopgluedatabase"."irworkshopgluetablealb"
WHERE request_url LIKE '%http://169.254.169.254%';
```

Use these results to identify the source IP addresses and user agents associated with the simulated SSRF requests.

**Important:** The client IP recorded by the load balancer is not necessarily the identity of the individual who initiated the activity. Account for NAT, VPNs, proxies, and other network intermediaries when interpreting source addresses.

Load balancer logs can take several minutes to become queryable, depending on the workshop's delivery and catalog configuration.

## 7. Investigating Findings with GuardDuty

Amazon GuardDuty analyzes AWS activity to identify potential threats, including suspicious use of EC2 instance credentials.

### 7.1 Review findings

1. Open Amazon GuardDuty in the AWS Management Console.
2. Navigate to **Findings**.
3. Look for findings related to EC2 instance credential misuse.

The workshop describes these finding types:

```text
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
```

The expected finding for the demonstrated scenario is:

```text
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS
```

### 7.2 Correlate the evidence

Where available, inspect:

- Access key ID, without exposing it in public documentation.
- Associated IAM role or identity.
- EC2 instance details.
- Finding creation time.
- Remote IP address.
- Whether suspicious requests were denied.
- Related CloudTrail events.
- Related SSM command records.

Use timestamps, identities, source addresses, and command IDs to correlate evidence across services.

GuardDuty findings can take 45 minutes or longer to appear. The absence of an immediate finding does not establish that the simulated activity was harmless or that detection is working correctly.

## 8. Configuring AWS WAF Protections

The workshop's bonus exercise demonstrates how AWS WAF can filter requests before they reach the vulnerable application.

**Cost note:** AWS WAF resources and associated request processing may incur additional charges. Review current AWS pricing before enabling the bonus resources.

### 8.1 Generate baseline traffic

Use the web application normally from two different browsers, such as Chrome and Firefox.

The workshop also generates a controlled request containing the EC2 metadata endpoint in the vulnerable query parameter. Perform such testing only within the authorized lab.

Allow time for the Application Load Balancer logs to arrive in Athena.

### 8.2 Create an IP set

1. Open **AWS WAF & Shield**.
2. Select **IP sets**.
3. Create an IP set, using the workshop's name `WebAppIPSet`.
4. Add the relevant source IP obtained from the lab's Application Load Balancer logs.
5. Use a `/32` subnet mask for a single IPv4 address.
6. Create the IP set.

Use the actual observed lab address, not the illustrative IP address in the workshop documentation.

The IP set can be referenced by a Web ACL rule. An IP-based rule is not a substitute for fixing the SSRF vulnerability.

### 8.3 Block metadata endpoint references

The workshop configures a query-string rule on the `WebAppACL` web ACL.

1. Open **Web ACLs** and select `WebAppACL`.
2. Open **Rules**.
3. Add a custom rule named `QueryRule`.
4. Set the inspection component to **Query string**.
5. Select **Contains string** as the match type.
6. Use the string below as the match value:

```text
http://169.254.169.254
```

7. Set the matching action to **Block**.
8. Save the rule and the Web ACL changes.

### 8.4 Validate the query-string rule

Repeat the baseline test:

- Open the application normally.
- Confirm that ordinary requests remain accessible.
- Submit the workshop's controlled metadata-endpoint test.
- Check the resulting HTTP response and WAF metrics or logs.

**Expected observation:** The application remains accessible for normal requests, while matching metadata-endpoint requests are blocked with HTTP `403 Forbidden`.

A literal-string rule is a demonstration rather than comprehensive SSRF protection. URL encoding, alternative IP representations, redirects, IPv6, and other internal destinations may evade a simple match.

### 8.5 Restrict user agents

The workshop also demonstrates a browser user-agent allowlist.

1. Edit `WebAppACL`.
2. Remove the previous `QueryRule` if following the workshop's sequential configuration exactly.
3. Add a custom rule named `UserAgentRule`.
4. Configure inspection of all headers, including the specified key `User-Agent`.
5. Select **Contains string** as the match type.
6. Use `Chrome` as the match value.
7. Set the matching action to **Allow**.
8. Save the rule.
9. Change the default action for requests that do not match any rule to **Block**.
10. Save the Web ACL.

Test the application using Chrome and Firefox.

**Expected observation:** Requests with matching Chrome user-agent headers are allowed by this rule, while other requests are blocked by the default action.

This is a lab exercise, not a recommended production access-control strategy. User-agent strings are easy to spoof and should not be treated as reliable authentication or authorization signals. A production configuration should also consider the effect of replacing the earlier query-string rule.

## 9. Validation Checklist

Use this checklist to track completion of the lab.

- [ ] CloudFormation stack deployed successfully.
- [ ] `LoadBalancerUrl` retrieved from CloudFormation outputs.
- [ ] EC2 instance reached `2/2` status checks passed.
- [ ] Web application loaded successfully.
- [ ] Normal image rendering tested.
- [ ] Vulnerable endpoint and SSRF risk documented.
- [ ] Active AWS CLI identity verified.
- [ ] IAM user creation attempts generated.
- [ ] CloudFormation stack creation attempts generated.
- [ ] SSM command execution scenario investigated.
- [ ] `CreateUser` events queried in Athena.
- [ ] `CreateStack` events queried in Athena.
- [ ] `ConsoleLogin` events queried in Athena.
- [ ] `SendCommand` events queried in Athena.
- [ ] Application Load Balancer logs queried.
- [ ] GuardDuty findings reviewed, when available.
- [ ] AWS WAF IP set configured.
- [ ] Query-string rule tested.
- [ ] User-agent rule tested.
- [ ] Results and relevant evidence documented.
- [ ] Lab resources reviewed for cleanup.

Mark a step complete only after verifying the result in your environment.

## Security Findings and Recommendations

| Finding | Security impact | Recommended mitigation |
|---|---|---|
| SSRF in the image-rendering endpoint | May allow server-side requests to internal services | Enforce strict destination allowlists and safe URL parsing |
| Exposure of EC2 metadata | May expose instance information or temporary role credentials | Enforce IMDSv2 and minimize metadata access |
| Temporary credential misuse | May enable unauthorized AWS API activity | Use short-lived credentials, investigate suspicious usage, and revoke or contain affected access |
| Excessive IAM permissions | Can enable unintended administrative operations | Apply least-privilege policies and regularly review role permissions |
| SSM command execution permissions | Can provide remote operating-system command execution | Restrict `ssm:SendCommand`, managed-instance access, and document permissions |
| Unauthorized CloudFormation operations | May allow creation or modification of infrastructure | Restrict stack and change-set operations to approved identities |
| Suspicious API requests | May indicate credential compromise or privilege escalation attempts | Monitor CloudTrail and alert on anomalous API activity |
| SSRF-related HTTP requests | Can expose internal services through a vulnerable application | Combine application-layer URL validation, network egress controls, and WAF protections |
| User-agent filtering | Easily bypassed by clients that spoof headers | Do not use user-agent filtering as an authentication mechanism |

### Recommended production improvements

1. **Fix the application vulnerability.** Prefer a strict allowlist of permitted image hosts and validate URLs after parsing and resolving redirects.
2. **Enforce IMDSv2.** Configure the EC2 instance to require IMDSv2, while recognizing that this is an additional barrier rather than a complete SSRF fix.
3. **Restrict network egress.** Prevent the application from reaching sensitive internal endpoints and services it does not require.
4. **Apply least privilege.** Remove unnecessary IAM permissions, especially those that allow privileged API operations or remote command execution.
5. **Centralize audit evidence.** Retain CloudTrail and load balancer logs with appropriate access controls and retention policies.
6. **Configure actionable detections.** Alert on anomalous use of EC2-associated credentials, suspicious IAM operations, and unexpected Systems Manager activity.
7. **Use WAF as defense in depth.** Combine carefully designed managed and custom rules with application fixes and network controls.
8. **Build an incident response process.** Document triage, credential containment, evidence preservation, recovery, and post-incident review.

## Cleanup and Cost Management

Before ending the lab:

1. Review the CloudFormation stack and resources created by the workshop.
2. Identify any resources created during the WAF bonus exercise.
3. Follow the workshop's cleanup instructions for the stack and any separately created resources.
4. Remove temporary local credential environment variables when the session is complete:

```bash
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN
unset AWS_DEFAULT_REGION
```

5. Confirm that the temporary credentials are no longer being used.
6. Check for remaining resources, such as load balancers, EC2 instances, S3 log buckets, Athena query results, and AWS WAF resources.
7. Review AWS Billing and Cost Explorer for any charges associated with the lab.

Do not delete shared or pre-existing resources without confirming ownership. Follow the workshop's cleanup procedure so that dependencies are removed in the correct order.

## Lessons Learned

This project demonstrates that a web application vulnerability can become a cloud security incident when combined with exposed instance credentials and excessive permissions.

The main lessons are:

- SSRF can bridge the boundary between a public web application and internal cloud resources.
- Temporary credentials can be sensitive even when they expire automatically.
- IAM authorization denials can still provide valuable detection evidence.
- CloudTrail and Athena help investigators reconstruct suspicious API activity.
- GuardDuty adds threat detection and investigation context.
- Systems Manager permissions can significantly increase the impact of compromised credentials.
- AWS WAF can block selected requests, but it does not replace secure application design.
- Effective defense requires prevention, detection, investigation, and response working together.

## References

- [AWS Security Workshops](https://catalog.us-east-1.prod.workshops.aws/)
- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [Amazon Athena User Guide](https://docs.aws.amazon.com/athena/latest/ug/)
- [Amazon GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/)
- [AWS Systems Manager User Guide](https://docs.aws.amazon.com/systems-manager/latest/userguide/)
- [AWS WAF Developer Guide](https://docs.aws.amazon.com/waf/latest/developerguide/)
- [EC2 Instance Metadata and User Data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

**Project status:** Hands-on AWS security simulation and detection lab documented.

**Repository note:** Add screenshots of your own verified results, sanitized Athena query outputs, and WAF test evidence before publishing. Never commit AWS credentials, session tokens, private account information, or unredacted security logs.
