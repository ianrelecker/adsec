# Active Directory Security Concepts

This document explains the key security concepts evaluated by ADSecEval and provides background on why these aspects of Active Directory security are important.

## Core Active Directory Security Principles

### 1. Defense in Depth

Active Directory security should implement multiple layers of controls. If one security measure fails, others should be in place to prevent compromise. ADSecEval evaluates whether your AD environment implements proper defense in depth strategies.

### 2. Least Privilege

Users and service accounts should have only the minimum permissions necessary to perform their functions. Excessive privileges increase the attack surface and potential impact of a compromised account.

### 3. Separation of Duties

Administrative responsibilities should be distributed among different individuals to prevent any single person from having excessive control and to reduce the risk of malicious actions.

## Key Areas Assessed by ADSecEval

### Privileged Account Security

#### Why It Matters

Privileged accounts (Domain Admins, Enterprise Admins, etc.) have extensive access to domain resources. If compromised, these accounts can be used to take complete control of the AD environment. 

#### Key Security Controls

1. **Administrative Tiering**: Implementing a tiered administrative model separates administrative accounts into different privilege levels (Tier 0, 1, and 2) to limit lateral movement.

2. **Protected Accounts**: Using features like the Protected Users group and AdminSDHolder to secure privileged accounts.

3. **Multi-Factor Authentication**: Requiring MFA for privileged account access significantly reduces the risk of credential theft.

4. **Just-In-Time Administration**: Providing temporary elevated privileges only when needed, rather than permanent assignments.

5. **Privileged Access Workstations (PAWs)**: Dedicated, hardened workstations for administrative tasks.

### Password Policies

#### Why It Matters

Weak password policies make it easier for attackers to guess or crack passwords, which remains one of the most common attack vectors.

#### Key Security Controls

1. **Password Complexity**: Requirements for length, character types, and complexity.

2. **Password Age**: Controls for minimum and maximum password age.

3. **Password History**: Prevention of password reuse.

4. **Account Lockout**: Protection against brute force attacks.

5. **Fine-Grained Password Policies**: Different password requirements for different user groups.

### Domain Controller Security

#### Why It Matters

Domain controllers hold the Active Directory database and all authentication services. They are the most critical servers in the environment, and compromise of a DC typically means compromise of the entire domain.

#### Key Security Controls

1. **Operating System Security**: Ensuring DCs run supported, patched OS versions.

2. **Secure Channel**: Encrypting and signing communications between domain members.

3. **LDAP Signing**: Preventing LDAP protocol-based attacks.

4. **SMB Signing**: Preventing SMB relay attacks.

5. **NTLM Settings**: Reducing reliance on weaker authentication protocols.

6. **Protected Process Light (PPL)**: Protecting critical security processes from tampering.

### Trust Relationships

#### Why It Matters

Trust relationships extend the security boundary of your Active Directory. A misconfigured trust can allow attackers to leverage a compromised domain to attack trusted domains.

#### Key Security Controls

1. **Trust Types**: Understanding external vs. forest trusts.

2. **SID Filtering**: Preventing SID history-based attacks across trust boundaries.

3. **Selective Authentication**: Limiting which users can authenticate across trusts.

4. **Trust Transitivity**: Understanding and controlling how trusts chain together.

5. **Trust Direction**: Controlling the flow of authentication requests.

## Attack Vectors Addressed

### 1. Credential Theft

Attackers often target credentials through phishing, keylogging, or extracting them from memory (e.g., Mimikatz). Strong password policies, MFA, and protected accounts help mitigate this risk.

### 2. Privilege Escalation

Once inside a network, attackers attempt to elevate their privileges. Administrative tiering, proper permission management, and regular security group reviews help prevent this.

### 3. Lateral Movement

After compromising one system, attackers move laterally across the network. Network segmentation, proper firewall rules, and monitoring for suspicious authentication attempts help detect and prevent lateral movement.

### 4. Domain Dominance

The ultimate goal for many attackers is to achieve domain dominance (e.g., obtaining Domain Admin privileges). Properly secured domain controllers, restricted privileged account usage, and implementing PAW strategies help prevent this.

### 5. Advanced Attack Techniques

#### Kerberoasting

Attackers target service accounts with SPNs to request and offline crack service tickets. This technique allows attackers to obtain service account passwords without sending suspicious traffic or requiring elevated privileges.

#### AS-REP Roasting

By targeting accounts with Kerberos pre-authentication disabled, attackers can request AS-REP tickets and attempt to crack them offline to reveal passwords.

#### NTLM Relay

Attackers capture NTLM authentication traffic and relay it to another service to authenticate as the user. Proper implementation of SMB signing, LDAP signing, and channel binding helps prevent these attacks.

#### Active Directory Certificate Services (ADCS) Abuse

Misconfigured certificate templates can be exploited to obtain certificates for other users, enabling impersonation and unauthorized privilege escalation.

### 6. Group Policy Security

Group Policy is a powerful mechanism that can either strengthen security or, if misconfigured, introduce security vulnerabilities:

- Overprivileged user rights assignments can lead to privilege escalation
- Weak security settings can enable attack techniques
- Insufficient audit policies can allow attacks to go undetected
- Improper GPO permissions can enable attackers to modify security settings

## Remediation Strategies

### Immediate Actions

For critical findings, ADSecEval recommends immediate remediation steps such as:
- Removing excessive privileges
- Enabling MFA for privileged accounts
- Patching domain controllers
- Adjusting insecure settings

### Medium-Term Improvements

For medium-severity findings, recommended improvements include:
- Implementing administrative tiering
- Deploying PAWs
- Enhancing monitoring and logging
- Refining password policies

### Long-Term Strategy

For a comprehensive security posture, consider:
- Regular security assessments
- Advanced detection capabilities
- Red team exercises
- Security training for administrators

## Security Frameworks and Compliance

ADSecEval maps findings to industry security frameworks and compliance standards, providing a comprehensive view of your Active Directory security posture:

### Security Frameworks

1. **Microsoft ESAE/Red Forest** - A tiered administrative model for AD security separation and enhanced protection.

2. **NIST Cybersecurity Framework** - Risk-based approach to managing cybersecurity risk with core functions: Identify, Protect, Detect, Respond, Recover.

3. **CIS Controls** - Prioritized set of actions to protect organizations from known cyber attack vectors, organized into implementation groups.

4. **MITRE ATT&CK** - Knowledge base of adversary tactics and techniques based on real-world observations.

### Compliance Standards

1. **NIST SP 800-53** - Comprehensive security controls catalog for federal information systems with control baselines.

2. **ISO 27001** - International standard for information security management systems (ISMS) with Annex A controls.

3. **PCI DSS** - Payment Card Industry Data Security Standard requirements for handling cardholder data.

4. **HIPAA Security Rule** - Requirements for protecting electronic protected health information (ePHI).

### Privileged Access Management Models

1. **Microsoft Tiered Administration Model** - Separates administrative accounts and systems into tiers to limit lateral movement.

2. **Zero Standing Privileges** - Eliminating permanent privileged access and requiring just-in-time elevation.

3. **Secure Administrative Hosts** - Using dedicated, hardened workstations for administrative tasks.

4. **Administrative Forest Design** - Implementing a separate forest for administrative accounts with enhanced security.

## Conclusion

Active Directory security is a complex, multi-faceted challenge. ADSecEval helps identify weaknesses in your environment and provides actionable recommendations to improve your security posture. By understanding these core concepts, you can better interpret assessment results and implement effective security controls.