"""
Assessment module for Active Directory Certificate Services (ADCS) security.
"""

import logging
from typing import Dict, Any, List, Optional

from .base import AssessmentBase, CheckResult, CheckSeverity

logger = logging.getLogger(__name__)


class ADCSAssessment(AssessmentBase):
    """Security assessment for Active Directory Certificate Services."""
    
    name = "Active Directory Certificate Services Security Assessment"
    description = "Evaluates the security configuration of Active Directory Certificate Services (ADCS)"
    
    def _register_checks(self) -> None:
        """Register ADCS security checks."""
        self.checks = {
            "ca_discovery": self.check_ca_discovery,
            "vulnerable_templates": self.check_vulnerable_templates,
            "enrollment_permissions": self.check_enrollment_permissions,
            "insecure_crypto": self.check_insecure_crypto,
            "ca_security": self.check_ca_security,
        }
    
    def check_ca_discovery(self) -> CheckResult:
        """
        Discover Certificate Authorities in the environment.
        
        Returns:
            CheckResult with findings
        """
        # Look for CA servers in Active Directory
        ca_server_filter = "(&(objectClass=pKIEnrollmentService)(cn=*))"
        ca_servers = self.client.search(
            search_base=f"CN=Public Key Services,CN=Services,CN=Configuration,{self.client.base_dn}",
            search_filter=ca_server_filter,
            attributes=["cn", "dNSHostName", "cACertificate", "certificateTemplates", "whenCreated"]
        )
        
        # Look for NTAuthCertificates object that contains Enterprise CA certificates
        nt_auth_certs = self.client.search(
            search_base=f"CN=Public Key Services,CN=Services,CN=Configuration,{self.client.base_dn}",
            search_filter="(cn=NTAuthCertificates)",
            attributes=["cACertificate"]
        )
        
        # Check for standalone vs enterprise CAs
        enterprise_cas = []
        standalone_cas = []
        
        for ca in ca_servers:
            ca_name = ca.get("cn", [""])[0] if isinstance(ca.get("cn"), list) else ca.get("cn", "")
            ca_host = ca.get("dNSHostName", [""])[0] if isinstance(ca.get("dNSHostName"), list) else ca.get("dNSHostName", "")
            
            # Check if this is an enterprise CA by looking at templates
            # Enterprise CAs have certificate templates, standalone CAs don't
            has_templates = "certificateTemplates" in ca and ca["certificateTemplates"]
            
            ca_info = {
                "name": ca_name,
                "hostname": ca_host,
                "created": ca.get("whenCreated", ""),
                "templates": len(ca.get("certificateTemplates", [])) if has_templates else 0
            }
            
            if has_templates:
                enterprise_cas.append(ca_info)
            else:
                standalone_cas.append(ca_info)
        
        details = {
            "ca_servers_found": len(ca_servers),
            "enterprise_cas": len(enterprise_cas),
            "standalone_cas": len(standalone_cas),
            "enterprise_ca_list": enterprise_cas,
            "standalone_ca_list": standalone_cas,
            "nt_auth_certs_found": len(nt_auth_certs) > 0,
        }
        
        # This check is informational
        return CheckResult(
            name="Certificate Authority Discovery",
            description="Discovers Certificate Authorities in the Active Directory environment",
            severity=CheckSeverity.INFO,
            passed=True,  # This is just a discovery check
            details=details,
            recommendation="Document all Certificate Authorities and ensure they are properly secured",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-certificate-services-client-authentication"
        )
    
    def check_vulnerable_templates(self) -> CheckResult:
        """
        Check for vulnerable certificate templates.
        
        Returns:
            CheckResult with findings
        """
        # Look for certificate templates in Active Directory
        template_filter = "(objectClass=pKICertificateTemplate)"
        templates = self.client.search(
            search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.client.base_dn}",
            search_filter=template_filter,
            attributes=["cn", "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy", 
                       "msPKI-RA-Signature", "msPKI-Enrollment-Flag", "nTSecurityDescriptor"]
        )
        
        # Check for vulnerable settings in templates
        vulnerable_templates = []
        
        for template in templates:
            template_name = template.get("cn", [""])[0] if isinstance(template.get("cn"), list) else template.get("cn", "")
            
            # Check for vulnerable flags - ESC1: Template allows requesters to specify subject
            name_flags = template.get("msPKI-Certificate-Name-Flag", [0])
            if isinstance(name_flags, list):
                name_flags = int(name_flags[0]) if name_flags else 0
            else:
                name_flags = int(name_flags)
            
            subject_alt_name_enabled = bool(name_flags & 1)
            
            # Check for ESC3: Template enables certificate request agent
            ra_signature = template.get("msPKI-RA-Signature", [False])
            if isinstance(ra_signature, list):
                ra_signature = ra_signature[0] if ra_signature else False
            
            # Check for ESC4: Template has vulnerable EKUs
            extended_key_usage = template.get("pKIExtendedKeyUsage", [])
            if not extended_key_usage and "msPKI-Certificate-Application-Policy" in template:
                extended_key_usage = template.get("msPKI-Certificate-Application-Policy", [])
            
            has_client_auth = False
            has_any_purpose = False
            
            if extended_key_usage:
                has_client_auth = "1.3.6.1.5.5.7.3.2" in extended_key_usage  # Client Authentication
                has_any_purpose = "2.5.29.37.0" in extended_key_usage  # Any Purpose
            
            # Check for ESC6: Template has AD CS web enrollment enabled
            enrollment_flags = template.get("msPKI-Enrollment-Flag", [0])
            if isinstance(enrollment_flags, list):
                enrollment_flags = int(enrollment_flags[0]) if enrollment_flags else 0
            else:
                enrollment_flags = int(enrollment_flags)
            
            web_enrollment_enabled = bool(enrollment_flags & 0x00000100)  # PEND_ALL_REQUESTS (CT_FLAG_PEND_ALL_REQUESTS)
            
            # Determine if template is vulnerable
            vulnerabilities = []
            
            if subject_alt_name_enabled:
                vulnerabilities.append("ESC1: Template allows requesters to specify subject alternative names")
            
            if ra_signature:
                vulnerabilities.append("ESC3: Template enables certificate request agent")
            
            if (has_client_auth or has_any_purpose) and subject_alt_name_enabled:
                vulnerabilities.append("ESC4: Template has client authentication EKU and allows requesters to specify subject")
            
            if web_enrollment_enabled:
                vulnerabilities.append("ESC6: Template has web enrollment enabled")
            
            if vulnerabilities:
                vulnerable_templates.append({
                    "name": template_name,
                    "vulnerabilities": vulnerabilities
                })
        
        details = {
            "total_templates": len(templates),
            "vulnerable_templates": len(vulnerable_templates),
            "template_issues": vulnerable_templates,
            "recommendations": [
                "Disable or secure templates that allow requesters to specify subject alternative names",
                "Remove client authentication EKU from templates that allow requesters to specify subject",
                "Restrict enrollment permissions on vulnerable templates",
                "Consider using custom templates with stricter security settings"
            ]
        }
        
        # Check passes if no vulnerable templates found
        passed = len(vulnerable_templates) == 0
        
        return CheckResult(
            name="Vulnerable Certificate Templates",
            description="Checks for vulnerable certificate templates that could be exploited for privilege escalation",
            severity=CheckSeverity.CRITICAL,
            passed=passed,
            details=details,
            recommendation="Disable or secure vulnerable certificate templates that could allow privilege escalation",
            reference_url="https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        )
    
    def check_enrollment_permissions(self) -> CheckResult:
        """
        Check certificate enrollment permissions.
        
        Returns:
            CheckResult with findings
        """
        # This would require checking ACLs on certificate templates
        # For this implementation, we'll return a placeholder with recommendations
        
        details = {
            "note": "Comprehensive enrollment permission checking requires deep ACL analysis",
            "recommendations": [
                "Restrict enrollment permissions to only necessary users and groups",
                "Review all certificate template ACLs for overly permissive settings",
                "Remove enrollment rights for Authenticated Users and Domain Users",
                "Implement approval requirements for sensitive certificate templates",
                "Consider using tools like Certify or PKI Health Tool for detailed analysis"
            ]
        }
        
        return CheckResult(
            name="Certificate Enrollment Permissions",
            description="Checks certificate enrollment permissions for overly permissive settings",
            severity=CheckSeverity.HIGH,
            passed=None,  # Cannot determine via basic LDAP
            details=details,
            recommendation="Review and restrict certificate enrollment permissions to prevent unauthorized certificate issuance",
            reference_url="https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control"
        )
    
    def check_insecure_crypto(self) -> CheckResult:
        """
        Check for insecure cryptographic settings in ADCS.
        
        Returns:
            CheckResult with findings
        """
        # Look for CA settings in AD
        ca_server_filter = "(objectClass=pKIEnrollmentService)"
        ca_servers = self.client.search(
            search_base=f"CN=Public Key Services,CN=Services,CN=Configuration,{self.client.base_dn}",
            search_filter=ca_server_filter,
            attributes=["cn", "dNSHostName", "cACertificate"]
        )
        
        # In a real implementation, we would analyze the certificates for key length, algorithm, etc.
        # For this example, we'll provide a placeholder with best practices
        
        details = {
            "ca_servers": len(ca_servers),
            "note": "Comprehensive cryptographic security assessment requires certificate and CA configuration analysis",
            "recommendations": [
                "Ensure all CA certificates use RSA keys of at least 2048 bits or ECC keys of at least 256 bits",
                "Use SHA-256 or stronger hashing algorithms for all certificates",
                "Disable MD5 and SHA-1 hashing algorithms on all CAs",
                "Configure strong key protection on CA private keys",
                "Implement key recovery agents for critical certificates"
            ]
        }
        
        return CheckResult(
            name="Insecure Cryptographic Settings",
            description="Checks for insecure cryptographic settings in Active Directory Certificate Services",
            severity=CheckSeverity.HIGH,
            passed=None,  # Cannot determine via basic LDAP
            details=details,
            recommendation="Configure strong cryptographic settings on all Certificate Authorities",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/system-cryptography-use-fips-compliant-algorithms-for-encryption-hashing-and-signing"
        )
    
    def check_ca_security(self) -> CheckResult:
        """
        Check CA server security settings.
        
        Returns:
            CheckResult with findings
        """
        # Look for CA servers in AD
        ca_server_filter = "(objectClass=pKIEnrollmentService)"
        ca_servers = self.client.search(
            search_base=f"CN=Public Key Services,CN=Services,CN=Configuration,{self.client.base_dn}",
            search_filter=ca_server_filter,
            attributes=["cn", "dNSHostName"]
        )
        
        ca_list = []
        for ca in ca_servers:
            ca_name = ca.get("cn", [""])[0] if isinstance(ca.get("cn"), list) else ca.get("cn", "")
            ca_host = ca.get("dNSHostName", [""])[0] if isinstance(ca.get("dNSHostName"), list) else ca.get("dNSHostName", "")
            
            ca_list.append({
                "name": ca_name,
                "hostname": ca_host
            })
        
        # In a real implementation, we would check CA server security settings
        # For this example, we'll provide a placeholder with best practices
        
        details = {
            "ca_servers": ca_list,
            "note": "Comprehensive CA server security assessment requires direct access to CA servers",
            "recommendations": [
                "Run enterprise CAs on dedicated servers that are domain members",
                "Run standalone CAs on dedicated servers that are not domain members",
                "Implement physical and logical security controls for CA servers",
                "Store CA private keys in hardware security modules (HSMs)",
                "Configure proper CA backup and recovery procedures",
                "Implement role separation for CA administrators",
                "Configure proper audit logging for all CA activities",
                "Implement network segmentation for CA servers",
                "Keep CA servers updated with security patches"
            ]
        }
        
        return CheckResult(
            name="CA Server Security",
            description="Checks security settings on Certificate Authority servers",
            severity=CheckSeverity.CRITICAL,
            passed=None,  # Cannot determine via basic LDAP
            details=details,
            recommendation="Implement comprehensive security controls for all Certificate Authority servers",
            reference_url="https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786426(v=ws.11)"
        ) 