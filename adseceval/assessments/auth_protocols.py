"""
Assessment module for authentication protocols and advanced authentication in Active Directory.
"""

import logging
from typing import Dict, Any, List, Optional
import ldap3

from .base import AssessmentBase, CheckResult, CheckSeverity

logger = logging.getLogger(__name__)


class AuthProtocolsAssessment(AssessmentBase):
    """Security assessment for authentication protocols in Active Directory."""
    
    name = "Authentication Protocols Security Assessment"
    description = "Evaluates the security configuration of authentication protocols and mechanisms in Active Directory"
    
    def _register_checks(self) -> None:
        """Register authentication protocol security checks."""
        self.checks = {
            "ntlm_usage": self.check_ntlm_usage,
            "ldap_channel_binding": self.check_ldap_channel_binding,
            "kerberos_configuration": self.check_kerberos_configuration,
            "credential_guard": self.check_credential_guard,
            "laps_implementation": self.check_laps_implementation,
            "delegation_security": self.check_delegation_security,
        }
    
    def check_ntlm_usage(self) -> CheckResult:
        """
        Check if NTLM is restricted in the domain.
        
        Returns:
            CheckResult with findings
        """
        # Query NTLM restriction policy from domain GPOs
        # This requires examining GPO settings retrieved via LDAP
        
        # For this implementation, we'll check policy objects that might contain NTLM settings
        ntlm_policies = self.client.search(
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=["displayName", "gPCFileSysPath", "whenCreated", "whenChanged"]
        )
        
        # Check settings in Default Domain Policy or similar
        # In a real implementation, we would parse GPO settings
        # For now, we'll return a placeholder result
        
        gpo_count = len(ntlm_policies)
        
        details = {
            "gpo_count": gpo_count,
            "note": "Complete NTLM restriction validation requires policy analysis. Verify the following settings:",
            "recommendations": [
                "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = 'Deny all'",
                "Network security: Restrict NTLM: NTLM authentication in this domain = 'Deny all'",
                "Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication = 'None'"
            ],
            "gpo_list": [
                {
                    "name": gpo.get("displayName", [""])[0] if isinstance(gpo.get("displayName"), list) else gpo.get("displayName", ""),
                    "path": gpo.get("gPCFileSysPath", [""])[0] if isinstance(gpo.get("gPCFileSysPath"), list) else gpo.get("gPCFileSysPath", "")
                }
                for gpo in ntlm_policies[:5]  # Limit to first 5 for brevity
            ]
        }
        
        return CheckResult(
            name="NTLM Restriction",
            description="Checks if NTLM authentication is restricted in the domain",
            severity=CheckSeverity.HIGH,
            passed=None,  # Cannot determine via basic LDAP
            details=details,
            recommendation="Configure NTLM restriction policies to limit legacy authentication protocols",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain"
        )
    
    def check_ldap_channel_binding(self) -> CheckResult:
        """
        Check if LDAP channel binding and LDAP signing are enforced.
        
        Returns:
            CheckResult with findings
        """
        domain_controllers = self.client.get_domain_controllers()
        
        # In a real implementation, we would check registry settings on DCs
        # For now, we'll simulate a check based on the domain functional level
        functional_level = self.client.domain_info.get("functional_level", 0)
        
        # Windows Server 2016 functional level or higher generally supports channel binding
        # Convert functional_level to int if it's a string
        functional_level_int = int(functional_level) if str(functional_level).isdigit() else 0
        supports_channel_binding = functional_level_int >= 7  # 7 corresponds to Windows Server 2016
        
        details = {
            "domain_controllers": len(domain_controllers),
            "domain_functional_level": functional_level,
            "functional_level_supports_channel_binding": supports_channel_binding,
            "note": "LDAP channel binding enforcement requires registry checks on domain controllers",
            "recommendations": [
                "Set HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding = 2",
                "Set HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity = 2"
            ]
        }
        
        return CheckResult(
            name="LDAP Channel Binding and Signing",
            description="Checks if LDAP channel binding and LDAP signing are enforced",
            severity=CheckSeverity.CRITICAL,
            passed=None,  # Cannot determine via basic LDAP
            details=details,
            recommendation="Enable LDAP channel binding and LDAP signing to prevent NTLM relay attacks",
            reference_url="https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a"
        )
    
    def check_kerberos_configuration(self) -> CheckResult:
        """
        Check Kerberos security configuration.
        
        Returns:
            CheckResult with findings
        """
        # Check Kerberos settings in domain
        domain_controllers = self.client.get_domain_controllers()
        
        # Check for DES encryption support - this is insecure
        des_disabled = True
        rc4_disabled = True
        aes_enabled = True
        
        # Check each DC's Kerberos settings via supported encryption types
        weak_encryption_dcs = []
        
        for dc in domain_controllers:
            dc_name = dc.get("name", [""])[0] if isinstance(dc.get("name"), list) else dc.get("name", "")
            
            # Get supported encryption types
            supported_enc = dc.get("msDS-SupportedEncryptionTypes", [0])
            if isinstance(supported_enc, list):
                supported_enc = supported_enc[0] if supported_enc else 0
            else:
                supported_enc = int(supported_enc)
            
            # Parse encryption types
            encryption_types = {
                "DES": bool(supported_enc & 1),
                "DES_CRC": bool(supported_enc & 2),
                "RC4_HMAC": bool(supported_enc & 4),
                "AES128_CTS_HMAC_SHA1": bool(supported_enc & 8),
                "AES256_CTS_HMAC_SHA1": bool(supported_enc & 16)
            }
            
            # Check if weak encryption is enabled
            if encryption_types["DES"] or encryption_types["DES_CRC"]:
                des_disabled = False
                weak_encryption_dcs.append({
                    "name": dc_name,
                    "weakness": "DES encryption enabled"
                })
            
            if encryption_types["RC4_HMAC"] and not (encryption_types["AES128_CTS_HMAC_SHA1"] or encryption_types["AES256_CTS_HMAC_SHA1"]):
                rc4_disabled = False
                weak_encryption_dcs.append({
                    "name": dc_name,
                    "weakness": "Only RC4 encryption enabled, AES disabled"
                })
            
            if not (encryption_types["AES128_CTS_HMAC_SHA1"] or encryption_types["AES256_CTS_HMAC_SHA1"]):
                aes_enabled = False
                weak_encryption_dcs.append({
                    "name": dc_name,
                    "weakness": "AES encryption not enabled"
                })
        
        details = {
            "domain_controllers": len(domain_controllers),
            "des_disabled": des_disabled,
            "rc4_only": not rc4_disabled,
            "aes_enabled": aes_enabled,
            "weak_encryption_dcs": weak_encryption_dcs,
            "recommendations": [
                "Disable DES encryption types",
                "Enable AES encryption types",
                "Consider disabling RC4 after ensuring all systems support AES"
            ]
        }
        
        # Check passes if DES is disabled and AES is enabled
        passed = des_disabled and aes_enabled
        
        return CheckResult(
            name="Kerberos Encryption Configuration",
            description="Checks if secure Kerberos encryption types are configured",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Configure Kerberos to use only strong encryption types (AES) and disable weak encryption types (DES, RC4)",
            reference_url="https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview"
        )
    
    def check_credential_guard(self) -> CheckResult:
        """
        Check if Windows Defender Credential Guard is configured.
        
        Returns:
            CheckResult with findings
        """
        # This would require checking Group Policy settings
        # We'll return a placeholder result with guidance
        
        details = {
            "note": "Windows Defender Credential Guard configuration requires GPO analysis",
            "recommendations": [
                "Enable Virtualization-based security",
                "Enable Credential Guard with UEFI lock",
                "Use Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security"
            ]
        }
        
        return CheckResult(
            name="Windows Defender Credential Guard",
            description="Checks if Windows Defender Credential Guard is configured",
            severity=CheckSeverity.HIGH,
            passed=None,  # Cannot determine via basic LDAP
            details=details,
            recommendation="Enable Windows Defender Credential Guard to protect credentials from theft",
            reference_url="https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard"
        )
    
    def check_laps_implementation(self) -> CheckResult:
        """
        Check if Local Administrator Password Solution (LAPS) is implemented.
        
        Returns:
            CheckResult with findings
        """
        # Check for LAPS schema extensions
        laps_attributes = ["ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"]
        
        # Check if LAPS schema extensions exist
        schema_entries = []
        
        for attr in laps_attributes:
            attr_results = self.client.search(
                search_base=f"CN=Schema,CN=Configuration,{self.client.base_dn}",
                search_filter=f"(lDAPDisplayName={attr})",
                attributes=["lDAPDisplayName", "attributeID"]
            )
            
            if attr_results:
                schema_entries.append(attr)
        
        # Check if computers have LAPS attributes populated
        computer_sample = self.client.search(
            search_filter="(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",  # Non-DC computers
            attributes=["name", "ms-Mcs-AdmPwdExpirationTime"],
            search_scope=ldap3.SUBTREE
        )[:10]  # Limit to 10 computers for sample
        
        laps_used = False
        laps_computers = 0
        
        if len(schema_entries) == 2:  # Both LAPS attributes found in schema
            for computer in computer_sample:
                if computer.get("ms-Mcs-AdmPwdExpirationTime", []):
                    laps_computers += 1
            
            laps_used = laps_computers > 0
        
        details = {
            "laps_schema_extensions": schema_entries,
            "schema_extensions_count": len(schema_entries),
            "computer_sample_size": len(computer_sample),
            "computers_with_laps": laps_computers,
            "laps_implemented": laps_used,
            "recommendations": [
                "Deploy LAPS to manage local administrator passwords",
                "Ensure LAPS GPO settings are applied to all workstations and servers",
                "Regularly audit LAPS permissions to ensure proper access controls"
            ]
        }
        
        return CheckResult(
            name="Local Administrator Password Solution (LAPS)",
            description="Checks if LAPS is implemented to manage local administrator passwords",
            severity=CheckSeverity.HIGH,
            passed=laps_used,
            details=details,
            recommendation="Implement LAPS to securely manage and rotate local administrator passwords",
            reference_url="https://docs.microsoft.com/en-us/defender-for-identity/security-assessment-laps"
        )
    
    def check_delegation_security(self) -> CheckResult:
        """
        Check for insecure Kerberos delegation configurations.
        
        Returns:
            CheckResult with findings
        """
        # Check for unconstrained delegation
        unconstrained_delegation = self.client.search(
            search_filter="(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            attributes=["name", "userAccountControl", "servicePrincipalName"],
            search_scope=ldap3.SUBTREE
        )
        
        # Check for constrained delegation
        constrained_delegation = self.client.search(
            search_filter="(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))",
            attributes=["name", "msDS-AllowedToDelegateTo"],
            search_scope=ldap3.SUBTREE
        )
        
        # Check for resource-based constrained delegation
        rbcd_query = self.client.search(
            search_filter="(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
            attributes=["name", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
            search_scope=ldap3.SUBTREE
        )
        
        # Find risky delegation configurations
        sensitive_accounts_with_delegation = self.client.search(
            search_filter="(&(|(objectCategory=user)(objectCategory=computer))(userAccountControl:1.2.840.113556.1.4.803:=1048576))",
            attributes=["name", "userAccountControl", "servicePrincipalName"],
            search_scope=ldap3.SUBTREE
        )
        
        details = {
            "unconstrained_delegation_count": len(unconstrained_delegation),
            "constrained_delegation_count": len(constrained_delegation),
            "resource_based_delegation_count": len(rbcd_query),
            "sensitive_accounts_with_delegation": len(sensitive_accounts_with_delegation),
            "unconstrained_delegation_computers": [
                comp.get("name", [""])[0] if isinstance(comp.get("name"), list) else comp.get("name", "")
                for comp in unconstrained_delegation[:10]  # Limit to first 10
            ],
            "sensitive_accounts": [
                acct.get("name", [""])[0] if isinstance(acct.get("name"), list) else acct.get("name", "")
                for acct in sensitive_accounts_with_delegation
            ],
            "recommendations": [
                "Replace unconstrained delegation with constrained delegation",
                "Configure 'Account is sensitive and cannot be delegated' for privileged accounts",
                "Regularly audit delegation configurations"
            ]
        }
        
        # Check passes if no unconstrained delegation and no sensitive accounts with delegation
        passed = len(unconstrained_delegation) == 0 and len(sensitive_accounts_with_delegation) == 0
        
        return CheckResult(
            name="Kerberos Delegation Security",
            description="Checks for insecure Kerberos delegation configurations",
            severity=CheckSeverity.CRITICAL,
            passed=passed,
            details=details,
            recommendation="Replace unconstrained delegation with constrained delegation and protect sensitive accounts from delegation",
            reference_url="https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
        ) 