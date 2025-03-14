"""
Assessment module for domain controller security in Active Directory.
"""

import logging
from typing import Dict, Any, List, Optional

from .base import AssessmentBase, CheckResult, CheckSeverity

logger = logging.getLogger(__name__)


class DomainControllerAssessment(AssessmentBase):
    """Security assessment for domain controllers in Active Directory."""
    
    name = "Domain Controller Security Assessment"
    description = "Evaluates the security configuration of domain controllers in the Active Directory environment"
    
    def _register_checks(self) -> None:
        """Register domain controller security checks."""
        self.checks = {
            "os_version": self.check_os_version,
            "secure_ldap": self.check_secure_ldap,
            "smb_signing": self.check_smb_signing,
            "dns_security": self.check_dns_security,
            "fsmo_roles": self.check_fsmo_roles,
        }
    
    def check_os_version(self) -> CheckResult:
        """
        Check if domain controllers are running supported OS versions.
        
        Returns:
            CheckResult with findings
        """
        # Get domain controllers
        domain_controllers = self.client.get_domain_controllers()
        
        # Define supported versions
        supported_versions = ["Windows Server 2016", "Windows Server 2019", "Windows Server 2022"]
        
        dc_details = {}
        unsupported_dcs = []
        
        for dc in domain_controllers:
            # Get operating system info
            dc_name = dc.get("name", [""])[0] if isinstance(dc.get("name"), list) else dc.get("name", "")
            os_version = dc.get("operatingSystem", [""])[0] if isinstance(dc.get("operatingSystem"), list) else dc.get("operatingSystem", "")
            
            # Store DC details
            dc_details[dc_name] = {
                "operating_system": os_version,
                "supported": any(sv in os_version for sv in supported_versions)
            }
            
            # Check if OS is supported
            if not any(sv in os_version for sv in supported_versions):
                unsupported_dcs.append({
                    "name": dc_name,
                    "operating_system": os_version
                })
        
        details = {
            "domain_controllers": dc_details,
            "unsupported_count": len(unsupported_dcs),
            "unsupported_dcs": unsupported_dcs
        }
        
        # Check passes if all DCs are running supported OS versions
        passed = len(unsupported_dcs) == 0
        
        return CheckResult(
            name="Domain Controller OS Versions",
            description="Checks if domain controllers are running supported operating system versions",
            severity=CheckSeverity.CRITICAL,
            passed=passed,
            details=details,
            recommendation="Upgrade all domain controllers to Windows Server 2016 or newer",
            reference_url="https://docs.microsoft.com/en-us/windows-server/get-started/windows-server-release-info"
        )
    
    def check_secure_ldap(self) -> CheckResult:
        """
        Check if LDAP signing and LDAPS are properly configured.
        
        Returns:
            CheckResult with findings
        """
        # This check would typically involve querying registry settings or GPOs
        # For demonstration purposes, we'll implement a simplified check
        
        # Get domain controllers
        domain_controllers = self.client.get_domain_controllers()
        
        # In a real implementation, we would check LDAP signing requirements
        # For now, this is a placeholder that always returns "not implemented"
        
        details = {
            "domain_controllers": [dc.get("name", [""])[0] if isinstance(dc.get("name"), list) else dc.get("name", "") for dc in domain_controllers],
            "note": "This check requires inspection of domain controller registry settings, which is not implemented via LDAP"
        }
        
        return CheckResult(
            name="LDAP Security Configuration",
            description="Checks if LDAP signing and LDAPS are properly configured on domain controllers",
            severity=CheckSeverity.HIGH,
            passed=False,  # Always fail in this simplified version
            details=details,
            recommendation="Configure LDAP signing requirements to 'Require signing' and enable LDAPS on all domain controllers",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements"
        )
    
    def check_smb_signing(self) -> CheckResult:
        """
        Check if SMB signing is properly configured.
        
        Returns:
            CheckResult with findings
        """
        # This check would typically involve querying registry settings or GPOs
        # For demonstration purposes, we'll implement a simplified check
        
        # Get domain controllers
        domain_controllers = self.client.get_domain_controllers()
        
        # In a real implementation, we would check SMB signing requirements
        # For now, this is a placeholder that always returns "not implemented"
        
        details = {
            "domain_controllers": [dc.get("name", [""])[0] if isinstance(dc.get("name"), list) else dc.get("name", "") for dc in domain_controllers],
            "note": "This check requires inspection of domain controller registry settings, which is not implemented via LDAP"
        }
        
        return CheckResult(
            name="SMB Signing Configuration",
            description="Checks if SMB signing is properly configured on domain controllers",
            severity=CheckSeverity.HIGH,
            passed=False,  # Always fail in this simplified version
            details=details,
            recommendation="Configure 'Microsoft network server: Digitally sign communications (always)' to 'Enabled' for all domain controllers",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always"
        )
    
    def check_dns_security(self) -> CheckResult:
        """
        Check if DNS security settings are properly configured.
        
        Returns:
            CheckResult with findings
        """
        # This check would typically involve querying DNS server settings
        # For demonstration purposes, we'll implement a simplified check
        
        # Get domain controllers
        domain_controllers = self.client.get_domain_controllers()
        
        # In a real implementation, we would check DNS security settings
        # For now, this is a placeholder that always returns "not implemented"
        
        details = {
            "domain_controllers": [dc.get("name", [""])[0] if isinstance(dc.get("name"), list) else dc.get("name", "") for dc in domain_controllers],
            "note": "This check requires inspection of DNS server settings, which is not implemented via LDAP"
        }
        
        return CheckResult(
            name="DNS Security Configuration",
            description="Checks if DNS security settings are properly configured on domain controllers",
            severity=CheckSeverity.MEDIUM,
            passed=False,  # Always fail in this simplified version
            details=details,
            recommendation="Enable DNSSEC, configure secure DNS updates, and implement DNS logging on all domain controllers",
            reference_url="https://docs.microsoft.com/en-us/windows-server/networking/dns/deploy/dnssec"
        )
    
    def check_fsmo_roles(self) -> CheckResult:
        """
        Check if FSMO roles are properly configured.
        
        Returns:
            CheckResult with findings
        """
        # This check would typically involve querying AD for FSMO role holders
        # For demonstration purposes, we'll implement a simplified check
        
        # In a real implementation, we would detect FSMO role holders
        # For now, this is a placeholder that always returns "not implemented"
        
        details = {
            "note": "This check requires querying AD for FSMO role holders, which is simplified in this version"
        }
        
        return CheckResult(
            name="FSMO Roles Configuration",
            description="Checks if FSMO roles are properly configured and secured",
            severity=CheckSeverity.MEDIUM,
            passed=False,  # Always fail in this simplified version
            details=details,
            recommendation="Ensure FSMO roles are assigned to properly secured domain controllers and consider having backup contingency plans",
            reference_url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/planning-operations-master-role-placement"
        )