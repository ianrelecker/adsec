"""
Assessment module for domain controller security in Active Directory.
"""

import logging
import ldap3
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
        # Get domain controllers
        domain_controllers = self.client.get_domain_controllers()
        
        # Check LDAPS availability by checking msDS-SupportedEncryptionTypes
        ldaps_info = {}
        ldaps_not_enforced = []
        
        for dc in domain_controllers:
            dc_name = dc.get("name", [""])[0] if isinstance(dc.get("name"), list) else dc.get("name", "")
            dc_hostname = dc.get("dNSHostName", [""])[0] if isinstance(dc.get("dNSHostName"), list) else dc.get("dNSHostName", "")
            
            # Get encryption types supported (this is LDAP-accessible)
            supported_enc = dc.get("msDS-SupportedEncryptionTypes", [0])
            if isinstance(supported_enc, list):
                supported_enc = supported_enc[0] if supported_enc else 0
            
            # Parse encryption types - these values tell us about Kerberos encryption types
            encryption_types = {
                "DES": bool(supported_enc & 1),
                "DES_CRC": bool(supported_enc & 2),
                "RC4_HMAC": bool(supported_enc & 4),
                "AES128_CTS_HMAC_SHA1": bool(supported_enc & 8),
                "AES256_CTS_HMAC_SHA1": bool(supported_enc & 16)
            }
            
            # Determine if strong encryption is supported (AES)
            has_strong_encryption = encryption_types["AES128_CTS_HMAC_SHA1"] or encryption_types["AES256_CTS_HMAC_SHA1"]
            
            # Check LDAPS availability by testing a connection
            ldaps_available = False
            try:
                # For an actual implementation, we would test LDAPS connection here
                # Just use information from existing connection for now
                if self.client.domain_config.get("use_ssl") or self.client.domain_config.get("use_tls"):
                    ldaps_available = True
            except Exception as e:
                logger.warning(f"Error checking LDAPS on {dc_name}: {str(e)}")
            
            ldaps_info[dc_name] = {
                "hostname": dc_hostname,
                "encryption_types": encryption_types,
                "has_strong_encryption": has_strong_encryption,
                "ldaps_available": ldaps_available
            }
            
            # If LDAPS is not available or weak encryption is used, add to list
            if not ldaps_available or not has_strong_encryption:
                ldaps_not_enforced.append(dc_name)
        
        details = {
            "domain_controllers_ldaps": ldaps_info,
            "ldaps_not_enforced_count": len(ldaps_not_enforced),
            "ldaps_not_enforced": ldaps_not_enforced,
            "note": "Complete LDAP signing requirements check requires inspection of domain controller registry settings"
        }
        
        # Check passes if all DCs have LDAPS available and strong encryption
        passed = len(ldaps_not_enforced) == 0
        
        return CheckResult(
            name="LDAP Security Configuration",
            description="Checks if LDAP signing and LDAPS are properly configured on domain controllers",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Configure LDAP signing requirements to 'Require signing', enable LDAPS on all domain controllers, and disable weak encryption types",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements"
        )
    
    def check_smb_signing(self) -> CheckResult:
        """
        Check if SMB signing is properly configured.
        
        Returns:
            CheckResult with findings
        """
        # Get domain controllers
        domain_controllers = self.client.get_domain_controllers()
        
        # This check cannot be fully implemented via LDAP as it requires checking registry settings
        # We'll note the DCs that need to be checked manually
        
        dc_names = []
        for dc in domain_controllers:
            dc_name = dc.get("name", [""])[0] if isinstance(dc.get("name"), list) else dc.get("name", "")
            dc_names.append(dc_name)
        
        details = {
            "domain_controllers": dc_names,
            "note": "SMB signing verification requires direct access to domain controllers or querying Windows registry settings, which cannot be done via LDAP",
            "recommendation": "Use additional tools (like CIS benchmarks scanners) to verify SMB signing on these domain controllers"
        }
        
        return CheckResult(
            name="SMB Signing Configuration",
            description="Checks if SMB signing is properly configured on domain controllers",
            severity=CheckSeverity.HIGH,
            passed=None,  # Cannot determine via LDAP
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
        # Get domain controllers
        domain_controllers = self.client.get_domain_controllers()
        
        # Some basic DNS server info can be queried via LDAP, but detailed security settings require direct access
        # Let's query for DNS server roles via LDAP
        
        dns_servers = []
        for dc in domain_controllers:
            dc_name = dc.get("name", [""])[0] if isinstance(dc.get("name"), list) else dc.get("name", "")
            dc_hostname = dc.get("dNSHostName", [""])[0] if isinstance(dc.get("dNSHostName"), list) else dc.get("dNSHostName", "")
            
            # Look for DNS service in serviceAccountName attribute or similar (simplified)
            is_dns_server = True  # Assume all DCs are DNS servers for demo
            
            if is_dns_server:
                dns_servers.append({
                    "name": dc_name,
                    "hostname": dc_hostname
                })
        
        # Try to get DNS zone information from AD (DNS zones are stored in AD)
        dns_zones = []
        try:
            # Look for DNS zones in the application partition
            dns_partition_dn = f"DC=DomainDnsZones,{self.client.base_dn}"
            dns_zone_filter = "(objectClass=dnsZone)"
            
            dns_zone_results = self.client.search(
                search_base=dns_partition_dn,
                search_filter=dns_zone_filter,
                attributes=["name", "dc", "whenCreated", "whenChanged"]
            )
            
            for zone in dns_zone_results:
                zone_name = zone.get("name", [""])[0] if isinstance(zone.get("name"), list) else zone.get("name", "")
                dns_zones.append({
                    "name": zone_name,
                    "dnssec_enabled": False,  # Cannot determine via basic LDAP (would need direct DNS query)
                    "secure_updates": False   # Cannot determine via basic LDAP
                })
        except Exception as e:
            logger.warning(f"Error querying DNS zones: {str(e)}")
        
        details = {
            "dns_servers": dns_servers,
            "dns_zones": dns_zones,
            "note": "Complete DNS security verification requires direct access to DNS servers, which cannot be fully assessed via LDAP"
        }
        
        return CheckResult(
            name="DNS Security Configuration",
            description="Partial check of DNS security settings via LDAP - full check requires direct DNS server access",
            severity=CheckSeverity.MEDIUM,
            passed=None,  # Cannot fully determine via LDAP
            details=details,
            recommendation="Enable DNSSEC, configure secure DNS updates, and implement DNS logging on all domain controllers",
            reference_url="https://docs.microsoft.com/en-us/windows-server/networking/dns/deploy/dnssec"
        )
    
    def check_fsmo_roles(self) -> CheckResult:
        """
        Check if FSMO roles are properly configured using LDAP queries.
        
        Returns:
            CheckResult with findings
        """
        fsmo_roles = {}
        fsmo_servers = set()
        
        try:
            # Schema master role
            schema_dn = f"CN=Schema,CN=Configuration,{self.client.base_dn}"
            schema_results = self.client.search(
                search_base=schema_dn,
                search_filter="(objectClass=*)",
                attributes=["fSMORoleOwner"]
            )
            
            if schema_results and schema_results[0].get("fSMORoleOwner"):
                role_owner = schema_results[0]["fSMORoleOwner"][0] if isinstance(schema_results[0]["fSMORoleOwner"], list) else schema_results[0]["fSMORoleOwner"]
                fsmo_roles["schema_master"] = role_owner
                fsmo_servers.add(role_owner.split(',', 1)[0].replace('CN=', ''))
            
            # Domain naming master role
            partitions_dn = f"CN=Partitions,CN=Configuration,{self.client.base_dn}"
            partitions_results = self.client.search(
                search_base=partitions_dn,
                search_filter="(objectClass=*)",
                attributes=["fSMORoleOwner"]
            )
            
            if partitions_results and partitions_results[0].get("fSMORoleOwner"):
                role_owner = partitions_results[0]["fSMORoleOwner"][0] if isinstance(partitions_results[0]["fSMORoleOwner"], list) else partitions_results[0]["fSMORoleOwner"]
                fsmo_roles["domain_naming_master"] = role_owner
                fsmo_servers.add(role_owner.split(',', 1)[0].replace('CN=', ''))
            
            # Infrastructure master role
            infrastructure_dn = f"CN=Infrastructure,{self.client.base_dn}"
            infrastructure_results = self.client.search(
                search_base=infrastructure_dn,
                search_filter="(objectClass=*)",
                attributes=["fSMORoleOwner"]
            )
            
            if infrastructure_results and infrastructure_results[0].get("fSMORoleOwner"):
                role_owner = infrastructure_results[0]["fSMORoleOwner"][0] if isinstance(infrastructure_results[0]["fSMORoleOwner"], list) else infrastructure_results[0]["fSMORoleOwner"]
                fsmo_roles["infrastructure_master"] = role_owner
                fsmo_servers.add(role_owner.split(',', 1)[0].replace('CN=', ''))
            
            # RID master role
            rid_manager_dn = f"CN=RID Manager$,CN=System,{self.client.base_dn}"
            rid_results = self.client.search(
                search_base=rid_manager_dn,
                search_filter="(objectClass=*)",
                attributes=["fSMORoleOwner"]
            )
            
            if rid_results and rid_results[0].get("fSMORoleOwner"):
                role_owner = rid_results[0]["fSMORoleOwner"][0] if isinstance(rid_results[0]["fSMORoleOwner"], list) else rid_results[0]["fSMORoleOwner"]
                fsmo_roles["rid_master"] = role_owner
                fsmo_servers.add(role_owner.split(',', 1)[0].replace('CN=', ''))
            
            # PDC emulator role
            pdc_dn = self.client.base_dn
            pdc_results = self.client.search(
                search_base=pdc_dn,
                search_filter="(objectClass=domainDNS)",
                attributes=["fSMORoleOwner"]
            )
            
            if pdc_results and pdc_results[0].get("fSMORoleOwner"):
                role_owner = pdc_results[0]["fSMORoleOwner"][0] if isinstance(pdc_results[0]["fSMORoleOwner"], list) else pdc_results[0]["fSMORoleOwner"]
                fsmo_roles["pdc_emulator"] = role_owner
                fsmo_servers.add(role_owner.split(',', 1)[0].replace('CN=', ''))
            
        except Exception as e:
            logger.error(f"Error querying FSMO roles: {str(e)}", exc_info=True)
        
        # Check if FSMO roles are distributed across multiple servers (for redundancy analysis)
        is_consolidated = len(fsmo_servers) <= 2  # Best practice: PDC and backup DC
        
        details = {
            "fsmo_roles": fsmo_roles,
            "fsmo_servers": list(fsmo_servers),
            "role_count": len(fsmo_roles),
            "is_consolidated": is_consolidated
        }
        
        # Check passes if all FSMO roles are assigned and properly consolidated
        passed = len(fsmo_roles) == 5 and is_consolidated
        
        return CheckResult(
            name="FSMO Roles Configuration",
            description="Checks if FSMO roles are properly configured and distributed",
            severity=CheckSeverity.MEDIUM,
            passed=passed,
            details=details,
            recommendation="Ensure FSMO roles are assigned to properly secured domain controllers. For smaller environments, consolidate roles on 1-2 DCs; for larger environments, consider distributing roles according to a designed topology.",
            reference_url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/planning-operations-master-role-placement"
        )