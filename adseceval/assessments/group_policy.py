"""
Assessment module for Group Policy security in Active Directory.
This module analyzes Group Policy Objects (GPOs) for security best practices and misconfigurations.
"""

import logging
import json
from typing import Dict, Any, List, Optional

from .base import AssessmentBase, CheckResult, CheckSeverity

logger = logging.getLogger(__name__)


class GroupPolicyAssessment(AssessmentBase):
    """
    Security assessment for Group Policy configurations in Active Directory.
    Analyzes GPO settings for security risks and compliance with best practices.
    """
    
    name = "Group Policy Security Assessment"
    description = "Evaluates Group Policy Objects (GPOs) for security best practices and identifies misconfigurations"
    
    def _register_checks(self) -> None:
        """Register Group Policy security checks."""
        self.checks = {
            "default_domain_policy": self.check_default_domain_policy,
            "password_policy_gpo": self.check_password_policy_gpo,
            "privileged_access_gpo": self.check_privileged_access_gpo,
            "audit_policy": self.check_audit_policy,
            "user_rights_assignment": self.check_user_rights_assignment,
            "security_options": self.check_security_options,
            "wmi_filtering": self.check_wmi_filtering,
            "empty_gpos": self.check_empty_gpos,
            "gpo_permissions": self.check_gpo_permissions
        }
    
    def _get_all_gpos(self) -> List[Dict[str, Any]]:
        """
        Get all Group Policy Objects in the domain.
        
        Returns:
            List of GPOs with their details
        """
        gpos = self.client.search(
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=["displayName", "gPCFileSysPath", "whenCreated", "whenChanged", "versionNumber", "flags"]
        )
        
        return gpos
    
    def check_default_domain_policy(self) -> CheckResult:
        """
        Check the Default Domain Policy for security best practices.
        
        Returns:
            CheckResult with findings
        """
        # Look for the Default Domain Policy GPO
        gpos = self.client.search(
            search_filter="(&(objectClass=groupPolicyContainer)(displayName=Default Domain Policy))",
            attributes=["displayName", "gPCFileSysPath", "whenCreated", "whenChanged", "versionNumber"]
        )
        
        if not gpos:
            return CheckResult(
                name="Default Domain Policy",
                description="Checks if the Default Domain Policy follows security best practices",
                severity=CheckSeverity.HIGH,
                passed=False,
                details={"error": "Default Domain Policy not found"},
                recommendation="Recreate the Default Domain Policy GPO using the dcgpofix tool.",
                reference_url="https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dcgpofix"
            )
        
        # In a real implementation, this would analyze the settings of the GPO
        # For this example, we'll simulate a result based on common findings
        
        details = {
            "gpo_name": "Default Domain Policy",
            "gpo_path": gpos[0].get("gPCFileSysPath", [""])[0] if isinstance(gpos[0].get("gPCFileSysPath"), list) else gpos[0].get("gPCFileSysPath", ""),
            "last_modified": gpos[0].get("whenChanged", [""])[0] if isinstance(gpos[0].get("whenChanged"), list) else gpos[0].get("whenChanged", ""),
            "issues_found": [
                "Password policy settings should be configured separately",
                "Account lockout policy should be configured separately",
                "Default Domain Policy should be used only for core domain settings"
            ],
            "security_settings": {
                "minimum_password_length": "Too short (should be 14+ characters)",
                "password_complexity": "Enabled (good)",
                "account_lockout_threshold": "Too high (should be 5 or less)"
            },
            "recommendations": [
                "Create dedicated GPOs for password policies",
                "Create dedicated GPOs for account lockout policies",
                "Limit Default Domain Policy to core domain settings only",
                "Follow the principle of least privilege when configuring GPOs"
            ]
        }
        
        # In a real implementation, this would be determined by actual checks
        # For this example, we'll simulate a failed result as it's a common finding
        passed = False
        
        return CheckResult(
            name="Default Domain Policy",
            description="Checks if the Default Domain Policy follows security best practices",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Create dedicated GPOs for specific policy areas rather than overloading the Default Domain Policy.",
            reference_url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-secure-administrative-hosts"
        )
    
    def check_password_policy_gpo(self) -> CheckResult:
        """
        Check for dedicated password policy GPOs and their settings.
        
        Returns:
            CheckResult with findings
        """
        # Look for password policy GPOs
        # In a real implementation, this would analyze the GPO settings
        # For this example, we'll simulate a result
        
        details = {
            "dedicated_password_policy_gpo_found": False,
            "password_policy_location": "Default Domain Policy (not recommended)",
            "policy_settings": {
                "minimum_password_length": "Insufficient (found: 8, recommended: 14+)",
                "password_complexity": "Enabled (good)",
                "password_history": "Insufficient (found: 10, recommended: 24)",
                "maximum_password_age": "Too long (found: 90 days, recommended: 60 days or less)"
            },
            "recommendations": [
                "Create a dedicated Password Policy GPO",
                "Configure minimum password length of 14+ characters",
                "Enable password complexity requirements",
                "Set password history to 24 or more previous passwords",
                "Set maximum password age to 60 days or less",
                "Consider implementing fine-grained password policies for specific groups"
            ]
        }
        
        # In a real implementation, this would be determined by actual checks
        # For this example, we'll simulate a failed result
        passed = False
        
        return CheckResult(
            name="Password Policy GPO",
            description="Checks for dedicated password policy GPOs and their security settings",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Create a dedicated Password Policy GPO with strong password requirements and separate it from the Default Domain Policy.",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy"
        )
    
    def check_privileged_access_gpo(self) -> CheckResult:
        """
        Check for privileged access management GPOs.
        
        Returns:
            CheckResult with findings
        """
        # Look for privileged access management GPOs
        # In a real implementation, this would analyze the GPO settings
        # For this example, we'll simulate a result
        
        details = {
            "privileged_access_gpos_found": [
                "Tier 0 - Domain Controllers",
                "Tier 1 - Server Admins"
            ],
            "missing_privileged_access_gpos": [
                "Protected Users Configuration",
                "Just-In-Time Administration",
                "Privileged Access Workstation (PAW) Configuration"
            ],
            "tier_model_implemented": "Partial",
            "security_issues": [
                "Local admin password management not implemented via GPO",
                "Protected Users group not enforced via GPO",
                "No restrictions on Remote Desktop access to sensitive systems"
            ],
            "recommendations": [
                "Implement comprehensive tiered administration model with dedicated GPOs",
                "Create GPO to enforce Protected Users group membership for admins",
                "Configure 'Deny log on through Remote Desktop Services' for privileged accounts on regular systems",
                "Implement Just-In-Time Administration through dedicated GPO",
                "Create PAW configuration GPO for secure admin workstations"
            ]
        }
        
        # In a real implementation, this would be determined by actual checks
        # For this example, we'll simulate a partial implementation
        passed = False
        
        return CheckResult(
            name="Privileged Access Management GPOs",
            description="Checks for GPOs related to privileged access management",
            severity=CheckSeverity.CRITICAL,
            passed=passed,
            details=details,
            recommendation="Implement comprehensive privileged access management GPOs that enforce the tiered administration model.",
            reference_url="https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material"
        )
    
    def check_audit_policy(self) -> CheckResult:
        """
        Check audit policy GPO settings.
        
        Returns:
            CheckResult with findings
        """
        # Look for audit policy GPOs
        # In a real implementation, this would analyze the GPO settings
        # For this example, we'll simulate a result
        
        details = {
            "advanced_audit_policy_configured": True,
            "audit_policies": {
                "account_logon": {
                    "credential_validation": "Success and Failure (good)",
                    "kerberos_authentication": "Success and Failure (good)",
                    "kerberos_service_ticket_operations": "Not configured (should be Success and Failure)"
                },
                "account_management": {
                    "user_account_management": "Success and Failure (good)",
                    "security_group_management": "Success and Failure (good)",
                    "distribution_group_management": "Not configured (not critical)"
                },
                "ds_access": {
                    "directory_service_changes": "Success (should include Failure)",
                    "directory_service_access": "Not configured (should be Success and Failure)"
                },
                "logon_logoff": {
                    "logon": "Success and Failure (good)",
                    "logoff": "Success (good)",
                    "special_logon": "Success (good)"
                },
                "object_access": {
                    "file_system": "Not configured (should be Success and Failure for sensitive files)",
                    "registry": "Not configured (not critical)"
                },
                "policy_change": {
                    "audit_policy_change": "Success and Failure (good)",
                    "authentication_policy_change": "Success (should include Failure)"
                },
                "privilege_use": {
                    "sensitive_privilege_use": "Not configured (should be Success and Failure)"
                },
                "system": {
                    "security_state_change": "Success (good)",
                    "security_system_extension": "Success (good)",
                    "system_integrity": "Success and Failure (good)"
                }
            },
            "recommendations": [
                "Configure all critical audit policies to log Success and Failure events",
                "Ensure Directory Service Access and Changes are audited",
                "Configure auditing for Sensitive Privilege Use",
                "Audit Kerberos Service Ticket Operations",
                "Ensure log retention and log monitoring processes are in place"
            ]
        }
        
        # Check if critical audit policies are configured correctly
        critical_audit_policies = [
            details["audit_policies"]["account_logon"]["credential_validation"],
            details["audit_policies"]["account_management"]["security_group_management"],
            details["audit_policies"]["logon_logoff"]["logon"],
            details["audit_policies"]["policy_change"]["audit_policy_change"],
            details["audit_policies"]["system"]["security_system_extension"],
            details["audit_policies"]["system"]["system_integrity"]
        ]
        
        # Count correctly configured critical policies
        correct_policies = sum(1 for policy in critical_audit_policies if policy == "Success and Failure (good)")
        
        # Determine if check passes (at least 80% of critical policies correctly configured)
        passed = (correct_policies / len(critical_audit_policies)) >= 0.8
        
        return CheckResult(
            name="Audit Policy Configuration",
            description="Checks if audit policies are properly configured in GPOs",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Configure advanced audit policies to log both success and failure events for critical security actions.",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings"
        )
    
    def check_user_rights_assignment(self) -> CheckResult:
        """
        Check user rights assignment GPO settings.
        
        Returns:
            CheckResult with findings
        """
        # Look for user rights assignment GPOs
        # In a real implementation, this would analyze the GPO settings
        # For this example, we'll simulate a result
        
        details = {
            "problematic_assignments": [
                {
                    "right": "SeDebugPrivilege (Debug programs)",
                    "assigned_to": ["Domain Admins", "Enterprise Admins", "Regular User Group"],
                    "issue": "Should only be assigned to specific administrative accounts for troubleshooting"
                },
                {
                    "right": "SeBackupPrivilege (Back up files and directories)",
                    "assigned_to": ["Backup Operators", "Domain Admins", "Regular Admin Group"],
                    "issue": "Should only be assigned to dedicated backup accounts"
                },
                {
                    "right": "SeTakeOwnershipPrivilege (Take ownership of files or other objects)",
                    "assigned_to": ["Domain Admins", "Enterprise Admins", "Power Users"],
                    "issue": "Power Users should not have this privilege"
                },
                {
                    "right": "SeRemoteInteractiveLogonRight (Allow log on through Remote Desktop Services)",
                    "assigned_to": ["Remote Desktop Users", "Domain Admins", "All IT Staff"],
                    "issue": "Too broadly assigned, should be limited to specific roles"
                }
            ],
            "secure_assignments": [
                {
                    "right": "SeNetworkLogonRight (Access this computer from the network)",
                    "assigned_to": ["Authenticated Users"],
                    "note": "Appropriately configured"
                },
                {
                    "right": "SeInteractiveLogonRight (Allow log on locally)",
                    "assigned_to": ["Administrators", "Users"],
                    "note": "Appropriately configured"
                }
            ],
            "recommendations": [
                "Limit privileged user rights to the minimum necessary accounts",
                "Remove 'Debug programs' privilege from regular user groups",
                "Restrict 'Take ownership' privilege to only Domain and Enterprise Admins",
                "Limit 'Allow log on through Remote Desktop Services' to specific administrative roles",
                "Deny logon rights for privileged accounts on lower-tier systems"
            ]
        }
        
        # Determine if check passes
        # In a real implementation, this would be based on actual findings
        # For this example, simulate a failing check due to problematic assignments
        passed = len(details["problematic_assignments"]) == 0
        
        return CheckResult(
            name="User Rights Assignment",
            description="Checks if user rights are assigned according to the principle of least privilege",
            severity=CheckSeverity.CRITICAL,
            passed=passed,
            details=details,
            recommendation="Restrict privileged rights to the minimum necessary accounts and implement separation of duties.",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment"
        )
    
    def check_security_options(self) -> CheckResult:
        """
        Check security options in GPOs.
        
        Returns:
            CheckResult with findings
        """
        # Look for security options in GPOs
        # In a real implementation, this would analyze the GPO settings
        # For this example, we'll simulate a result
        
        details = {
            "security_options": {
                "network_security": {
                    "lan_manager_authentication_level": "Send NTLMv2 response only (should be 'Send NTLMv2 response only. Refuse LM & NTLM')",
                    "minimum_session_security": "Require 128-bit encryption (good)",
                    "restrict_ntlm": "Not configured (should restrict NTLM)"
                },
                "domain_member": {
                    "digitally_encrypt_secure_channel_data": "Enabled (good)",
                    "digitally_sign_secure_channel_data": "Enabled (good)",
                    "require_strong_session_key": "Enabled (good)"
                },
                "interactive_logon": {
                    "dont_display_last_username": "Not configured (should be enabled)",
                    "smart_card_removal_behavior": "Lock Workstation (good)",
                    "message_text_for_users": "Configured (good)"
                },
                "microsoft_network_server": {
                    "digitally_sign_communications": "Enabled (good)",
                    "server_smbv1": "Enabled (should be disabled)"
                },
                "microsoft_network_client": {
                    "digitally_sign_communications": "Enabled (good)",
                    "send_unencrypted_password_to_third_party_smb_servers": "Disabled (good)"
                },
                "user_account_control": {
                    "behavior_of_the_elevation_prompt_for_administrators": "Prompt for consent (good)",
                    "run_all_administrators_in_admin_approval_mode": "Enabled (good)"
                }
            },
            "recommendations": [
                "Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'",
                "Configure 'Restrict NTLM' settings",
                "Enable 'Don't display last signed-in' option",
                "Disable SMBv1 protocol",
                "Enable UAC and configure appropriate elevation prompts"
            ]
        }
        
        # Count security issues
        issues_count = 0
        
        # Network security issues
        if details["security_options"]["network_security"]["lan_manager_authentication_level"] != "Send NTLMv2 response only. Refuse LM & NTLM":
            issues_count += 1
        if details["security_options"]["network_security"]["restrict_ntlm"] == "Not configured (should restrict NTLM)":
            issues_count += 1
            
        # Interactive logon issues
        if details["security_options"]["interactive_logon"]["dont_display_last_username"] == "Not configured (should be enabled)":
            issues_count += 1
            
        # SMB issues
        if details["security_options"]["microsoft_network_server"]["server_smbv1"] == "Enabled (should be disabled)":
            issues_count += 1
        
        # Determine if check passes
        # For this example, we'll require no critical issues to pass
        passed = issues_count == 0
        
        return CheckResult(
            name="Security Options Configuration",
            description="Checks if security options in GPOs follow security best practices",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Configure security options according to security best practices, focusing on authentication, encryption, and protocol security.",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-options"
        )
    
    def check_wmi_filtering(self) -> CheckResult:
        """
        Check if WMI filtering is used effectively for GPO targeting.
        
        Returns:
            CheckResult with findings
        """
        # In a real implementation, this would check for WMI filters linked to GPOs
        # For this example, we'll simulate a result
        
        details = {
            "total_gpos": 15,  # Example count
            "gpos_with_wmi_filters": 2,
            "gpos_that_should_use_filters": [
                "Workstation Security Settings",
                "Server Security Settings",
                "Operating System-Specific Settings"
            ],
            "effective_wmi_filters": [
                {
                    "name": "Windows 10 Only",
                    "linked_gpos": ["Windows 10 Settings"],
                    "query": "SELECT * FROM Win32_OperatingSystem WHERE Version LIKE '10.%'"
                },
                {
                    "name": "Servers Only",
                    "linked_gpos": ["Server Hardening"],
                    "query": "SELECT * FROM Win32_OperatingSystem WHERE ProductType = 3"
                }
            ],
            "recommendations": [
                "Use WMI filters to target specific operating systems or system types",
                "Keep WMI queries simple and efficient to avoid performance impacts",
                "Document WMI filters and their purposes",
                "Test WMI filters thoroughly before deployment",
                "Consider using security groups for targeting when possible"
            ]
        }
        
        # Determine if check passes
        # For this example, we'll use a simple criterion - at least some WMI filters should be used
        passed = details["gpos_with_wmi_filters"] > 0
        
        return CheckResult(
            name="WMI Filtering Usage",
            description="Checks if WMI filtering is effectively used for GPO targeting",
            severity=CheckSeverity.MEDIUM,
            passed=passed,
            details=details,
            recommendation="Use WMI filters to apply GPOs only to systems that need them, improving security and reducing GPO processing overhead.",
            reference_url="https://docs.microsoft.com/en-us/troubleshoot/windows-server/group-policy/use-wmi-filters"
        )
    
    def check_empty_gpos(self) -> CheckResult:
        """
        Check for empty or unused GPOs.
        
        Returns:
            CheckResult with findings
        """
        # In a real implementation, this would check GPO settings and links
        # For this example, we'll simulate a result
        
        details = {
            "total_gpos": 22,  # Example count
            "empty_gpos": [
                {
                    "name": "Test Policy",
                    "created": "2022-05-15",
                    "modified": "2022-05-15",
                    "linked": False
                },
                {
                    "name": "Old Security Settings",
                    "created": "2021-11-03",
                    "modified": "2022-01-24",
                    "linked": False
                },
                {
                    "name": "Temporary Policy",
                    "created": "2023-02-10",
                    "modified": "2023-02-10",
                    "linked": False
                }
            ],
            "linked_but_empty_gpos": [
                {
                    "name": "Department Policy",
                    "created": "2022-07-20",
                    "modified": "2022-07-20",
                    "links": ["OU=Marketing,DC=contoso,DC=com"]
                }
            ],
            "recommendations": [
                "Remove or document empty GPOs",
                "Remove links to empty GPOs",
                "Create a naming convention that identifies test or temporary GPOs",
                "Implement a regular GPO cleanup process",
                "Document the purpose of all GPOs"
            ]
        }
        
        # Determine if check passes
        # Allow a small number of empty GPOs (e.g., 1-2) for testing purposes
        passed = len(details["empty_gpos"]) <= 2 and len(details["linked_but_empty_gpos"]) == 0
        
        return CheckResult(
            name="Empty GPOs",
            description="Checks for empty or unused GPOs that should be removed",
            severity=CheckSeverity.LOW,
            passed=passed,
            details=details,
            recommendation="Remove empty GPOs and unlink GPOs that have no settings to maintain a clean and manageable Group Policy environment.",
            reference_url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/group-policy--management-enhancements"
        )
    
    def check_gpo_permissions(self) -> CheckResult:
        """
        Check GPO permissions for security best practices.
        
        Returns:
            CheckResult with findings
        """
        # In a real implementation, this would check permissions on GPOs
        # For this example, we'll simulate a result
        
        details = {
            "total_gpos": 22,  # Example count
            "gpos_with_permission_issues": [
                {
                    "name": "Finance Department Policy",
                    "issues": [
                        "Authenticated Users have Edit permissions",
                        "Missing 'Apply Group Policy' permission for target groups"
                    ]
                },
                {
                    "name": "Default Domain Controllers Policy",
                    "issues": [
                        "IT Support group has Edit permissions",
                        "Too many groups with Edit permissions"
                    ]
                },
                {
                    "name": "Password Policy",
                    "issues": [
                        "Help Desk group has Edit permissions",
                        "Delegation not following least privilege"
                    ]
                }
            ],
            "best_practices": [
                "Only Domain Admins and Enterprise Admins should have Edit permissions on critical GPOs",
                "Use security groups for delegation rather than individual accounts",
                "Tier 0 GPOs should have the strictest permissions",
                "GPO delegation should follow the same tiering model as administrative access"
            ],
            "recommendations": [
                "Review and restrict Edit permissions on all GPOs",
                "Ensure Authenticated Users have only 'Apply Group Policy' permissions",
                "Follow least privilege principles when delegating GPO management",
                "Implement formal change control for critical GPOs",
                "Audit GPO permission changes"
            ]
        }
        
        # Determine if check passes
        passed = len(details["gpos_with_permission_issues"]) == 0
        
        return CheckResult(
            name="GPO Permissions",
            description="Checks if GPO permissions follow security best practices",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Restrict GPO permissions following the principle of least privilege and ensure proper delegation of GPO management.",
            reference_url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack#secure-domain-controller-policy-settings",
            compliance_mappings={
                "NIST SP 800-53": ["AC-2", "AC-3", "AC-6"],
                "CIS": ["5.1", "5.2"],
                "ISO 27001": ["A.9.2.3", "A.9.4.1"]
            }
        )