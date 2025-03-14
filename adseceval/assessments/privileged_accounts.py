"""
Assessment module for privileged account security in Active Directory.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from .base import AssessmentBase, CheckResult, CheckSeverity

logger = logging.getLogger(__name__)


class PrivilegedAccountsAssessment(AssessmentBase):
    """Security assessment for privileged accounts in Active Directory."""
    
    name = "Privileged Accounts Security Assessment"
    description = "Evaluates the security configuration of privileged accounts in Active Directory"
    
    def _register_checks(self) -> None:
        """Register privileged account security checks."""
        self.checks = {
            "admin_count": self.check_admin_count,
            "dormant_admins": self.check_dormant_admin_accounts,
            "service_account_privileges": self.check_service_account_privileges,
            "nested_groups": self.check_nested_privileged_groups,
            "protected_users": self.check_protected_users_group,
            "admin_mfa": self.check_admin_mfa,
        }
    
    def check_admin_count(self) -> CheckResult:
        """
        Check if the number of domain admin accounts is appropriate.
        
        Returns:
            CheckResult with findings
        """
        # Get privileged groups
        privileged_groups = self.client.get_privileged_groups()
        
        admin_details = {}
        all_admins = set()
        
        # Get the membership of key admin groups
        for group in privileged_groups:
            group_name = group.get("sAMAccountName", [""])[0] if isinstance(group.get("sAMAccountName"), list) else group.get("sAMAccountName", "")
            
            if group_name in ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]:
                # Get group members
                group_dn = group.get("distinguishedName", [""])[0] if isinstance(group.get("distinguishedName"), list) else group.get("distinguishedName", "")
                members = self.client.get_group_members(group_dn)
                
                # Filter out nested groups, only count user accounts
                user_members = [m for m in members if "user" in str(m.get("objectClass", [])).lower()]
                
                admin_details[group_name] = {
                    "count": len(user_members),
                    "members": [
                        {
                            "sAMAccountName": m.get("sAMAccountName", [""])[0] if isinstance(m.get("sAMAccountName"), list) else m.get("sAMAccountName", ""),
                            "distinguishedName": m.get("distinguishedName", [""])[0] if isinstance(m.get("distinguishedName"), list) else m.get("distinguishedName", ""),
                        }
                        for m in user_members
                    ]
                }
                
                # Add to set of all admins
                for member in user_members:
                    all_admins.add(member.get("sAMAccountName", [""])[0] if isinstance(member.get("sAMAccountName"), list) else member.get("sAMAccountName", ""))
        
        # Count unique admin accounts
        admin_details["total_unique_admins"] = len(all_admins)
        admin_details["unique_admins"] = list(all_admins)
        
        # Check if the number of admins is within recommended range (2-4)
        passed = 2 <= admin_details.get("total_unique_admins", 0) <= 4
        
        return CheckResult(
            name="Domain Admin Count",
            description="Checks if the number of domain administrator accounts is within recommended limits",
            severity=CheckSeverity.CRITICAL,
            passed=passed,
            details=admin_details,
            recommendation="Limit the number of Domain Administrators to 2-4 carefully managed accounts",
            reference_url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory"
        )
    
    def check_dormant_admin_accounts(self) -> CheckResult:
        """
        Check for dormant administrator accounts.
        
        Returns:
            CheckResult with findings
        """
        # Get privileged groups
        privileged_groups = self.client.get_privileged_groups()
        
        # Threshold for dormant accounts (60 days)
        dormant_threshold_days = 60
        threshold_date = datetime.now() - timedelta(days=dormant_threshold_days)
        
        all_admin_accounts = set()
        dormant_admins = []
        active_admins = []
        
        # Check each privileged group
        for group in privileged_groups:
            group_name = group.get("sAMAccountName", [""])[0] if isinstance(group.get("sAMAccountName"), list) else group.get("sAMAccountName", "")
            
            if group_name in ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]:
                # Get group members
                group_dn = group.get("distinguishedName", [""])[0] if isinstance(group.get("distinguishedName"), list) else group.get("distinguishedName", "")
                members = self.client.get_group_members(group_dn)
                
                # Filter out nested groups, only check user accounts
                user_members = [m for m in members if "user" in str(m.get("objectClass", [])).lower()]
                
                for member in user_members:
                    account_name = member.get("sAMAccountName", [""])[0] if isinstance(member.get("sAMAccountName"), list) else member.get("sAMAccountName", "")
                    
                    # Skip if already processed
                    if account_name in all_admin_accounts:
                        continue
                    
                    all_admin_accounts.add(account_name)
                    
                    # Check if account is dormant
                    last_logon = None
                    if "lastLogonTimestamp" in member:
                        last_logon = member["lastLogonTimestamp"]
                        if isinstance(last_logon, list) and last_logon:
                            last_logon = last_logon[0]
                    
                    account_enabled = True
                    if "userAccountControl" in member:
                        uac = member["userAccountControl"]
                        if isinstance(uac, list) and uac:
                            uac = uac[0]
                        account_enabled = not (int(uac) & 2)  # Check if the account is disabled
                    
                    # Determine if dormant
                    is_dormant = False
                    if not account_enabled:
                        is_dormant = True
                    elif last_logon is None:
                        is_dormant = True
                    elif isinstance(last_logon, datetime) and last_logon < threshold_date:
                        is_dormant = True
                    
                    account_details = {
                        "sAMAccountName": account_name,
                        "distinguishedName": member.get("distinguishedName", [""])[0] if isinstance(member.get("distinguishedName"), list) else member.get("distinguishedName", ""),
                        "lastLogon": last_logon,
                        "enabled": account_enabled,
                        "memberOf": group_name
                    }
                    
                    if is_dormant:
                        dormant_admins.append(account_details)
                    else:
                        active_admins.append(account_details)
        
        # Prepare result details
        details = {
            "total_admin_accounts": len(all_admin_accounts),
            "dormant_accounts": len(dormant_admins),
            "active_accounts": len(active_admins),
            "dormant_threshold_days": dormant_threshold_days,
            "dormant_admins": dormant_admins
        }
        
        # Check passes if there are no dormant admin accounts
        passed = len(dormant_admins) == 0
        
        return CheckResult(
            name="Dormant Admin Accounts",
            description="Checks for dormant administrator accounts that may pose a security risk",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Disable or remove dormant administrator accounts that haven't been used within the last 60 days",
            reference_url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise"
        )
    
    def check_service_account_privileges(self) -> CheckResult:
        """
        Check if service accounts have excessive privileges.
        
        Returns:
            CheckResult with findings
        """
        # Get privileged groups
        privileged_groups = self.client.get_privileged_groups()
        
        # Service account patterns
        service_account_patterns = ["svc", "service", "srv", "_sa"]
        
        privileged_service_accounts = []
        
        # Check each privileged group for service accounts
        for group in privileged_groups:
            group_name = group.get("sAMAccountName", [""])[0] if isinstance(group.get("sAMAccountName"), list) else group.get("sAMAccountName", "")
            
            if group_name in ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", 
                             "Backup Operators", "Server Operators", "Account Operators"]:
                # Get group members
                group_dn = group.get("distinguishedName", [""])[0] if isinstance(group.get("distinguishedName"), list) else group.get("distinguishedName", "")
                members = self.client.get_group_members(group_dn)
                
                # Filter out nested groups, only check user accounts
                user_members = [m for m in members if "user" in str(m.get("objectClass", [])).lower()]
                
                # Check if each member is a service account
                for member in user_members:
                    account_name = member.get("sAMAccountName", [""])[0] if isinstance(member.get("sAMAccountName"), list) else member.get("sAMAccountName", "")
                    
                    # Check if the account name matches service account patterns
                    is_service_account = False
                    for pattern in service_account_patterns:
                        if pattern.lower() in account_name.lower():
                            is_service_account = True
                            break
                    
                    if is_service_account:
                        privileged_service_accounts.append({
                            "sAMAccountName": account_name,
                            "distinguishedName": member.get("distinguishedName", [""])[0] if isinstance(member.get("distinguishedName"), list) else member.get("distinguishedName", ""),
                            "memberOf": group_name,
                            "groupDN": group_dn
                        })
        
        # Prepare result details
        details = {
            "privileged_service_accounts": len(privileged_service_accounts),
            "account_details": privileged_service_accounts
        }
        
        # Check passes if no service accounts have privileged group memberships
        passed = len(privileged_service_accounts) == 0
        
        return CheckResult(
            name="Service Account Privileges",
            description="Checks if service accounts have excessive privileges",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Remove service accounts from privileged groups and implement managed service accounts or group managed service accounts",
            reference_url="https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview"
        )
    
    def check_nested_privileged_groups(self) -> CheckResult:
        """
        Check for nested group memberships in privileged groups.
        
        Returns:
            CheckResult with findings
        """
        # Get privileged groups
        privileged_groups = self.client.get_privileged_groups()
        
        nested_groups = {}
        
        # Check each privileged group for nested groups
        for group in privileged_groups:
            group_name = group.get("sAMAccountName", [""])[0] if isinstance(group.get("sAMAccountName"), list) else group.get("sAMAccountName", "")
            
            if group_name in ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", 
                             "Backup Operators", "Server Operators", "Account Operators"]:
                # Get group members
                group_dn = group.get("distinguishedName", [""])[0] if isinstance(group.get("distinguishedName"), list) else group.get("distinguishedName", "")
                members = self.client.get_group_members(group_dn)
                
                # Filter for nested groups
                nested = [
                    {
                        "sAMAccountName": m.get("sAMAccountName", [""])[0] if isinstance(m.get("sAMAccountName"), list) else m.get("sAMAccountName", ""),
                        "distinguishedName": m.get("distinguishedName", [""])[0] if isinstance(m.get("distinguishedName"), list) else m.get("distinguishedName", "")
                    }
                    for m in members if "group" in str(m.get("objectClass", [])).lower()
                ]
                
                if nested:
                    nested_groups[group_name] = nested
        
        total_nested = sum(len(groups) for groups in nested_groups.values())
        
        # Prepare result details
        details = {
            "total_nested_groups": total_nested,
            "nested_groups_by_privileged_group": nested_groups
        }
        
        # Check passes if there are no nested groups in privileged groups
        passed = total_nested == 0
        
        return CheckResult(
            name="Nested Privileged Groups",
            description="Checks for nested group memberships in privileged groups which can obscure privilege paths",
            severity=CheckSeverity.MEDIUM,
            passed=passed,
            details=details,
            recommendation="Remove nested groups from privileged groups to maintain clear privilege paths and reduce attack surface",
            reference_url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"
        )
    
    def check_protected_users_group(self) -> CheckResult:
        """
        Check if privileged accounts are in the Protected Users group.
        
        Returns:
            CheckResult with findings
        """
        # Get privileged groups
        privileged_groups = self.client.get_privileged_groups()
        
        # Get the Protected Users group
        protected_users_search = self.client.search(
            search_filter="(sAMAccountName=Protected Users)",
            attributes=["distinguishedName", "member"]
        )
        
        if not protected_users_search:
            return CheckResult(
                name="Protected Users Group",
                description="Checks if privileged accounts are members of the Protected Users group",
                severity=CheckSeverity.HIGH,
                passed=False,
                details={"error": "Protected Users group not found"},
                recommendation="Create and configure the Protected Users group for privileged accounts",
                reference_url="https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"
            )
        
        protected_users = protected_users_search[0]
        protected_users_dn = protected_users.get("distinguishedName", [""])[0] if isinstance(protected_users.get("distinguishedName"), list) else protected_users.get("distinguishedName", "")
        protected_users_members = protected_users.get("member", [])
        
        # Get all admin accounts
        admin_accounts = set()
        
        for group in privileged_groups:
            group_name = group.get("sAMAccountName", [""])[0] if isinstance(group.get("sAMAccountName"), list) else group.get("sAMAccountName", "")
            
            if group_name in ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]:
                # Get group members
                group_dn = group.get("distinguishedName", [""])[0] if isinstance(group.get("distinguishedName"), list) else group.get("distinguishedName", "")
                members = self.client.get_group_members(group_dn)
                
                # Filter out nested groups, only check user accounts
                user_members = [m for m in members if "user" in str(m.get("objectClass", [])).lower()]
                
                for member in user_members:
                    admin_accounts.add(member.get("distinguishedName", [""])[0] if isinstance(member.get("distinguishedName"), list) else member.get("distinguishedName", ""))
        
        # Check which admin accounts are in Protected Users
        protected_admins = []
        unprotected_admins = []
        
        for admin_dn in admin_accounts:
            if admin_dn in protected_users_members:
                protected_admins.append(admin_dn)
            else:
                # Get account details
                admin_details = self.client.search(
                    search_filter=f"(distinguishedName={admin_dn})",
                    attributes=["sAMAccountName"]
                )
                
                if admin_details:
                    account_name = admin_details[0].get("sAMAccountName", [""])[0] if isinstance(admin_details[0].get("sAMAccountName"), list) else admin_details[0].get("sAMAccountName", "")
                    unprotected_admins.append({
                        "sAMAccountName": account_name,
                        "distinguishedName": admin_dn
                    })
        
        # Prepare result details
        details = {
            "total_admin_accounts": len(admin_accounts),
            "protected_admin_accounts": len(protected_admins),
            "unprotected_admin_accounts": len(unprotected_admins),
            "unprotected_admins": unprotected_admins
        }
        
        # Check passes if all admin accounts are in Protected Users
        passed = len(unprotected_admins) == 0
        
        return CheckResult(
            name="Protected Users Group Membership",
            description="Checks if privileged accounts are members of the Protected Users group",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Add all privileged accounts to the Protected Users group to provide additional security protections",
            reference_url="https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"
        )
    
    def check_admin_mfa(self) -> CheckResult:
        """
        Check if MFA is enabled for admin accounts.
        This is a simplified check since MFA info may not be directly accessible via LDAP.
        
        Returns:
            CheckResult with findings
        """
        # In a real implementation, we would check MFA status through a more specific API
        # This is a placeholder that checks for userAccountControl settings that might indicate MFA
        
        # Get privileged groups
        privileged_groups = self.client.get_privileged_groups()
        
        admin_accounts = set()
        
        for group in privileged_groups:
            group_name = group.get("sAMAccountName", [""])[0] if isinstance(group.get("sAMAccountName"), list) else group.get("sAMAccountName", "")
            
            if group_name in ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]:
                # Get group members
                group_dn = group.get("distinguishedName", [""])[0] if isinstance(group.get("distinguishedName"), list) else group.get("distinguishedName", "")
                members = self.client.get_group_members(group_dn)
                
                # Filter out nested groups, only check user accounts
                user_members = [m for m in members if "user" in str(m.get("objectClass", [])).lower()]
                
                for member in user_members:
                    admin_accounts.add(member.get("distinguishedName", [""])[0] if isinstance(member.get("distinguishedName"), list) else member.get("distinguishedName", ""))
        
        # Check smart card required flag as a proxy for MFA
        # Note: This is not a perfect check for MFA, but it's one indicator
        admins_with_mfa = []
        admins_without_mfa = []
        
        for admin_dn in admin_accounts:
            admin_details = self.client.search(
                search_filter=f"(distinguishedName={admin_dn})",
                attributes=["sAMAccountName", "userAccountControl"]
            )
            
            if admin_details:
                account_name = admin_details[0].get("sAMAccountName", [""])[0] if isinstance(admin_details[0].get("sAMAccountName"), list) else admin_details[0].get("sAMAccountName", "")
                uac = admin_details[0].get("userAccountControl", [0])[0] if isinstance(admin_details[0].get("userAccountControl"), list) else admin_details[0].get("userAccountControl", 0)
                
                # Check if smart card is required (UAC flag 0x40000)
                smart_card_required = bool(int(uac) & 0x40000)
                
                admin_info = {
                    "sAMAccountName": account_name,
                    "distinguishedName": admin_dn,
                    "smartCardRequired": smart_card_required
                }
                
                if smart_card_required:
                    admins_with_mfa.append(admin_info)
                else:
                    admins_without_mfa.append(admin_info)
        
        # Prepare result details
        details = {
            "total_admin_accounts": len(admin_accounts),
            "admins_with_smart_card": len(admins_with_mfa),
            "admins_without_smart_card": len(admins_without_mfa),
            "note": "This check uses smart card requirement as a proxy for MFA. Complete MFA status may require checking additional systems.",
            "admins_without_mfa": admins_without_mfa
        }
        
        # Check passes if all admin accounts require smart cards
        passed = len(admins_without_mfa) == 0
        
        return CheckResult(
            name="Admin MFA Enforcement",
            description="Checks if multi-factor authentication is enforced for administrative accounts",
            severity=CheckSeverity.CRITICAL,
            passed=passed,
            details=details,
            recommendation="Configure all administrative accounts to require multi-factor authentication",
            reference_url="https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-getstarted"
        )