"""
Assessment module for tiered administration model in Active Directory.
"""

import logging
import re
from typing import Dict, Any, List, Optional, Set

from .base import AssessmentBase, CheckResult, CheckSeverity

logger = logging.getLogger(__name__)


class TieredAdminAssessment(AssessmentBase):
    """Security assessment for tiered administration model in Active Directory."""
    
    name = "Tiered Administration Model Assessment"
    description = "Evaluates the implementation of a tiered administration model in Active Directory"
    
    def _register_checks(self) -> None:
        """Register tiered administration security checks."""
        self.checks = {
            "admin_tier_separation": self.check_admin_tier_separation,
            "paw_implementation": self.check_paw_implementation,
            "tier0_security": self.check_tier0_security,
            "lateral_movement": self.check_lateral_movement_paths,
            "jit_admin": self.check_jit_admin,
        }
    
    def check_admin_tier_separation(self) -> CheckResult:
        """
        Check if administrative tiers are properly separated.
        
        Returns:
            CheckResult with findings
        """
        # Get all security groups that might be related to tiered administration
        tier_patterns = {
            "tier0": [r"tier.?0", r"t0", r"-t0-", r"-0-", r"admin.*tier.*0"],
            "tier1": [r"tier.?1", r"t1", r"-t1-", r"-1-", r"admin.*tier.*1"],
            "tier2": [r"tier.?2", r"t2", r"-t2-", r"-2-", r"admin.*tier.*2"]
        }
        
        all_groups = self.client.search(
            search_filter="(&(objectClass=group)(objectCategory=group))",
            attributes=["name", "sAMAccountName", "description", "member", "memberOf"]
        )
        
        # Categorize groups by tier
        tier_groups = {
            "tier0": [],
            "tier1": [],
            "tier2": []
        }
        
        for group in all_groups:
            group_name = group.get("sAMAccountName", [""])[0] if isinstance(group.get("sAMAccountName"), list) else group.get("sAMAccountName", "")
            for tier, patterns in tier_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, group_name, re.IGNORECASE):
                        tier_groups[tier].append({
                            "name": group_name,
                            "members": len(group.get("member", [])),
                            "distinguishedName": group.get("distinguishedName", [""])[0] if isinstance(group.get("distinguishedName"), list) else group.get("distinguishedName", "")
                        })
                        break
        
        # Also consider well-known administrative groups as Tier 0
        well_known_tier0 = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]
        for group in all_groups:
            group_name = group.get("sAMAccountName", [""])[0] if isinstance(group.get("sAMAccountName"), list) else group.get("sAMAccountName", "")
            if group_name in well_known_tier0 and not any(g["name"] == group_name for g in tier_groups["tier0"]):
                tier_groups["tier0"].append({
                    "name": group_name,
                    "members": len(group.get("member", [])),
                    "distinguishedName": group.get("distinguishedName", [""])[0] if isinstance(group.get("distinguishedName"), list) else group.get("distinguishedName", ""),
                    "note": "Well-known administrative group"
                })
        
        # Check for tier violations (accounts in multiple tiers)
        tier_violations = []
        
        # Get members of each tier
        tier_members = {
            "tier0": set(),
            "tier1": set(),
            "tier2": set()
        }
        
        for tier, groups in tier_groups.items():
            for group in groups:
                group_dn = group["distinguishedName"]
                members = self.client.get_group_members(group_dn)
                for member in members:
                    member_dn = member.get("distinguishedName", [""])[0] if isinstance(member.get("distinguishedName"), list) else member.get("distinguishedName", "")
                    tier_members[tier].add(member_dn)
        
        # Check for accounts in multiple tiers
        t0_and_t1 = tier_members["tier0"].intersection(tier_members["tier1"])
        t0_and_t2 = tier_members["tier0"].intersection(tier_members["tier2"])
        t1_and_t2 = tier_members["tier1"].intersection(tier_members["tier2"])
        
        for member_dn in t0_and_t1:
            # Get account details
            account = self.client.search(
                search_filter=f"(distinguishedName={member_dn})",
                attributes=["sAMAccountName", "objectClass"]
            )
            if account:
                account_name = account[0].get("sAMAccountName", [""])[0] if isinstance(account[0].get("sAMAccountName"), list) else account[0].get("sAMAccountName", "")
                tier_violations.append({
                    "account": account_name,
                    "violation": "Account is in both Tier 0 and Tier 1 groups"
                })
        
        for member_dn in t0_and_t2:
            # Get account details
            account = self.client.search(
                search_filter=f"(distinguishedName={member_dn})",
                attributes=["sAMAccountName", "objectClass"]
            )
            if account:
                account_name = account[0].get("sAMAccountName", [""])[0] if isinstance(account[0].get("sAMAccountName"), list) else account[0].get("sAMAccountName", "")
                tier_violations.append({
                    "account": account_name,
                    "violation": "Account is in both Tier 0 and Tier 2 groups"
                })
        
        for member_dn in t1_and_t2:
            # Get account details
            account = self.client.search(
                search_filter=f"(distinguishedName={member_dn})",
                attributes=["sAMAccountName", "objectClass"]
            )
            if account:
                account_name = account[0].get("sAMAccountName", [""])[0] if isinstance(account[0].get("sAMAccountName"), list) else account[0].get("sAMAccountName", "")
                tier_violations.append({
                    "account": account_name,
                    "violation": "Account is in both Tier 1 and Tier 2 groups"
                })
        
        # Prepare result details
        tiered_model_found = sum(len(groups) for groups in tier_groups.values()) > 3  # At least some tier groups exist
        
        details = {
            "tiered_model_detected": tiered_model_found,
            "tier0_groups": len(tier_groups["tier0"]),
            "tier1_groups": len(tier_groups["tier1"]),
            "tier2_groups": len(tier_groups["tier2"]),
            "tier_violations": len(tier_violations),
            "violations": tier_violations,
            "tier_groups": tier_groups
        }
        
        # Check passes if tiered model is found and no violations exist
        passed = tiered_model_found and len(tier_violations) == 0
        
        return CheckResult(
            name="Administrative Tier Separation",
            description="Checks if administrative tiers are properly implemented and separated",
            severity=CheckSeverity.CRITICAL,
            passed=passed,
            details=details,
            recommendation="Implement proper tiered administration model with clear separation between tiers",
            reference_url="https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model"
        )
    
    def check_paw_implementation(self) -> CheckResult:
        """
        Check if Privileged Access Workstations (PAWs) are implemented.
        
        Returns:
            CheckResult with findings
        """
        # Look for PAW-related computer objects or security groups
        paw_patterns = [r"paw", r"admin.*workstation", r"tier.*workstation", r"priv.*workstation"]
        
        # Search for PAW computer objects
        paw_computers = []
        for pattern in paw_patterns:
            results = self.client.search(
                search_filter=f"(&(objectClass=computer)(name=*{pattern}*))",
                attributes=["name", "distinguishedName", "operatingSystem", "whenCreated"]
            )
            for computer in results:
                computer_name = computer.get("name", [""])[0] if isinstance(computer.get("name"), list) else computer.get("name", "")
                paw_computers.append({
                    "name": computer_name,
                    "os": computer.get("operatingSystem", [""])[0] if isinstance(computer.get("operatingSystem"), list) else computer.get("operatingSystem", "")
                })
        
        # Search for PAW security groups
        paw_groups = []
        for pattern in paw_patterns:
            results = self.client.search(
                search_filter=f"(&(objectClass=group)(name=*{pattern}*))",
                attributes=["name", "distinguishedName", "description", "member"]
            )
            for group in results:
                group_name = group.get("name", [""])[0] if isinstance(group.get("name"), list) else group.get("name", "")
                paw_groups.append({
                    "name": group_name,
                    "description": group.get("description", [""])[0] if isinstance(group.get("description"), list) else group.get("description", ""),
                    "members": len(group.get("member", []))
                })
        
        # Determine if PAWs are likely implemented
        paw_implemented = len(paw_computers) > 0 or len(paw_groups) > 0
        
        details = {
            "paw_implemented": paw_implemented,
            "paw_computers_found": len(paw_computers),
            "paw_groups_found": len(paw_groups),
            "paw_computers": paw_computers,
            "paw_groups": paw_groups,
            "recommendations": [
                "Implement PAWs for Tier 0 administrators",
                "Configure Device Guard and Credential Guard on PAWs",
                "Restrict network access from PAWs to only required resources",
                "Implement jump servers for Tier 1 and Tier 2 administration"
            ]
        }
        
        return CheckResult(
            name="Privileged Access Workstations (PAWs)",
            description="Checks if Privileged Access Workstations are implemented for administrative tasks",
            severity=CheckSeverity.HIGH,
            passed=paw_implemented,
            details=details,
            recommendation="Implement Privileged Access Workstations for administrative activities, especially for Tier 0 administrators",
            reference_url="https://docs.microsoft.com/en-us/security/compass/privileged-access-devices"
        )
    
    def check_tier0_security(self) -> CheckResult:
        """
        Check security of Tier 0 assets.
        
        Returns:
            CheckResult with findings
        """
        # Get domain controllers (primary Tier 0 assets)
        domain_controllers = self.client.get_domain_controllers()
        
        # Get Tier 0 admin accounts
        privileged_groups = self.client.get_privileged_groups()
        tier0_accounts = set()
        
        for group in privileged_groups:
            group_name = group.get("sAMAccountName", [""])[0] if isinstance(group.get("sAMAccountName"), list) else group.get("sAMAccountName", "")
            
            if group_name in ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]:
                # Get group members
                group_dn = group.get("distinguishedName", [""])[0] if isinstance(group.get("distinguishedName"), list) else group.get("distinguishedName", "")
                members = self.client.get_group_members(group_dn)
                
                for member in members:
                    member_dn = member.get("distinguishedName", [""])[0] if isinstance(member.get("distinguishedName"), list) else member.get("distinguishedName", "")
                    if "user" in str(member.get("objectClass", [])).lower():
                        tier0_accounts.add(member_dn)
        
        # Check security settings for Tier 0 accounts
        tier0_security_issues = []
        
        for account_dn in tier0_accounts:
            account = self.client.search(
                search_filter=f"(distinguishedName={account_dn})",
                attributes=["sAMAccountName", "userAccountControl", "msDS-User-Account-Control-Computed"]
            )
            
            if account:
                account_name = account[0].get("sAMAccountName", [""])[0] if isinstance(account[0].get("sAMAccountName"), list) else account[0].get("sAMAccountName", "")
                uac = account[0].get("userAccountControl", [0])[0] if isinstance(account[0].get("userAccountControl"), list) else account[0].get("userAccountControl", 0)
                
                # Check security settings
                # UAC flags: https://support.microsoft.com/en-us/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
                
                # Smart card required (0x40000)
                smart_card_required = bool(int(uac) & 0x40000)
                
                # Account is sensitive and cannot be delegated (0x100000)
                no_delegation = bool(int(uac) & 0x100000)
                
                if not smart_card_required:
                    tier0_security_issues.append({
                        "account": account_name,
                        "issue": "Smart card authentication not required"
                    })
                
                if not no_delegation:
                    tier0_security_issues.append({
                        "account": account_name,
                        "issue": "Account can be delegated (not marked as sensitive)"
                    })
        
        # Check domain controller security
        dc_security_issues = []
        
        for dc in domain_controllers:
            dc_name = dc.get("name", [""])[0] if isinstance(dc.get("name"), list) else dc.get("name", "")
            os_version = dc.get("operatingSystem", [""])[0] if isinstance(dc.get("operatingSystem"), list) else dc.get("operatingSystem", "")
            
            # Check if OS is current
            if "2008" in os_version or "2012" in os_version:
                dc_security_issues.append({
                    "dc": dc_name,
                    "issue": f"Running outdated OS: {os_version}"
                })
        
        details = {
            "tier0_accounts": len(tier0_accounts),
            "tier0_account_issues": len(tier0_security_issues),
            "domain_controllers": len(domain_controllers),
            "dc_security_issues": len(dc_security_issues),
            "account_issues": tier0_security_issues,
            "dc_issues": dc_security_issues,
            "recommendations": [
                "Require smart cards for all Tier 0 administrators",
                "Mark all Tier 0 accounts as sensitive and cannot be delegated",
                "Implement just-in-time (JIT) administration for Tier 0 access",
                "Upgrade domain controllers to latest supported OS version",
                "Implement LAPS for local admin passwords on all Tier 0 systems"
            ]
        }
        
        # Check passes if no security issues found
        passed = len(tier0_security_issues) == 0 and len(dc_security_issues) == 0
        
        return CheckResult(
            name="Tier 0 Asset Security",
            description="Checks security of Tier 0 assets and accounts",
            severity=CheckSeverity.CRITICAL,
            passed=passed,
            details=details,
            recommendation="Implement enhanced security controls for all Tier 0 assets and accounts",
            reference_url="https://docs.microsoft.com/en-us/security/compass/privileged-access-security-baselines"
        )
    
    def check_lateral_movement_paths(self) -> CheckResult:
        """
        Check for potential lateral movement paths between tiers.
        
        Returns:
            CheckResult with findings
        """
        # This is a complex check that would require deep analysis of group memberships and permissions
        # For this example, we'll implement a simplified version checking for common issues
        
        # Check for local admin group memberships that might allow lateral movement
        
        # Look for built-in Administrators group
        admin_groups = self.client.search(
            search_filter="(sAMAccountName=Administrators)",
            attributes=["distinguishedName", "member"]
        )
        
        admin_group_members = []
        if admin_groups:
            admin_group_dn = admin_groups[0].get("distinguishedName", [""])[0] if isinstance(admin_groups[0].get("distinguishedName"), list) else admin_groups[0].get("distinguishedName", "")
            members = self.client.get_group_members(admin_group_dn)
            
            for member in members:
                member_name = member.get("sAMAccountName", [""])[0] if isinstance(member.get("sAMAccountName"), list) else member.get("sAMAccountName", "")
                admin_group_members.append(member_name)
        
        # Check for groups that might indicate excessive local admin rights
        excessive_rights_groups = self.client.search(
            search_filter="(&(objectClass=group)(|(name=*helpdesk*)(name=*desktop*admin*)(name=*workstation*admin*)))",
            attributes=["name", "description", "member"]
        )
        
        lateral_movement_risks = []
        for group in excessive_rights_groups:
            group_name = group.get("name", [""])[0] if isinstance(group.get("name"), list) else group.get("name", "")
            members_count = len(group.get("member", []))
            
            if members_count > 0:
                lateral_movement_risks.append({
                    "group": group_name,
                    "members": members_count,
                    "description": group.get("description", [""])[0] if isinstance(group.get("description"), list) else group.get("description", "")
                })
        
        details = {
            "admin_group_members": admin_group_members,
            "excessive_rights_groups": len(excessive_rights_groups),
            "lateral_movement_risks": lateral_movement_risks,
            "recommendations": [
                "Implement clean-source principle for administration",
                "Remove unnecessary administrators from local admin groups",
                "Implement LAPS to manage local administrator passwords",
                "Use jump servers for cross-tier administration",
                "Implement network segmentation between tiers"
            ],
            "notes": [
                "A comprehensive lateral movement analysis requires detailed assessment of permissions and group memberships",
                "Consider using tools like BloodHound for detailed analysis of attack paths"
            ]
        }
        
        # This check is informational due to its complexity
        return CheckResult(
            name="Lateral Movement Paths",
            description="Checks for potential lateral movement paths between administrative tiers",
            severity=CheckSeverity.HIGH,
            passed=None,  # Too complex to determine via basic LDAP
            details=details,
            recommendation="Analyze and eliminate lateral movement paths between tiers by implementing proper network segmentation and JIT administration",
            reference_url="https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model"
        )
    
    def check_jit_admin(self) -> CheckResult:
        """
        Check if just-in-time administration is implemented.
        
        Returns:
            CheckResult with findings
        """
        # Look for evidence of JIT implementation
        # This could be MIM PAM, Azure PIM, or custom solutions
        
        # Look for groups that might indicate JIT implementation
        jit_groups = self.client.search(
            search_filter="(&(objectClass=group)(|(name=*temp*admin*)(name=*pam*)(name=*jit*)(name=*priv*elev*)))",
            attributes=["name", "description", "whenCreated", "member"]
        )
        
        # Look for time-bound group membership (temporary group memberships)
        # This is a simplified check - in reality, would need to check for dynamic objects or Azure AD PIM
        
        jit_implemented = len(jit_groups) > 0
        
        details = {
            "jit_likely_implemented": jit_implemented,
            "potential_jit_groups": len(jit_groups),
            "jit_groups": [
                {
                    "name": group.get("name", [""])[0] if isinstance(group.get("name"), list) else group.get("name", ""),
                    "description": group.get("description", [""])[0] if isinstance(group.get("description"), list) else group.get("description", "")
                }
                for group in jit_groups
            ],
            "jit_options": [
                "Microsoft Identity Manager (MIM) Privileged Access Management (PAM)",
                "Azure AD Privileged Identity Management (PIM)",
                "Custom JIT solutions using temporary group memberships",
                "Third-party privileged access management solutions"
            ],
            "recommendations": [
                "Implement just-in-time administration for all privileged access",
                "Use time-bound and approval-based elevation of privileges",
                "Enable comprehensive auditing for all privileged access",
                "Consider Azure AD PIM if using hybrid or cloud environment"
            ]
        }
        
        return CheckResult(
            name="Just-In-Time Administration",
            description="Checks if just-in-time (JIT) administration is implemented",
            severity=CheckSeverity.MEDIUM,
            passed=jit_implemented,
            details=details,
            recommendation="Implement just-in-time administration to minimize standing privileges and reduce attack surface",
            reference_url="https://docs.microsoft.com/en-us/security/compass/privileged-access-deployment"
        ) 