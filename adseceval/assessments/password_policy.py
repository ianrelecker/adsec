"""
Assessment module for password policy security in Active Directory.
"""

import logging
from typing import Dict, Any, List, Optional

from .base import AssessmentBase, CheckResult, CheckSeverity

logger = logging.getLogger(__name__)


class PasswordPolicyAssessment(AssessmentBase):
    """Security assessment for password policies in Active Directory."""
    
    name = "Password Policy Security Assessment"
    description = "Evaluates the security configuration of password policies in Active Directory"
    
    def _register_checks(self) -> None:
        """Register password policy security checks."""
        self.checks = {
            "password_complexity": self.check_password_complexity,
            "password_length": self.check_password_length,
            "password_history": self.check_password_history,
            "password_age": self.check_password_age,
            "account_lockout": self.check_account_lockout,
            "fine_grained_policies": self.check_fine_grained_policies,
            "reversible_encryption": self.check_reversible_encryption,
        }
    
    def check_password_complexity(self) -> CheckResult:
        """
        Check if password complexity requirements are enforced.
        
        Returns:
            CheckResult with findings
        """
        # Get domain password policy
        policy = self.client.get_password_policy()
        
        # Check if complexity is enabled
        complexity_enabled = policy.get("complexityEnabled", False)
        
        details = {
            "complexity_enabled": complexity_enabled,
            "policy_details": policy
        }
        
        # Check passes if complexity is enabled
        passed = complexity_enabled
        
        return CheckResult(
            name="Password Complexity",
            description="Checks if password complexity requirements are enforced in the domain password policy",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Enable password complexity requirements in the domain policy to enhance password security",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements"
        )
    
    def check_password_length(self) -> CheckResult:
        """
        Check if minimum password length meets security recommendations.
        
        Returns:
            CheckResult with findings
        """
        # Get domain password policy
        policy = self.client.get_password_policy()
        
        # Get minimum password length
        min_length = 0
        if "minPwdLength" in policy:
            min_length = int(policy["minPwdLength"][0]) if isinstance(policy["minPwdLength"], list) else int(policy["minPwdLength"])
        
        # Recommended minimum length
        recommended_length = 14
        
        details = {
            "current_min_length": min_length,
            "recommended_min_length": recommended_length,
            "policy_details": policy
        }
        
        # Check passes if minimum length is at least the recommended length
        passed = min_length >= recommended_length
        
        return CheckResult(
            name="Minimum Password Length",
            description="Checks if the minimum password length meets security recommendations",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation=f"Configure minimum password length to at least {recommended_length} characters",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length"
        )
    
    def check_password_history(self) -> CheckResult:
        """
        Check if password history requirements meet security recommendations.
        
        Returns:
            CheckResult with findings
        """
        # Get domain password policy
        policy = self.client.get_password_policy()
        
        # Get password history length
        history_length = 0
        if "pwdHistoryLength" in policy:
            history_length = int(policy["pwdHistoryLength"][0]) if isinstance(policy["pwdHistoryLength"], list) else int(policy["pwdHistoryLength"])
        
        # Recommended history length
        recommended_length = 24
        
        details = {
            "current_history_length": history_length,
            "recommended_history_length": recommended_length,
            "policy_details": policy
        }
        
        # Check passes if history length is at least the recommended length
        passed = history_length >= recommended_length
        
        return CheckResult(
            name="Password History",
            description="Checks if password history requirements meet security recommendations",
            severity=CheckSeverity.MEDIUM,
            passed=passed,
            details=details,
            recommendation=f"Configure password history to remember at least {recommended_length} previous passwords",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-password-history"
        )
    
    def check_password_age(self) -> CheckResult:
        """
        Check if password age settings meet security recommendations.
        
        Returns:
            CheckResult with findings
        """
        # Get domain password policy
        policy = self.client.get_password_policy()
        
        # Get password age settings
        min_age_days = policy.get("minPwdAgeDays", 0)
        max_age_days = policy.get("maxPwdAgeDays", 0)
        
        # Recommended settings
        recommended_min_age = 1.0
        recommended_max_age = 90.0
        
        details = {
            "current_min_age_days": min_age_days,
            "current_max_age_days": max_age_days,
            "recommended_min_age": recommended_min_age,
            "recommended_max_age": recommended_max_age,
            "policy_details": policy
        }
        
        # Check for appropriate age settings
        # Minimum age should be at least 1 day
        # Maximum age should be no more than 90 days and not 0 (never expire)
        min_age_ok = min_age_days >= recommended_min_age
        max_age_ok = 0 < max_age_days <= recommended_max_age
        
        passed = min_age_ok and max_age_ok
        
        return CheckResult(
            name="Password Age",
            description="Checks if password age settings meet security recommendations",
            severity=CheckSeverity.MEDIUM,
            passed=passed,
            details=details,
            recommendation=f"Configure minimum password age to at least {recommended_min_age} day and maximum password age to no more than {recommended_max_age} days",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age"
        )
    
    def check_account_lockout(self) -> CheckResult:
        """
        Check if account lockout settings meet security recommendations.
        
        Returns:
            CheckResult with findings
        """
        # Get domain password policy
        policy = self.client.get_password_policy()
        
        # Get lockout settings
        lockout_threshold = 0
        lockout_duration_minutes = 0
        lockout_window_minutes = 0
        
        if "lockoutThreshold" in policy:
            lockout_threshold = int(policy["lockoutThreshold"][0]) if isinstance(policy["lockoutThreshold"], list) else int(policy["lockoutThreshold"])
        
        if "lockoutDurationMinutes" in policy:
            lockout_duration_minutes = policy["lockoutDurationMinutes"]
        
        if "lockoutObservationWindowMinutes" in policy:
            lockout_window_minutes = policy["lockoutObservationWindowMinutes"]
        
        # Recommended settings
        recommended_threshold = 10
        recommended_duration = 15
        recommended_window = 15
        
        details = {
            "current_lockout_threshold": lockout_threshold,
            "current_lockout_duration_minutes": lockout_duration_minutes,
            "current_lockout_window_minutes": lockout_window_minutes,
            "recommended_threshold": recommended_threshold,
            "recommended_duration": recommended_duration,
            "recommended_window": recommended_window,
            "policy_details": policy
        }
        
        # Check for appropriate lockout settings
        # Threshold should be 10 or fewer failed attempts but not 0 (disabled)
        # Duration should be at least 15 minutes
        # Observation window should be at least 15 minutes
        threshold_ok = 0 < lockout_threshold <= recommended_threshold
        duration_ok = lockout_duration_minutes >= recommended_duration
        window_ok = lockout_window_minutes >= recommended_window
        
        passed = threshold_ok and duration_ok and window_ok
        
        return CheckResult(
            name="Account Lockout Settings",
            description="Checks if account lockout settings meet security recommendations",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation=f"Configure account lockout threshold to {recommended_threshold} or fewer attempts, lockout duration to at least {recommended_duration} minutes, and observation window to at least {recommended_window} minutes",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy"
        )
    
    def check_fine_grained_policies(self) -> CheckResult:
        """
        Check if fine-grained password policies are used.
        
        Returns:
            CheckResult with findings
        """
        # Get fine-grained password policies
        fgpps = self.client.get_fine_grained_password_policies()
        
        # Count policies
        policy_count = len(fgpps)
        
        details = {
            "policy_count": policy_count,
            "policies": fgpps
        }
        
        # Check is informational, not strictly pass/fail
        # But we'll consider it "passed" if there are any FGPPs
        passed = policy_count > 0
        
        return CheckResult(
            name="Fine-Grained Password Policies",
            description="Checks if fine-grained password policies are used for different security requirements",
            severity=CheckSeverity.INFO,
            passed=passed,
            details=details,
            recommendation="Consider implementing fine-grained password policies for different user groups, especially for privileged accounts",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/fine-grained-password-policies"
        )
    
    def check_reversible_encryption(self) -> CheckResult:
        """
        Check if passwords are stored with reversible encryption.
        
        Returns:
            CheckResult with findings
        """
        # Get domain password policy
        policy = self.client.get_password_policy()
        
        # Check if reversible encryption is enabled
        reversible_encryption = policy.get("reversibleEncryptionEnabled", False)
        
        details = {
            "reversible_encryption_enabled": reversible_encryption,
            "policy_details": policy
        }
        
        # Check passes if reversible encryption is disabled
        passed = not reversible_encryption
        
        return CheckResult(
            name="Reversible Encryption",
            description="Checks if passwords are stored with reversible encryption",
            severity=CheckSeverity.CRITICAL,
            passed=passed,
            details=details,
            recommendation="Disable 'Store passwords using reversible encryption' in the domain password policy",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption"
        )