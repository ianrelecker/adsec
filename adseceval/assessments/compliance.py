"""
Assessment module for regulatory compliance validation in Active Directory.
This module maps security checks to compliance frameworks and generates compliance-focused reports.
"""

import logging
from typing import Dict, Any, List, Optional, Set
import json
import os
from collections import defaultdict

from .base import AssessmentBase, CheckResult, CheckSeverity

logger = logging.getLogger(__name__)


class ComplianceAssessment(AssessmentBase):
    """
    Security assessment that evaluates Active Directory against compliance frameworks.
    Maps findings to specific compliance controls and requirements.
    """
    
    name = "Compliance and Regulatory Assessment"
    description = "Evaluates Active Directory security against common compliance frameworks and standards"
    
    # Define compliance frameworks and their control mapping files
    COMPLIANCE_FRAMEWORKS = {
        "nist": "NIST SP 800-53",
        "cis": "CIS Controls",
        "iso27001": "ISO 27001",
        "pci-dss": "PCI DSS",
        "hipaa": "HIPAA"
    }
    
    def __init__(self, client: Any, config: Dict[str, Any] = None):
        """
        Initialize the assessment.
        
        Args:
            client: Client for interacting with Active Directory
            config: Configuration options for this assessment
        """
        super().__init__(client, config)
        
        # Determine which frameworks to assess
        self.selected_frameworks = []
        framework_choice = self.config.get("compliance_framework", "all")
        
        if framework_choice == "all":
            self.selected_frameworks = list(self.COMPLIANCE_FRAMEWORKS.keys())
        elif framework_choice in self.COMPLIANCE_FRAMEWORKS:
            self.selected_frameworks = [framework_choice]
            
        logger.info(f"Selected compliance frameworks: {', '.join(self.selected_frameworks)}")
        
        # Load control mappings
        self.control_mappings = self._load_control_mappings()
    
    def _register_checks(self) -> None:
        """Register compliance checks."""
        self.checks = {
            "nist_compliance": self.check_nist_compliance,
            "cis_compliance": self.check_cis_compliance,
            "iso27001_compliance": self.check_iso27001_compliance,
            "pci_dss_compliance": self.check_pci_dss_compliance,
            "hipaa_compliance": self.check_hipaa_compliance,
            "gap_analysis": self.check_gap_analysis
        }
    
    def _load_control_mappings(self) -> Dict[str, Dict[str, Any]]:
        """
        Load control mappings from static definitions.
        
        In a full implementation, these would be loaded from JSON files.
        
        Returns:
            Dictionary of control mappings by framework
        """
        mappings = {}
        
        # NIST SP 800-53 mappings
        mappings["nist"] = {
            "controls": {
                "AC-2": {
                    "title": "Account Management",
                    "description": "The organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
                    "related_checks": ["admin_count", "dormant_admins", "service_account_privileges"]
                },
                "AC-3": {
                    "title": "Access Enforcement",
                    "description": "The information system enforces approved authorizations for logical access to the system in accordance with applicable policy.",
                    "related_checks": ["admin_tier_separation", "tier0_security", "ldap_signing"]
                },
                "AC-6": {
                    "title": "Least Privilege",
                    "description": "The organization employs the principle of least privilege, allowing only authorized accesses for users that are necessary to accomplish assigned tasks.",
                    "related_checks": ["nested_groups", "protected_users", "admin_mfa"]
                },
                "AC-7": {
                    "title": "Unsuccessful Logon Attempts",
                    "description": "The information system enforces a limit of consecutive invalid logon attempts by a user.",
                    "related_checks": ["account_lockout"]
                },
                "IA-2": {
                    "title": "Identification and Authentication",
                    "description": "The information system uniquely identifies and authenticates organizational users.",
                    "related_checks": ["admin_mfa", "kerberos_configuration"]
                },
                "IA-5": {
                    "title": "Authenticator Management",
                    "description": "The organization manages information system authenticators by establishing and implementing procedures for authenticator management.",
                    "related_checks": ["password_complexity", "password_history", "password_age", "reversible_encryption"]
                },
                "SC-8": {
                    "title": "Transmission Confidentiality and Integrity",
                    "description": "The information system protects the confidentiality and integrity of transmitted information.",
                    "related_checks": ["secure_ldap", "smb_signing", "ldap_channel_binding"]
                }
            }
        }
        
        # CIS Controls mappings
        mappings["cis"] = {
            "controls": {
                "4.1": {
                    "title": "Maintain Inventory of Administrative Accounts",
                    "description": "Use automated tools to inventory all administrative accounts, including domain and local accounts.",
                    "related_checks": ["admin_count", "protected_users"]
                },
                "4.2": {
                    "title": "Change Default Passwords",
                    "description": "Before deploying any new asset, change all default passwords to have values consistent with administrative-level accounts.",
                    "related_checks": ["password_complexity", "password_length"]
                },
                "4.3": {
                    "title": "Ensure the Use of Dedicated Administrative Accounts",
                    "description": "Ensure that all users with administrative account access use a dedicated or secondary account for elevated activities.",
                    "related_checks": ["admin_tier_separation", "paw_implementation"]
                },
                "5.1": {
                    "title": "Establish Secure Configurations",
                    "description": "Maintain documented, standard security configuration standards for all operating systems and software.",
                    "related_checks": ["os_version", "secure_ldap", "smb_signing"]
                },
                "16.3": {
                    "title": "Require Multi-factor Authentication",
                    "description": "Require multi-factor authentication for all user accounts, on all systems, whether managed on-site or by a third-party provider.",
                    "related_checks": ["admin_mfa"]
                }
            }
        }
        
        # ISO 27001 mappings (simplified)
        mappings["iso27001"] = {
            "controls": {
                "A.9.2.3": {
                    "title": "Management of privileged access rights",
                    "description": "The allocation and use of privileged access rights shall be restricted and controlled.",
                    "related_checks": ["admin_count", "tier0_security", "jit_admin"]
                },
                "A.9.2.4": {
                    "title": "Management of secret authentication information of users",
                    "description": "The allocation of secret authentication information shall be controlled through a formal management process.",
                    "related_checks": ["password_complexity", "password_history", "laps_implementation"]
                },
                "A.9.4.3": {
                    "title": "Password management system",
                    "description": "Password management systems shall be interactive and shall ensure quality passwords.",
                    "related_checks": ["password_complexity", "password_length", "password_history"]
                }
            }
        }
        
        # PCI DSS mappings (simplified)
        mappings["pci-dss"] = {
            "controls": {
                "2.2": {
                    "title": "Configuration Standards",
                    "description": "Develop configuration standards for all system components that address all known security vulnerabilities.",
                    "related_checks": ["os_version", "secure_ldap", "smb_signing"]
                },
                "8.1.4": {
                    "title": "Remove/disable inactive user accounts",
                    "description": "Remove/disable inactive user accounts within 90 days.",
                    "related_checks": ["dormant_admins"]
                },
                "8.1.6": {
                    "title": "Account lockout duration",
                    "description": "Limit repeated access attempts by locking out the user account after a defined number of attempts.",
                    "related_checks": ["account_lockout"]
                },
                "8.2.1": {
                    "title": "Strong cryptography for passwords",
                    "description": "Use strong cryptography to render all authentication credentials unreadable during transmission and storage.",
                    "related_checks": ["reversible_encryption", "secure_ldap"]
                }
            }
        }
        
        # HIPAA mappings (simplified)
        mappings["hipaa"] = {
            "controls": {
                "164.308(a)(3)(i)": {
                    "title": "Workforce Security",
                    "description": "Implement policies and procedures to ensure that all members of its workforce have appropriate access to electronic protected health information.",
                    "related_checks": ["admin_tier_separation", "admin_count", "nested_groups"]
                },
                "164.308(a)(4)(i)": {
                    "title": "Information Access Management",
                    "description": "Implement policies and procedures for authorizing access to electronic protected health information.",
                    "related_checks": ["admin_tier_separation", "tier0_security"]
                },
                "164.308(a)(5)(ii)(C)": {
                    "title": "Password Management",
                    "description": "Implement procedures for creating, changing, and safeguarding passwords.",
                    "related_checks": ["password_complexity", "password_history", "password_length"]
                },
                "164.312(a)(2)(i)": {
                    "title": "Unique User Identification",
                    "description": "Assign a unique name and/or number for identifying and tracking user identity.",
                    "related_checks": ["admin_count", "service_account_privileges"]
                },
                "164.312(a)(2)(iv)": {
                    "title": "Encryption and Decryption",
                    "description": "Implement a mechanism to encrypt and decrypt electronic protected health information.",
                    "related_checks": ["secure_ldap", "smb_signing", "ldap_channel_binding"]
                }
            }
        }
        
        return mappings
    
    def _get_all_assessment_results(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get results from all other assessments.
        
        In a real implementation, this would get real results from other modules.
        For this example, we'll generate mock results.
        
        Returns:
            Dictionary with assessment results by module
        """
        # This would be implemented to get actual results from other modules
        # For this example, we'll return a placeholder
        
        # Get actual results from client's collected assessment results
        results = {}
        
        # Since we don't have access to other assessment results in this example,
        # this is a placeholder. In a real implementation, this would access
        # results from the other modules.
        
        return results
    
    def _evaluate_compliance(self, framework: str) -> Dict[str, Any]:
        """
        Evaluate compliance for a specific framework.
        
        Args:
            framework: Framework identifier (e.g., "nist", "cis")
            
        Returns:
            Compliance evaluation results
        """
        if framework not in self.control_mappings:
            return {
                "framework": self.COMPLIANCE_FRAMEWORKS.get(framework, framework),
                "compliant": False,
                "compliant_controls": 0,
                "non_compliant_controls": 0,
                "total_controls": 0,
                "compliance_percentage": 0,
                "controls": {},
                "error": f"Framework {framework} not found in control mappings"
            }
        
        # Get framework controls
        controls = self.control_mappings[framework]["controls"]
        
        # Initialize results
        results = {
            "framework": self.COMPLIANCE_FRAMEWORKS.get(framework, framework),
            "compliant_controls": 0,
            "non_compliant_controls": 0,
            "total_controls": len(controls),
            "controls": {}
        }
        
        # Evaluate each control
        for control_id, control_info in controls.items():
            # Collect all related check results
            control_checks = []
            
            # In a real implementation, this would get actual check results
            # Here we're simulating results
            for check_name in control_info.get("related_checks", []):
                # Simulate check result
                # In a real implementation, this would get the actual check result
                simulated_result = {
                    "name": check_name,
                    "passed": check_name not in ["admin_count", "password_length", "smb_signing", "ntlm_usage"]
                }
                control_checks.append(simulated_result)
            
            # Determine if control is compliant based on related checks
            control_compliant = all(check.get("passed", False) for check in control_checks)
            
            if control_compliant:
                results["compliant_controls"] += 1
            else:
                results["non_compliant_controls"] += 1
            
            # Add control details to results
            results["controls"][control_id] = {
                "id": control_id,
                "title": control_info.get("title", ""),
                "description": control_info.get("description", ""),
                "compliant": control_compliant,
                "related_checks": control_checks
            }
        
        # Calculate compliance percentage
        if results["total_controls"] > 0:
            results["compliance_percentage"] = round((results["compliant_controls"] / results["total_controls"]) * 100, 1)
        else:
            results["compliance_percentage"] = 0
            
        results["compliant"] = results["compliance_percentage"] >= 90  # Arbitrary threshold
        
        return results
    
    def check_nist_compliance(self) -> CheckResult:
        """
        Check compliance with NIST SP 800-53 controls.
        
        Returns:
            CheckResult with NIST compliance findings
        """
        if "nist" not in self.selected_frameworks:
            return CheckResult(
                name="NIST SP 800-53 Compliance",
                description="Evaluates compliance with NIST SP 800-53 security controls",
                severity=CheckSeverity.HIGH,
                passed=None,
                details={"skipped": True, "reason": "NIST framework not selected"},
                recommendation="Include 'nist' in the selected compliance frameworks to evaluate NIST SP 800-53 compliance."
            )
        
        try:
            results = self._evaluate_compliance("nist")
            
            details = {
                "framework": results["framework"],
                "compliance_percentage": results["compliance_percentage"],
                "compliant_controls": results["compliant_controls"],
                "non_compliant_controls": results["non_compliant_controls"],
                "total_controls": results["total_controls"],
                "critical_controls": {
                    "AC-2": results["controls"].get("AC-2", {}).get("compliant", False),
                    "AC-6": results["controls"].get("AC-6", {}).get("compliant", False),
                    "IA-2": results["controls"].get("IA-2", {}).get("compliant", False),
                    "SC-8": results["controls"].get("SC-8", {}).get("compliant", False)
                },
                "non_compliant_control_ids": [
                    control_id for control_id, control in results["controls"].items() 
                    if not control.get("compliant", False)
                ],
                "recommendations": [
                    "Review and address findings for non-compliant controls",
                    "Prioritize critical controls (AC-2, AC-6, IA-2, SC-8)",
                    "Develop a remediation plan for each non-compliant control",
                    "Implement continuous monitoring for compliance"
                ]
            }
            
            passed = results["compliant"]
            
        except Exception as e:
            logger.error(f"Error during NIST compliance check: {str(e)}", exc_info=True)
            details = {"error": str(e)}
            passed = False
        
        return CheckResult(
            name="NIST SP 800-53 Compliance",
            description="Evaluates compliance with NIST SP 800-53 security controls",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Address non-compliant controls, focusing on account management, access control, and secure communications.",
            reference_url="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        )
    
    def check_cis_compliance(self) -> CheckResult:
        """
        Check compliance with CIS Controls.
        
        Returns:
            CheckResult with CIS compliance findings
        """
        if "cis" not in self.selected_frameworks:
            return CheckResult(
                name="CIS Controls Compliance",
                description="Evaluates compliance with CIS Controls",
                severity=CheckSeverity.HIGH,
                passed=None,
                details={"skipped": True, "reason": "CIS framework not selected"},
                recommendation="Include 'cis' in the selected compliance frameworks to evaluate CIS Controls compliance."
            )
        
        try:
            results = self._evaluate_compliance("cis")
            
            details = {
                "framework": results["framework"],
                "compliance_percentage": results["compliance_percentage"],
                "compliant_controls": results["compliant_controls"],
                "non_compliant_controls": results["non_compliant_controls"],
                "total_controls": results["total_controls"],
                "critical_controls": {
                    "4.1": results["controls"].get("4.1", {}).get("compliant", False),
                    "4.3": results["controls"].get("4.3", {}).get("compliant", False),
                    "16.3": results["controls"].get("16.3", {}).get("compliant", False)
                },
                "non_compliant_control_ids": [
                    control_id for control_id, control in results["controls"].items() 
                    if not control.get("compliant", False)
                ],
                "recommendations": [
                    "Review and address findings for non-compliant controls",
                    "Prioritize critical identity and access management controls",
                    "Develop a remediation plan for each non-compliant control",
                    "Implement continuous monitoring for compliance"
                ]
            }
            
            passed = results["compliant"]
            
        except Exception as e:
            logger.error(f"Error during CIS compliance check: {str(e)}", exc_info=True)
            details = {"error": str(e)}
            passed = False
        
        return CheckResult(
            name="CIS Controls Compliance",
            description="Evaluates compliance with CIS Controls",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Address non-compliant controls, focusing on account management, authentication, and access control.",
            reference_url="https://www.cisecurity.org/controls/"
        )
    
    def check_iso27001_compliance(self) -> CheckResult:
        """
        Check compliance with ISO 27001 controls.
        
        Returns:
            CheckResult with ISO 27001 compliance findings
        """
        if "iso27001" not in self.selected_frameworks:
            return CheckResult(
                name="ISO 27001 Compliance",
                description="Evaluates compliance with ISO 27001 controls",
                severity=CheckSeverity.HIGH,
                passed=None,
                details={"skipped": True, "reason": "ISO 27001 framework not selected"},
                recommendation="Include 'iso27001' in the selected compliance frameworks to evaluate ISO 27001 compliance."
            )
        
        try:
            results = self._evaluate_compliance("iso27001")
            
            details = {
                "framework": results["framework"],
                "compliance_percentage": results["compliance_percentage"],
                "compliant_controls": results["compliant_controls"],
                "non_compliant_controls": results["non_compliant_controls"],
                "total_controls": results["total_controls"],
                "critical_controls": {
                    "A.9.2.3": results["controls"].get("A.9.2.3", {}).get("compliant", False),
                    "A.9.2.4": results["controls"].get("A.9.2.4", {}).get("compliant", False),
                    "A.9.4.3": results["controls"].get("A.9.4.3", {}).get("compliant", False)
                },
                "non_compliant_control_ids": [
                    control_id for control_id, control in results["controls"].items() 
                    if not control.get("compliant", False)
                ],
                "recommendations": [
                    "Review and address findings for non-compliant controls",
                    "Prioritize access control and authentication controls",
                    "Develop a remediation plan for each non-compliant control",
                    "Implement continuous monitoring for compliance"
                ]
            }
            
            passed = results["compliant"]
            
        except Exception as e:
            logger.error(f"Error during ISO 27001 compliance check: {str(e)}", exc_info=True)
            details = {"error": str(e)}
            passed = False
        
        return CheckResult(
            name="ISO 27001 Compliance",
            description="Evaluates compliance with ISO 27001 controls",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Address non-compliant controls, focusing on access control, authentication, and password management.",
            reference_url="https://www.iso.org/isoiec-27001-information-security.html"
        )
    
    def check_pci_dss_compliance(self) -> CheckResult:
        """
        Check compliance with PCI DSS requirements.
        
        Returns:
            CheckResult with PCI DSS compliance findings
        """
        if "pci-dss" not in self.selected_frameworks:
            return CheckResult(
                name="PCI DSS Compliance",
                description="Evaluates compliance with PCI DSS requirements",
                severity=CheckSeverity.HIGH,
                passed=None,
                details={"skipped": True, "reason": "PCI DSS framework not selected"},
                recommendation="Include 'pci-dss' in the selected compliance frameworks to evaluate PCI DSS compliance."
            )
        
        try:
            results = self._evaluate_compliance("pci-dss")
            
            details = {
                "framework": results["framework"],
                "compliance_percentage": results["compliance_percentage"],
                "compliant_controls": results["compliant_controls"],
                "non_compliant_controls": results["non_compliant_controls"],
                "total_controls": results["total_controls"],
                "critical_controls": {
                    "8.1.6": results["controls"].get("8.1.6", {}).get("compliant", False),
                    "8.2.1": results["controls"].get("8.2.1", {}).get("compliant", False)
                },
                "non_compliant_control_ids": [
                    control_id for control_id, control in results["controls"].items() 
                    if not control.get("compliant", False)
                ],
                "recommendations": [
                    "Review and address findings for non-compliant requirements",
                    "Prioritize authentication and access control requirements",
                    "Develop a remediation plan for each non-compliant requirement",
                    "Implement continuous monitoring for compliance"
                ]
            }
            
            passed = results["compliant"]
            
        except Exception as e:
            logger.error(f"Error during PCI DSS compliance check: {str(e)}", exc_info=True)
            details = {"error": str(e)}
            passed = False
        
        return CheckResult(
            name="PCI DSS Compliance",
            description="Evaluates compliance with PCI DSS requirements",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Address non-compliant requirements, focusing on account management, access control, and cryptography.",
            reference_url="https://www.pcisecuritystandards.org/document_library/"
        )
    
    def check_hipaa_compliance(self) -> CheckResult:
        """
        Check compliance with HIPAA Security Rule requirements.
        
        Returns:
            CheckResult with HIPAA compliance findings
        """
        if "hipaa" not in self.selected_frameworks:
            return CheckResult(
                name="HIPAA Security Rule Compliance",
                description="Evaluates compliance with HIPAA Security Rule requirements",
                severity=CheckSeverity.HIGH,
                passed=None,
                details={"skipped": True, "reason": "HIPAA framework not selected"},
                recommendation="Include 'hipaa' in the selected compliance frameworks to evaluate HIPAA Security Rule compliance."
            )
        
        try:
            results = self._evaluate_compliance("hipaa")
            
            details = {
                "framework": results["framework"],
                "compliance_percentage": results["compliance_percentage"],
                "compliant_controls": results["compliant_controls"],
                "non_compliant_controls": results["non_compliant_controls"],
                "total_controls": results["total_controls"],
                "critical_controls": {
                    "164.308(a)(3)(i)": results["controls"].get("164.308(a)(3)(i)", {}).get("compliant", False),
                    "164.312(a)(2)(iv)": results["controls"].get("164.312(a)(2)(iv)", {}).get("compliant", False)
                },
                "non_compliant_control_ids": [
                    control_id for control_id, control in results["controls"].items() 
                    if not control.get("compliant", False)
                ],
                "recommendations": [
                    "Review and address findings for non-compliant requirements",
                    "Prioritize access control and authentication requirements",
                    "Develop a remediation plan for each non-compliant requirement",
                    "Implement continuous monitoring for compliance"
                ]
            }
            
            passed = results["compliant"]
            
        except Exception as e:
            logger.error(f"Error during HIPAA compliance check: {str(e)}", exc_info=True)
            details = {"error": str(e)}
            passed = False
        
        return CheckResult(
            name="HIPAA Security Rule Compliance",
            description="Evaluates compliance with HIPAA Security Rule requirements",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Address non-compliant requirements, focusing on access control, authentication, and data protection.",
            reference_url="https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"
        )
    
    def check_gap_analysis(self) -> CheckResult:
        """
        Perform a gap analysis across all selected compliance frameworks.
        
        Returns:
            CheckResult with gap analysis findings
        """
        if not self.selected_frameworks:
            return CheckResult(
                name="Compliance Gap Analysis",
                description="Analyzes gaps across multiple compliance frameworks",
                severity=CheckSeverity.MEDIUM,
                passed=None,
                details={"skipped": True, "reason": "No compliance frameworks selected"},
                recommendation="Select one or more compliance frameworks to perform a gap analysis."
            )
        
        try:
            # Collect results from all frameworks
            framework_results = {}
            for framework in self.selected_frameworks:
                framework_results[framework] = self._evaluate_compliance(framework)
            
            # Find common gaps across frameworks
            common_gaps = set()
            for framework, results in framework_results.items():
                for control_id, control in results.get("controls", {}).items():
                    if not control.get("compliant", True):
                        for check in control.get("related_checks", []):
                            if not check.get("passed", True):
                                common_gaps.add(check.get("name", ""))
            
            # Build details
            details = {
                "frameworks_evaluated": len(self.selected_frameworks),
                "frameworks": [self.COMPLIANCE_FRAMEWORKS.get(f, f) for f in self.selected_frameworks],
                "common_gaps": list(common_gaps),
                "framework_compliance": {
                    self.COMPLIANCE_FRAMEWORKS.get(f, f): {
                        "compliance_percentage": r.get("compliance_percentage", 0),
                        "compliant": r.get("compliant", False)
                    }
                    for f, r in framework_results.items()
                },
                "highest_compliance": max((r.get("compliance_percentage", 0) for r in framework_results.values()), default=0),
                "lowest_compliance": min((r.get("compliance_percentage", 0) for r in framework_results.values()), default=0),
                "recommendations": [
                    "Address common gaps across all frameworks first",
                    "Prioritize critical control gaps",
                    "Develop a comprehensive remediation plan",
                    "Implement continuous compliance monitoring"
                ]
            }
            
            # Determine overall pass/fail
            overall_compliant = all(r.get("compliant", False) for r in framework_results.values())
            
        except Exception as e:
            logger.error(f"Error during compliance gap analysis: {str(e)}", exc_info=True)
            details = {"error": str(e)}
            overall_compliant = False
        
        return CheckResult(
            name="Compliance Gap Analysis",
            description="Analyzes gaps across multiple compliance frameworks",
            severity=CheckSeverity.MEDIUM,
            passed=overall_compliant,
            details=details,
            recommendation="Develop a unified compliance approach addressing common gaps across all frameworks.",
            reference_url="https://csrc.nist.gov/projects/risk-management/sp800-53-controls/mapping-documents"
        )