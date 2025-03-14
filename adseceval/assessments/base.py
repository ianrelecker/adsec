"""
Base assessment module that defines the framework for all security assessments.
"""

from abc import ABC, abstractmethod
from enum import Enum
import logging
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger(__name__)


class CheckSeverity(Enum):
    """Enum representing the severity of security check findings."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class CheckResult:
    """Class representing the result of a security check."""
    
    def __init__(
        self,
        name: str,
        description: str,
        severity: CheckSeverity,
        passed: bool,
        details: Dict[str, Any],
        recommendation: str,
        reference_url: Optional[str] = None,
        compliance_mappings: Optional[Dict[str, List[str]]] = None,
        exploitation_results: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize a new security check result.
        
        Args:
            name: Name of the check
            description: Description of what was checked
            severity: Severity level if the check fails
            passed: Whether the check passed
            details: Detailed information about the check result
            recommendation: Recommended action to remediate the issue
            reference_url: URL to reference documentation
            compliance_mappings: Dictionary mapping compliance frameworks to control IDs
                e.g., {"NIST SP 800-53": ["AC-2", "AC-6"], "CIS": ["1.4", "1.5"]}
            exploitation_results: Results of exploitation tests related to this finding
        """
        self.name = name
        self.description = description
        self.severity = severity
        self.passed = passed
        self.details = details
        self.recommendation = recommendation
        self.reference_url = reference_url
        self.compliance_mappings = compliance_mappings or {}
        self.exploitation_results = exploitation_results or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the check result to a dictionary.
        
        Returns:
            Dict representation of the check result
        """
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "passed": self.passed,
            "details": self.details,
            "recommendation": self.recommendation,
            "reference_url": self.reference_url,
            "compliance_mappings": self.compliance_mappings,
            "exploitation_results": self.exploitation_results
        }


class AssessmentBase(ABC):
    """Base class for all security assessments."""
    
    name = "Base Assessment"
    description = "Base assessment class that all assessments should inherit from."
    
    def __init__(self, client: Any, config: Dict[str, Any] = None):
        """
        Initialize the assessment.
        
        Args:
            client: Client for interacting with Active Directory
            config: Configuration options for this assessment
        """
        self.client = client
        self.config = config or {}
        self.checks = {}
        self.results = []
        self._register_checks()
    
    @abstractmethod
    def _register_checks(self) -> None:
        """
        Register the security checks for this assessment.
        This method should be overridden by subclasses.
        """
        pass
    
    def run(self) -> Dict[str, Any]:
        """
        Run all security checks for this assessment.
        
        Returns:
            Dict with assessment results
        """
        logger.info(f"Running assessment: {self.name}")
        
        self.results = []
        for check_name, check_func in self.checks.items():
            try:
                logger.debug(f"Running check: {check_name}")
                result = check_func()
                self.results.append(result)
                
                status = "PASSED" if result.passed else "FAILED"
                logger.info(f"Check {check_name}: {status} [{result.severity.value}]")
            except Exception as e:
                logger.error(f"Error running check {check_name}: {str(e)}", exc_info=True)
        
        return self.get_results()
    
    def get_results(self) -> Dict[str, Any]:
        """
        Get the results of this assessment.
        
        Returns:
            Dict with assessment results
        """
        # Calculate statistics
        total_checks = len(self.results)
        passed_checks = sum(1 for r in self.results if r.passed)
        failed_checks = total_checks - passed_checks
        
        # Count by severity
        severity_counts = {severity.value: 0 for severity in CheckSeverity}
        for result in self.results:
            if not result.passed:
                severity_counts[result.severity.value] += 1
        
        # Determine overall assessment status
        status = "passed"
        if any(not r.passed and r.severity in [CheckSeverity.CRITICAL, CheckSeverity.HIGH] for r in self.results):
            status = "critical"
        elif any(not r.passed and r.severity == CheckSeverity.MEDIUM for r in self.results):
            status = "warning"
        elif any(not r.passed for r in self.results):
            status = "info"
        
        return {
            "name": self.name,
            "description": self.description,
            "status": status,
            "summary": {
                "total_checks": total_checks,
                "passed_checks": passed_checks,
                "failed_checks": failed_checks,
                "by_severity": severity_counts
            },
            "checks": [r.to_dict() for r in self.results]
        }