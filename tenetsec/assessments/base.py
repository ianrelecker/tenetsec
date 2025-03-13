"""Base classes for security assessments."""

from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Callable
import logging
from ..graph_client import GraphClient

logger = logging.getLogger(__name__)


class CheckSeverity(str, Enum):
    """Severity levels for security checks."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    """Result of a security check."""

    name: str
    description: str
    severity: CheckSeverity
    passed: bool
    details: Dict[str, Any]
    recommendation: str
    reference_url: Optional[str] = None


class AssessmentBase:
    """Base class for security assessments."""

    # Name and description of the assessment
    name = "Base Assessment"
    description = "Base assessment class"
    
    def __init__(self, client: GraphClient):
        """Initialize the assessment module.
        
        Args:
            client: Authenticated GraphClient instance
        """
        self.client = client
        self.results: List[CheckResult] = []
        self.checks: Dict[str, Callable] = {}
        self._register_checks()
    
    def _register_checks(self) -> None:
        """Register security checks to be performed.
        
        This should be overridden by subclasses to register their specific checks.
        """
        pass
    
    def run_assessment(self) -> List[CheckResult]:
        """Run all registered security checks.
        
        Returns:
            List of check results
        """
        self.results = []
        
        for check_name, check_func in self.checks.items():
            try:
                logger.info(f"Running check: {check_name}")
                result = check_func()
                self.results.append(result)
            except Exception as e:
                logger.error(f"Error running check {check_name}: {str(e)}")
                # Add a failed check result for the error
                self.results.append(
                    CheckResult(
                        name=check_name,
                        description=f"Failed to run check due to error",
                        severity=CheckSeverity.INFO,
                        passed=False,
                        details={"error": str(e)},
                        recommendation="Check permissions and retry"
                    )
                )
        
        return self.results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the assessment results.
        
        Returns:
            Dict with summary statistics
        """
        if not self.results:
            return {
                "name": self.name,
                "total_checks": 0,
                "passed": 0,
                "failed": 0,
                "pass_percentage": 0,
                "by_severity": {}
            }
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        
        # Group by severity
        by_severity = {}
        for severity in CheckSeverity:
            severity_results = [r for r in self.results if r.severity == severity]
            severity_total = len(severity_results)
            severity_passed = sum(1 for r in severity_results if r.passed)
            
            if severity_total > 0:
                by_severity[severity.value] = {
                    "total": severity_total,
                    "passed": severity_passed,
                    "failed": severity_total - severity_passed,
                    "pass_percentage": round((severity_passed / severity_total) * 100, 1)
                }
        
        return {
            "name": self.name,
            "total_checks": total,
            "passed": passed,
            "failed": total - passed,
            "pass_percentage": round((passed / total) * 100, 1) if total > 0 else 0,
            "by_severity": by_severity
        }