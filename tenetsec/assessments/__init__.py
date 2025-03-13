"""Security assessment modules for TenetSec."""

from .base import AssessmentBase, CheckResult, CheckSeverity
from .identity import IdentityAssessment
from .defender import DefenderAssessment
from .exchange import ExchangeAssessment
from .sharepoint import SharePointAssessment
from .teams import TeamsAssessment

# List of all assessment modules
ALL_ASSESSMENTS = [
    IdentityAssessment,
    DefenderAssessment,
    ExchangeAssessment,
    SharePointAssessment,
    TeamsAssessment,
]