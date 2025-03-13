"""Defender for Office 365 security assessment."""

from typing import Dict, Any, List
from .base import AssessmentBase, CheckResult, CheckSeverity


class DefenderAssessment(AssessmentBase):
    """Security assessment for Microsoft Defender for Office 365."""

    name = "Microsoft Defender for Office 365 Assessment"
    description = "Evaluates the security configuration of Microsoft Defender for Office 365"

    def _register_checks(self) -> None:
        """Register security checks."""
        self.checks = {
            "safe_attachments": self.check_safe_attachments,
            "safe_links": self.check_safe_links,
            "anti_phishing": self.check_anti_phishing,
            "preset_security": self.check_preset_security,
            "alerts_config": self.check_alerts_config,
        }

    def check_safe_attachments(self) -> CheckResult:
        """Check if Safe Attachments is configured properly.
        
        Returns:
            CheckResult with findings
        """
        # Query Safe Attachments policies
        safe_attachment_policies = self.client.get("security/threatProtection/safeAttachmentPolicies")
        
        policy_details = {
            "policies": [],
            "has_default_policy": False,
            "default_policy_enabled": False,
            "action_settings": {}
        }
        
        has_effective_policy = False
        
        if "error" not in safe_attachment_policies and "value" in safe_attachment_policies:
            policies = safe_attachment_policies["value"]
            
            for policy in policies:
                policy_info = {
                    "name": policy.get("name"),
                    "enabled": policy.get("enabled", False),
                    "action": policy.get("actionSettings", {}).get("action"),
                    "scope": "default" if policy.get("isDefault", False) else "custom"
                }
                
                policy_details["policies"].append(policy_info)
                
                # Check if this is the default policy
                if policy.get("isDefault", False):
                    policy_details["has_default_policy"] = True
                    policy_details["default_policy_enabled"] = policy.get("enabled", False)
                    policy_details["action_settings"] = policy.get("actionSettings", {})
                
                # Check if policy is effective (enabled and with appropriate action)
                if (
                    policy.get("enabled", False) and
                    policy.get("actionSettings", {}).get("action") in ["block", "replace", "dynamic"]
                ):
                    has_effective_policy = True
        
        return CheckResult(
            name="Safe Attachments Configuration",
            description="Checks if Safe Attachments is configured properly to protect against malicious attachments",
            severity=CheckSeverity.HIGH,
            passed=has_effective_policy,
            details=policy_details,
            recommendation="Configure Safe Attachments policies with Block, Replace, or Dynamic Delivery actions to protect against malicious attachments",
            reference_url="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-about"
        )

    def check_safe_links(self) -> CheckResult:
        """Check if Safe Links is configured properly.
        
        Returns:
            CheckResult with findings
        """
        # Query Safe Links policies
        safe_links_policies = self.client.get("security/threatProtection/safeLinksPolicies")
        
        policy_details = {
            "policies": [],
            "has_default_policy": False,
            "default_policy_enabled": False,
            "protection_settings": {}
        }
        
        has_effective_policy = False
        
        if "error" not in safe_links_policies and "value" in safe_links_policies:
            policies = safe_links_policies["value"]
            
            for policy in policies:
                policy_info = {
                    "name": policy.get("name"),
                    "enabled": policy.get("enabled", False),
                    "tracks_clicks": policy.get("protectionSettings", {}).get("trackClicks", False),
                    "checks_detonation": policy.get("protectionSettings", {}).get("detonationEnabled", False),
                    "scope": "default" if policy.get("isDefault", False) else "custom"
                }
                
                policy_details["policies"].append(policy_info)
                
                # Check if this is the default policy
                if policy.get("isDefault", False):
                    policy_details["has_default_policy"] = True
                    policy_details["default_policy_enabled"] = policy.get("enabled", False)
                    policy_details["protection_settings"] = policy.get("protectionSettings", {})
                
                # Check if policy is effective (enabled with good protection settings)
                if (
                    policy.get("enabled", False) and
                    policy.get("protectionSettings", {}).get("detonationEnabled", False)
                ):
                    has_effective_policy = True
        
        return CheckResult(
            name="Safe Links Configuration",
            description="Checks if Safe Links is configured properly to protect against malicious URLs",
            severity=CheckSeverity.HIGH,
            passed=has_effective_policy,
            details=policy_details,
            recommendation="Configure Safe Links policies with URL detonation and click tracking to protect against malicious URLs",
            reference_url="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-about"
        )

    def check_anti_phishing(self) -> CheckResult:
        """Check if anti-phishing protection is configured.
        
        Returns:
            CheckResult with findings
        """
        # Query anti-phishing policies
        anti_phishing_policies = self.client.get("security/threatProtection/antiPhishingPolicies")
        
        policy_details = {
            "policies": [],
            "has_default_policy": False,
            "default_policy_enabled": False,
            "impersonation_protection": False,
            "spoof_protection": False,
            "mailbox_intelligence": False
        }
        
        has_effective_policy = False
        
        if "error" not in anti_phishing_policies and "value" in anti_phishing_policies:
            policies = anti_phishing_policies["value"]
            
            for policy in policies:
                impersonation_settings = policy.get("impersonationProtectionSettings", {})
                
                policy_info = {
                    "name": policy.get("name"),
                    "enabled": policy.get("enabled", False),
                    "impersonation_protection": impersonation_settings.get("enabled", False),
                    "spoof_protection": policy.get("spoofProtectionSettings", {}).get("enabled", False),
                    "mailbox_intelligence": policy.get("mailboxIntelligenceSettings", {}).get("enabled", False)
                }
                
                policy_details["policies"].append(policy_info)
                
                # Check if this is the default policy
                if policy.get("isDefault", False):
                    policy_details["has_default_policy"] = True
                    policy_details["default_policy_enabled"] = policy.get("enabled", False)
                    policy_details["impersonation_protection"] = impersonation_settings.get("enabled", False)
                    policy_details["spoof_protection"] = policy.get("spoofProtectionSettings", {}).get("enabled", False)
                    policy_details["mailbox_intelligence"] = policy.get("mailboxIntelligenceSettings", {}).get("enabled", False)
                
                # Check if policy is effective (enabled with good protection settings)
                if (
                    policy.get("enabled", False) and
                    (impersonation_settings.get("enabled", False) or
                     policy.get("spoofProtectionSettings", {}).get("enabled", False) or
                     policy.get("mailboxIntelligenceSettings", {}).get("enabled", False))
                ):
                    has_effective_policy = True
        
        return CheckResult(
            name="Anti-Phishing Protection",
            description="Checks if anti-phishing protection is properly configured",
            severity=CheckSeverity.HIGH,
            passed=has_effective_policy,
            details=policy_details,
            recommendation="Configure anti-phishing policies with impersonation protection, spoof protection, and mailbox intelligence to protect against phishing attacks",
            reference_url="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-protection-about"
        )

    def check_preset_security(self) -> CheckResult:
        """Check if preset security policies are enabled.
        
        Returns:
            CheckResult with findings
        """
        # Query preset security policies
        preset_policies = self.client.get("security/threatProtection/presetSecurityPolicies")
        
        policy_details = {
            "standard_protection": {
                "enabled": False,
                "applied_to_all": False
            },
            "strict_protection": {
                "enabled": False, 
                "applied_to_all": False
            }
        }
        
        has_effective_policy = False
        
        if "error" not in preset_policies and "value" in preset_policies:
            policies = preset_policies["value"]
            
            for policy in policies:
                protection_type = "standard_protection" if "standard" in policy.get("name", "").lower() else "strict_protection"
                
                policy_details[protection_type] = {
                    "enabled": policy.get("enabled", False),
                    "applied_to_all": policy.get("appliesToAll", False),
                    "excluded_users": policy.get("excludedUsers", []),
                    "excluded_groups": policy.get("excludedGroups", [])
                }
                
                # Check if policy is effective
                if policy.get("enabled", False) and policy.get("appliesToAll", False):
                    has_effective_policy = True
        
        return CheckResult(
            name="Preset Security Policies",
            description="Checks if preset security policies are enabled",
            severity=CheckSeverity.MEDIUM,
            passed=has_effective_policy,
            details=policy_details,
            recommendation="Enable either Standard or Strict preset security policies to apply Microsoft's recommended security settings",
            reference_url="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies"
        )

    def check_alerts_config(self) -> CheckResult:
        """Check if security alerts are properly configured.
        
        Returns:
            CheckResult with findings
        """
        # Query alert policies
        alert_policies = self.client.get("security/alertPolicies")
        
        policy_details = {
            "total_policies": 0,
            "enabled_policies": 0,
            "critical_alerts_enabled": False,
            "high_alerts_enabled": False,
            "categories": {}
        }
        
        if "error" not in alert_policies and "value" in alert_policies:
            policies = alert_policies["value"]
            policy_details["total_policies"] = len(policies)
            
            enabled_count = 0
            categories = {}
            critical_enabled = False
            high_enabled = False
            
            for policy in policies:
                is_enabled = policy.get("enabled", False)
                
                if is_enabled:
                    enabled_count += 1
                    
                    # Track by category
                    category = policy.get("category", "Other")
                    if category not in categories:
                        categories[category] = 0
                    categories[category] += 1
                    
                    # Check for critical and high severity alerts
                    severity = policy.get("severity", "")
                    if severity == "High":
                        high_enabled = True
                    elif severity == "Critical":
                        critical_enabled = True
            
            policy_details["enabled_policies"] = enabled_count
            policy_details["categories"] = categories
            policy_details["critical_alerts_enabled"] = critical_enabled
            policy_details["high_alerts_enabled"] = high_enabled
        
        # Check passes if high and critical alerts are enabled
        passed = policy_details["critical_alerts_enabled"] and policy_details["high_alerts_enabled"]
        
        return CheckResult(
            name="Security Alerts Configuration",
            description="Checks if security alerts are properly configured",
            severity=CheckSeverity.MEDIUM,
            passed=passed,
            details=policy_details,
            recommendation="Enable security alert policies, especially for high and critical severity threats",
            reference_url="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/alert-policies"
        )