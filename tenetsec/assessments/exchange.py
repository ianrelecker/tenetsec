"""Exchange Online security assessment."""

from typing import Dict, Any, List
from .base import AssessmentBase, CheckResult, CheckSeverity


class ExchangeAssessment(AssessmentBase):
    """Security assessment for Exchange Online."""

    name = "Exchange Online Security Assessment"
    description = "Evaluates the security configuration of Exchange Online"

    def _register_checks(self) -> None:
        """Register security checks."""
        self.checks = {
            "spam_filter": self.check_spam_filter,
            "mail_authentication": self.check_mail_authentication,
            "malware_filter": self.check_malware_filter,
            "mail_flow_rules": self.check_mail_flow_rules,
            "auditing": self.check_auditing,
        }

    def check_spam_filter(self) -> CheckResult:
        """Check if spam filter policies are properly configured.
        
        Returns:
            CheckResult with findings
        """
        # Query spam filter policies
        spam_policies = self.client.get("security/threatProtection/spamFilterPolicies")
        
        policy_details = {
            "policies": [],
            "has_default_policy": False,
            "default_policy_enabled": False,
            "high_confidence_spam_action": "unknown",
            "spam_action": "unknown"
        }
        
        has_effective_policy = False
        
        if "error" not in spam_policies and "value" in spam_policies:
            policies = spam_policies["value"]
            
            for policy in policies:
                policy_info = {
                    "name": policy.get("name"),
                    "enabled": policy.get("enabled", False),
                    "spam_action": policy.get("spamAction", ""),
                    "high_confidence_spam_action": policy.get("highConfidenceSpamAction", ""),
                    "scope": "default" if policy.get("isDefault", False) else "custom"
                }
                
                policy_details["policies"].append(policy_info)
                
                # Check if this is the default policy
                if policy.get("isDefault", False):
                    policy_details["has_default_policy"] = True
                    policy_details["default_policy_enabled"] = policy.get("enabled", False)
                    policy_details["spam_action"] = policy.get("spamAction", "")
                    policy_details["high_confidence_spam_action"] = policy.get("highConfidenceSpamAction", "")
                
                # Check if policy is effective
                if (
                    policy.get("enabled", False) and
                    policy.get("spamAction", "") in ["MoveToJmf", "Quarantine", "Delete"] and
                    policy.get("highConfidenceSpamAction", "") in ["Quarantine", "Delete"]
                ):
                    has_effective_policy = True
        
        return CheckResult(
            name="Spam Filter Configuration",
            description="Checks if spam filter policies are properly configured",
            severity=CheckSeverity.MEDIUM,
            passed=has_effective_policy,
            details=policy_details,
            recommendation="Configure spam filter policies to quarantine or delete spam and high-confidence spam",
            reference_url="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/configure-spam-settings"
        )

    def check_mail_authentication(self) -> CheckResult:
        """Check if email authentication methods are configured.
        
        Returns:
            CheckResult with findings
        """
        # Query domain authentication settings (SPF, DKIM, DMARC)
        domains = self.client.get("domains")
        
        auth_status = {
            "domains": [],
            "spf_configured": 0,
            "dkim_configured": 0,
            "dmarc_configured": 0,
            "total_domains": 0
        }
        
        if "error" not in domains and "value" in domains:
            domain_list = domains["value"]
            auth_status["total_domains"] = len(domain_list)
            
            for domain in domain_list:
                domain_name = domain.get("id")
                
                # Check SPF
                spf_record = self.client.get(f"domains/{domain_name}/serviceConfigurationRecords?$filter=recordType eq 'Txt'")
                has_spf = False
                
                if "error" not in spf_record and "value" in spf_record:
                    has_spf = any("v=spf1" in record.get("supportedService", "") for record in spf_record["value"])
                
                # Check DKIM
                dkim_status = self.client.get(f"security/threatProtection/domains/{domain_name}/dkimStatus")
                has_dkim = False
                
                if "error" not in dkim_status:
                    has_dkim = dkim_status.get("enabled", False)
                
                # Check DMARC
                dmarc_record = self.client.get(f"domains/{domain_name}/serviceConfigurationRecords?$filter=recordType eq 'Txt' and supportedService eq 'DMARC'")
                has_dmarc = False
                
                if "error" not in dmarc_record and "value" in dmarc_record:
                    has_dmarc = len(dmarc_record["value"]) > 0
                
                domain_info = {
                    "name": domain_name,
                    "spf": has_spf,
                    "dkim": has_dkim,
                    "dmarc": has_dmarc
                }
                
                auth_status["domains"].append(domain_info)
                
                if has_spf:
                    auth_status["spf_configured"] += 1
                if has_dkim:
                    auth_status["dkim_configured"] += 1
                if has_dmarc:
                    auth_status["dmarc_configured"] += 1
        
        # Check passes if most domains have all three authentication methods
        total_domains = auth_status["total_domains"]
        if total_domains > 0:
            spf_percentage = (auth_status["spf_configured"] / total_domains) * 100
            dkim_percentage = (auth_status["dkim_configured"] / total_domains) * 100
            dmarc_percentage = (auth_status["dmarc_configured"] / total_domains) * 100
            
            passed = (
                spf_percentage >= 80 and
                dkim_percentage >= 80 and
                dmarc_percentage >= 80
            )
        else:
            passed = False
        
        return CheckResult(
            name="Email Authentication",
            description="Checks if email authentication methods (SPF, DKIM, DMARC) are configured",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=auth_status,
            recommendation="Configure SPF, DKIM, and DMARC for all domains to prevent email spoofing and phishing",
            reference_url="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-about"
        )

    def check_malware_filter(self) -> CheckResult:
        """Check if malware filter policies are properly configured.
        
        Returns:
            CheckResult with findings
        """
        # Query malware filter policies
        malware_policies = self.client.get("security/threatProtection/malwareFilterPolicies")
        
        policy_details = {
            "policies": [],
            "has_default_policy": False,
            "default_policy_enabled": False,
            "file_types_blocked": []
        }
        
        has_effective_policy = False
        
        if "error" not in malware_policies and "value" in malware_policies:
            policies = malware_policies["value"]
            
            for policy in policies:
                policy_info = {
                    "name": policy.get("name"),
                    "enabled": policy.get("enabled", False),
                    "action": policy.get("action", ""),
                    "file_types_blocked": policy.get("fileTypesToBlock", []),
                    "scope": "default" if policy.get("isDefault", False) else "custom"
                }
                
                policy_details["policies"].append(policy_info)
                
                # Check if this is the default policy
                if policy.get("isDefault", False):
                    policy_details["has_default_policy"] = True
                    policy_details["default_policy_enabled"] = policy.get("enabled", False)
                    policy_details["file_types_blocked"] = policy.get("fileTypesToBlock", [])
                
                # Check if policy is effective
                if (
                    policy.get("enabled", False) and
                    policy.get("action", "") in ["DeleteMessage", "DeleteAttachmentAndUseDefaultAlert"] and
                    len(policy.get("fileTypesToBlock", [])) > 0
                ):
                    has_effective_policy = True
        
        return CheckResult(
            name="Malware Filter Configuration",
            description="Checks if malware filter policies are properly configured",
            severity=CheckSeverity.HIGH,
            passed=has_effective_policy,
            details=policy_details,
            recommendation="Configure malware filter policies to block known malicious file types and delete messages with malware",
            reference_url="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-malware-protection-office-365"
        )

    def check_mail_flow_rules(self) -> CheckResult:
        """Check if mail flow rules are properly configured for security.
        
        Returns:
            CheckResult with findings
        """
        # Query mail flow rules (transport rules)
        mail_rules = self.client.get("security/transportRules")
        
        rule_details = {
            "total_rules": 0,
            "enabled_rules": 0,
            "security_rules": 0,
            "attachment_rules": 0,
            "phishing_rules": 0,
            "external_sender_rules": 0
        }
        
        if "error" not in mail_rules and "value" in mail_rules:
            rules = mail_rules["value"]
            rule_details["total_rules"] = len(rules)
            
            for rule in rules:
                if rule.get("state", "") == "Enabled":
                    rule_details["enabled_rules"] += 1
                    
                    # Check for attachment filtering rules
                    conditions = rule.get("conditions", {})
                    if any(k for k in conditions.keys() if "attachment" in k.lower()):
                        rule_details["attachment_rules"] += 1
                        rule_details["security_rules"] += 1
                    
                    # Check for phishing-related rules
                    if any(k for k in conditions.keys() if "phish" in k.lower() or "spam" in k.lower()):
                        rule_details["phishing_rules"] += 1
                        rule_details["security_rules"] += 1
                    
                    # Check for external sender rules
                    if any(k for k in conditions.keys() if "external" in k.lower() or "outside" in k.lower()):
                        rule_details["external_sender_rules"] += 1
                        rule_details["security_rules"] += 1
        
        # Check passes if there are some security-focused mail flow rules
        passed = rule_details["security_rules"] >= 3
        
        return CheckResult(
            name="Mail Flow Rules",
            description="Checks if mail flow rules are configured to enhance security",
            severity=CheckSeverity.MEDIUM,
            passed=passed,
            details=rule_details,
            recommendation="Configure mail flow rules to handle suspicious attachments, mark external emails, and apply additional security measures",
            reference_url="https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules"
        )

    def check_auditing(self) -> CheckResult:
        """Check if mailbox and admin auditing is enabled.
        
        Returns:
            CheckResult with findings
        """
        # Query mailbox audit configuration
        mailbox_audit = self.client.get("security/auditConfigurations/mailboxAudit")
        
        # Query admin audit configuration
        admin_audit = self.client.get("security/auditConfigurations/adminAudit")
        
        audit_details = {
            "mailbox_auditing": {
                "enabled": False,
                "operations": []
            },
            "admin_auditing": {
                "enabled": False,
                "operations": []
            }
        }
        
        # Check mailbox auditing
        if "error" not in mailbox_audit:
            audit_details["mailbox_auditing"]["enabled"] = mailbox_audit.get("enabled", False)
            audit_details["mailbox_auditing"]["operations"] = mailbox_audit.get("operations", [])
        
        # Check admin auditing
        if "error" not in admin_audit:
            audit_details["admin_auditing"]["enabled"] = admin_audit.get("enabled", False)
            audit_details["admin_auditing"]["operations"] = admin_audit.get("operations", [])
        
        # Check passes if both types of auditing are enabled
        passed = (
            audit_details["mailbox_auditing"]["enabled"] and
            audit_details["admin_auditing"]["enabled"]
        )
        
        return CheckResult(
            name="Exchange Auditing",
            description="Checks if mailbox and admin auditing is enabled",
            severity=CheckSeverity.MEDIUM,
            passed=passed,
            details=audit_details,
            recommendation="Enable mailbox and admin auditing to track actions taken on mailboxes and by administrators",
            reference_url="https://docs.microsoft.com/en-us/microsoft-365/compliance/audit-log-enable-disable"
        )