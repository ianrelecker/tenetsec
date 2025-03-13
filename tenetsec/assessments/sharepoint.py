"""SharePoint and OneDrive security assessment."""

from typing import Dict, Any, List
from .base import AssessmentBase, CheckResult, CheckSeverity


class SharePointAssessment(AssessmentBase):
    """Security assessment for SharePoint Online and OneDrive for Business."""

    name = "SharePoint and OneDrive Security Assessment"
    description = "Evaluates the security configuration of SharePoint Online and OneDrive for Business"

    def _register_checks(self) -> None:
        """Register security checks."""
        self.checks = {
            "sharing_settings": self.check_sharing_settings,
            "access_control": self.check_access_control,
            "dlp_policies": self.check_dlp_policies,
            "sites_sensitive_files": self.check_sites_sensitive_files,
            "device_access": self.check_device_access,
        }

    def check_sharing_settings(self) -> CheckResult:
        """Check if sharing settings are configured securely.
        
        Returns:
            CheckResult with findings
        """
        # Query SharePoint tenant sharing settings
        sharing_settings = self.client.get("admin/sharepoint/settings")
        
        settings_details = {
            "default_sharing_link_type": "unknown",
            "default_link_permission": "unknown",
            "sharing_capability": "unknown",
            "allow_anonymous_sharing_expiration": False,
            "requires_acceptance": False
        }
        
        secure_settings = False
        
        if "error" not in sharing_settings:
            # Check default sharing link type (internal, direct, anonymous)
            settings_details["default_sharing_link_type"] = sharing_settings.get("defaultSharingLinkType", "unknown")
            
            # Check default link permission (edit vs view)
            settings_details["default_link_permission"] = sharing_settings.get("fileAnonymousLinkType", "unknown")
            
            # Check overall sharing capability
            settings_details["sharing_capability"] = sharing_settings.get("sharingCapability", "unknown")
            
            # Check if anonymous links can expire
            settings_details["allow_anonymous_sharing_expiration"] = sharing_settings.get("requireAnonymousLinksExpireInDays", False)
            
            # Check if sharing requires acceptance
            settings_details["requires_acceptance"] = sharing_settings.get("requireAcceptanceOfSharingRequestFrom", False)
            
            # Check for secure settings: internal sharing only or requiring sign-in
            secure_settings = (
                settings_details["sharing_capability"] in ["ExistingExternalUserSharingOnly", "ExternalUserAndGuestSharing"] and
                settings_details["default_sharing_link_type"] != "AnonymousAccess" and
                settings_details["allow_anonymous_sharing_expiration"]
            )
        
        return CheckResult(
            name="SharePoint Sharing Settings",
            description="Checks if SharePoint sharing settings are configured securely",
            severity=CheckSeverity.HIGH,
            passed=secure_settings,
            details=settings_details,
            recommendation="Configure SharePoint sharing settings to restrict external sharing, use secure link types by default, and set expiration for anonymous links",
            reference_url="https://docs.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off"
        )

    def check_access_control(self) -> CheckResult:
        """Check if access control settings are configured securely.
        
        Returns:
            CheckResult with findings
        """
        # Query access control settings
        access_settings = self.client.get("admin/sharepoint/accessControl")
        
        settings_details = {
            "conditional_access_policy": "unknown",
            "allows_limited_access": False,
            "blocks_download": False,
            "unmanaged_device_restrictions": False
        }
        
        secure_settings = False
        
        if "error" not in access_settings:
            # Check conditional access policy
            settings_details["conditional_access_policy"] = access_settings.get("conditionalAccessPolicy", "unknown")
            
            # Check if limited access is allowed
            settings_details["allows_limited_access"] = access_settings.get("allowLimitedAccess", False)
            
            # Check if download is blocked
            settings_details["blocks_download"] = access_settings.get("blockDownload", False)
            
            # Check for unmanaged device restrictions
            settings_details["unmanaged_device_restrictions"] = access_settings.get("unmanagedDeviceRestrictions", False)
            
            # Check for secure settings
            secure_settings = (
                settings_details["conditional_access_policy"] != "AllowFullAccess" and
                settings_details["unmanaged_device_restrictions"]
            )
        
        return CheckResult(
            name="SharePoint Access Control",
            description="Checks if access control settings are configured securely",
            severity=CheckSeverity.HIGH,
            passed=secure_settings,
            details=settings_details,
            recommendation="Configure SharePoint access control to restrict access from unmanaged devices and apply conditional access policies",
            reference_url="https://docs.microsoft.com/en-us/sharepoint/control-access-from-unmanaged-devices"
        )

    def check_dlp_policies(self) -> CheckResult:
        """Check if Data Loss Prevention (DLP) policies are configured.
        
        Returns:
            CheckResult with findings
        """
        # Query DLP policies
        dlp_policies = self.client.get("security/dataLossPrevention/policies")
        
        policy_details = {
            "total_policies": 0,
            "enabled_policies": 0,
            "sharepoint_policies": 0,
            "onedrive_policies": 0,
            "sensitive_types_covered": []
        }
        
        if "error" not in dlp_policies and "value" in dlp_policies:
            policies = dlp_policies["value"]
            policy_details["total_policies"] = len(policies)
            
            sensitive_types = set()
            
            for policy in policies:
                if policy.get("enabled", False):
                    policy_details["enabled_policies"] += 1
                    
                    # Check if policy applies to SharePoint
                    locations = policy.get("locations", {})
                    if locations.get("sharePoint", {}).get("enabled", False):
                        policy_details["sharepoint_policies"] += 1
                    
                    # Check if policy applies to OneDrive
                    if locations.get("oneDrive", {}).get("enabled", False):
                        policy_details["onedrive_policies"] += 1
                    
                    # Track sensitive info types covered
                    rules = policy.get("rules", [])
                    for rule in rules:
                        sensitive_info = rule.get("sensitiveInformation", {}).get("types", [])
                        for info_type in sensitive_info:
                            sensitive_types.add(info_type.get("name", ""))
            
            policy_details["sensitive_types_covered"] = list(sensitive_types)
        
        # Check passes if there are enabled policies for both SharePoint and OneDrive
        passed = (
            policy_details["sharepoint_policies"] > 0 and
            policy_details["onedrive_policies"] > 0
        )
        
        return CheckResult(
            name="Data Loss Prevention Policies",
            description="Checks if Data Loss Prevention (DLP) policies are configured for SharePoint and OneDrive",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=policy_details,
            recommendation="Configure DLP policies to protect sensitive information in SharePoint and OneDrive content",
            reference_url="https://docs.microsoft.com/en-us/microsoft-365/compliance/create-test-tune-dlp-policy"
        )

    def check_sites_sensitive_files(self) -> CheckResult:
        """Check for potentially unsecured sensitive files.
        
        Returns:
            CheckResult with findings
        """
        # Query sites with sensitive content
        sensitive_sites = self.client.get("security/secureScoreControlProfiles/SharePointSensitiveFiles/controlStateUpdates")
        
        site_details = {
            "total_sites": 0,
            "sites_with_sensitive_content": 0,
            "sites_with_external_sharing": 0,
            "sensitive_file_count": 0
        }
        
        all_secured = True
        
        if "error" not in sensitive_sites and "value" in sensitive_sites:
            updates = sensitive_sites["value"]
            
            for update in updates:
                # Get details about sites with sensitive content
                state = update.get("state", {})
                site_details["total_sites"] = state.get("totalSiteCount", 0)
                site_details["sites_with_sensitive_content"] = state.get("sensitiveContentSiteCount", 0)
                site_details["sites_with_external_sharing"] = state.get("externalSharingSiteCount", 0)
                site_details["sensitive_file_count"] = state.get("sensitiveFileCount", 0)
                
                # If there are sites with sensitive content that also have external sharing, that's a risk
                if site_details["sites_with_sensitive_content"] > 0 and site_details["sites_with_external_sharing"] > 0:
                    all_secured = False
                    break
        
        return CheckResult(
            name="Sensitive File Protection",
            description="Checks for potentially unsecured sensitive files in SharePoint and OneDrive",
            severity=CheckSeverity.MEDIUM,
            passed=all_secured,
            details=site_details,
            recommendation="Identify sites with sensitive content and restrict external sharing or apply additional protection measures",
            reference_url="https://docs.microsoft.com/en-us/microsoft-365/compliance/sensitivity-labels"
        )

    def check_device_access(self) -> CheckResult:
        """Check if device access policies are configured.
        
        Returns:
            CheckResult with findings
        """
        # Query device access policies
        device_policies = self.client.get("admin/sharepoint/deviceAccessPolicies")
        
        policy_details = {
            "web_access_policy": "unknown",
            "mobile_access_policy": "unknown",
            "desktop_access_policy": "unknown",
            "prevents_unmanaged_download": False
        }
        
        secure_policies = False
        
        if "error" not in device_policies:
            # Check web access policy
            policy_details["web_access_policy"] = device_policies.get("webAccessPolicy", "unknown")
            
            # Check mobile access policy
            policy_details["mobile_access_policy"] = device_policies.get("mobileAccessPolicy", "unknown")
            
            # Check desktop access policy
            policy_details["desktop_access_policy"] = device_policies.get("desktopAccessPolicy", "unknown")
            
            # Check if any policy prevents unmanaged downloads
            prevents_download = (
                policy_details["web_access_policy"] in ["BlockDownload", "BlockAccess"] or
                policy_details["mobile_access_policy"] in ["BlockDownload", "BlockAccess"] or
                policy_details["desktop_access_policy"] in ["BlockDownload", "BlockAccess"]
            )
            
            policy_details["prevents_unmanaged_download"] = prevents_download
            
            # Check for secure settings
            secure_policies = prevents_download
        
        return CheckResult(
            name="Device Access Policies",
            description="Checks if device access policies are configured for SharePoint and OneDrive",
            severity=CheckSeverity.MEDIUM,
            passed=secure_policies,
            details=policy_details,
            recommendation="Configure device access policies to restrict access and downloads from unmanaged devices",
            reference_url="https://docs.microsoft.com/en-us/sharepoint/control-access-from-unmanaged-devices"
        )