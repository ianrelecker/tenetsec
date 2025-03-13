"""Microsoft Teams security assessment."""

from typing import Dict, Any, List
from .base import AssessmentBase, CheckResult, CheckSeverity


class TeamsAssessment(AssessmentBase):
    """Security assessment for Microsoft Teams."""

    name = "Microsoft Teams Security Assessment"
    description = "Evaluates the security configuration of Microsoft Teams"

    def _register_checks(self) -> None:
        """Register security checks."""
        self.checks = {
            "external_access": self.check_external_access,
            "guest_access": self.check_guest_access,
            "meeting_policies": self.check_meeting_policies,
            "app_permissions": self.check_app_permissions,
            "messaging_policies": self.check_messaging_policies,
        }

    def check_external_access(self) -> CheckResult:
        """Check if external access is restricted.
        
        Returns:
            CheckResult with findings
        """
        # Query external access settings
        external_settings = self.client.get("teamwork/teamSettings/externalAccess")
        
        settings_details = {
            "allows_federation": False,
            "allowed_domains": [],
            "blocked_domains": [],
            "allows_public_cloud": False,
            "allows_government_cloud": False
        }
        
        restricted_access = False
        
        if "error" not in external_settings:
            # Check if federation is allowed
            settings_details["allows_federation"] = external_settings.get("allowFederation", False)
            
            # Check domain restrictions
            settings_details["allowed_domains"] = external_settings.get("allowedDomains", [])
            settings_details["blocked_domains"] = external_settings.get("blockedDomains", [])
            
            # Check other cloud settings
            settings_details["allows_public_cloud"] = external_settings.get("allowPublicCloudFederation", False)
            settings_details["allows_government_cloud"] = external_settings.get("allowGovCloudFederation", False)
            
            # Check for restricted settings (either federation is off or allowed domains are specified)
            restricted_access = (
                not settings_details["allows_federation"] or
                len(settings_details["allowed_domains"]) > 0 or
                len(settings_details["blocked_domains"]) > 0
            )
        
        return CheckResult(
            name="Teams External Access",
            description="Checks if external access in Teams is restricted",
            severity=CheckSeverity.HIGH,
            passed=restricted_access,
            details=settings_details,
            recommendation="Restrict external access in Teams by disabling federation or configuring allowed/blocked domains",
            reference_url="https://docs.microsoft.com/en-us/microsoftteams/manage-external-access"
        )

    def check_guest_access(self) -> CheckResult:
        """Check if guest access is restricted.
        
        Returns:
            CheckResult with findings
        """
        # Query guest access settings
        guest_settings = self.client.get("teamwork/teamSettings/guestAccess")
        
        settings_details = {
            "allows_guest_access": False,
            "allows_create_update_channels": False,
            "allows_delete_channels": False,
            "calling_allowed": False,
            "meeting_allowed": False,
            "has_conditional_access": False
        }
        
        restricted_guest_access = False
        
        if "error" not in guest_settings:
            # Check if guest access is allowed
            settings_details["allows_guest_access"] = guest_settings.get("allowGuestAccess", False)
            
            # Check channel permissions
            settings_details["allows_create_update_channels"] = guest_settings.get("allowCreateUpdateChannels", False)
            settings_details["allows_delete_channels"] = guest_settings.get("allowDeleteChannels", False)
            
            # Check calling and meeting permissions
            settings_details["calling_allowed"] = guest_settings.get("allowGuestUserCalling", False)
            settings_details["meeting_allowed"] = guest_settings.get("allowGuestMeetingJoin", False)
            
            # Check for conditional access
            ca_policies = self.client.get_all("identity/conditionalAccess/policies")
            
            if "error" not in ca_policies:
                for policy in ca_policies:
                    if (
                        policy.get("state") == "enabled" and
                        "includeGuestsOrExternalUsers" in policy.get("conditions", {}).get("users", {})
                    ):
                        settings_details["has_conditional_access"] = True
                        break
            
            # Check for restricted settings
            restricted_guest_access = (
                not settings_details["allows_guest_access"] or
                (settings_details["allows_guest_access"] and 
                not settings_details["allows_create_update_channels"] and
                not settings_details["allows_delete_channels"] and
                settings_details["has_conditional_access"])
            )
        
        return CheckResult(
            name="Teams Guest Access",
            description="Checks if guest access in Teams is restricted",
            severity=CheckSeverity.HIGH,
            passed=restricted_guest_access,
            details=settings_details,
            recommendation="Restrict guest access in Teams or limit permissions for guests and apply conditional access policies",
            reference_url="https://docs.microsoft.com/en-us/microsoftteams/guest-access"
        )

    def check_meeting_policies(self) -> CheckResult:
        """Check if meeting policies are secure.
        
        Returns:
            CheckResult with findings
        """
        # Query meeting policies
        meeting_policies = self.client.get("teamwork/meetingPolicies")
        
        policy_details = {
            "policies": [],
            "global_policy": {
                "anonymous_join": False,
                "lobby_bypass": "unknown",
                "recording_allowed": False
            },
            "secure_policies": 0,
            "total_policies": 0
        }
        
        global_policy_secure = False
        
        if "error" not in meeting_policies and "value" in meeting_policies:
            policies = meeting_policies["value"]
            policy_details["total_policies"] = len(policies)
            
            for policy in policies:
                policy_info = {
                    "id": policy.get("id"),
                    "anonymous_join": policy.get("anonymousJoinEnabled", False),
                    "lobby_bypass": policy.get("autoAdmittedUsers", "unknown"),
                    "recording_allowed": policy.get("allowRecording", False)
                }
                
                policy_details["policies"].append(policy_info)
                
                # Check if policy is secure
                is_secure = (
                    not policy_info["anonymous_join"] and
                    policy_info["lobby_bypass"] in ["everyoneInCompany", "everyoneInSameOrg", "organizer"] and
                    not policy_info["recording_allowed"]
                )
                
                if is_secure:
                    policy_details["secure_policies"] += 1
                
                # Check if this is the global policy
                if policy.get("id") == "Global":
                    policy_details["global_policy"] = policy_info
                    global_policy_secure = is_secure
        
        # Check passes if the global policy is secure
        passed = global_policy_secure
        
        return CheckResult(
            name="Teams Meeting Policies",
            description="Checks if Teams meeting policies are secure",
            severity=CheckSeverity.MEDIUM,
            passed=passed,
            details=policy_details,
            recommendation="Configure Teams meeting policies to restrict anonymous join, use lobby for external users, and control recording permissions",
            reference_url="https://docs.microsoft.com/en-us/microsoftteams/meeting-policies-overview"
        )

    def check_app_permissions(self) -> CheckResult:
        """Check if app permissions are restricted.
        
        Returns:
            CheckResult with findings
        """
        # Query app settings
        app_settings = self.client.get("teamwork/teamSettings/appPermissions")
        
        settings_details = {
            "global_apps_allowed": False,
            "org_apps_allowed": False,
            "third_party_apps_allowed": False,
            "custom_apps_allowed": False,
            "user_app_upload_allowed": False,
            "restricted_app_list": []
        }
        
        restricted_apps = False
        
        if "error" not in app_settings:
            # Check app installation settings
            settings_details["global_apps_allowed"] = app_settings.get("globalCatalogAppsEnabled", False)
            settings_details["org_apps_allowed"] = app_settings.get("orgCatalogAppsEnabled", False)
            settings_details["third_party_apps_allowed"] = app_settings.get("thirdPartyCatalogAppsEnabled", False)
            settings_details["custom_apps_allowed"] = app_settings.get("customAppsEnabled", False)
            settings_details["user_app_upload_allowed"] = app_settings.get("userAppUploadEnabled", False)
            
            # Check apps restricted
            restricted_apps_list = self.client.get("teamwork/restrictedApps")
            
            if "error" not in restricted_apps_list and "value" in restricted_apps_list:
                settings_details["restricted_app_list"] = [app.get("id") for app in restricted_apps_list["value"]]
            
            # Check for restricted settings
            restricted_apps = (
                not settings_details["third_party_apps_allowed"] or
                not settings_details["custom_apps_allowed"] or
                not settings_details["user_app_upload_allowed"] or
                len(settings_details["restricted_app_list"]) > 0
            )
        
        return CheckResult(
            name="Teams App Permissions",
            description="Checks if Teams app permissions are restricted",
            severity=CheckSeverity.MEDIUM,
            passed=restricted_apps,
            details=settings_details,
            recommendation="Restrict Teams app permissions by disabling third-party apps, custom apps, or user app uploads, or by creating an approved app list",
            reference_url="https://docs.microsoft.com/en-us/microsoftteams/manage-apps"
        )

    def check_messaging_policies(self) -> CheckResult:
        """Check if messaging policies are secure.
        
        Returns:
            CheckResult with findings
        """
        # Query messaging policies
        messaging_policies = self.client.get("teamwork/messagingPolicies")
        
        policy_details = {
            "policies": [],
            "global_policy": {
                "url_previews": False,
                "giphy_allowed": False,
                "stickers_allowed": False,
                "immersive_reader": False,
                "translation_allowed": False
            },
            "secure_policies": 0,
            "total_policies": 0
        }
        
        global_policy_secure = False
        
        if "error" not in messaging_policies and "value" in messaging_policies:
            policies = messaging_policies["value"]
            policy_details["total_policies"] = len(policies)
            
            for policy in policies:
                policy_info = {
                    "id": policy.get("id"),
                    "url_previews": policy.get("allowUrlPreviews", False),
                    "giphy_allowed": policy.get("allowGiphy", False),
                    "stickers_allowed": policy.get("allowStickers", False),
                    "immersive_reader": policy.get("allowImmersiveReader", False),
                    "translation_allowed": policy.get("allowTranslation", False)
                }
                
                policy_details["policies"].append(policy_info)
                
                # Check if policy is secure (restricts features that could expose data or allow phishing)
                is_secure = (
                    not policy_info["url_previews"] and
                    not policy_info["giphy_allowed"]
                )
                
                if is_secure:
                    policy_details["secure_policies"] += 1
                
                # Check if this is the global policy
                if policy.get("id") == "Global":
                    policy_details["global_policy"] = policy_info
                    global_policy_secure = is_secure
        
        # Check passes if the global policy is secure
        passed = global_policy_secure
        
        return CheckResult(
            name="Teams Messaging Policies",
            description="Checks if Teams messaging policies are secure",
            severity=CheckSeverity.LOW,
            passed=passed,
            details=policy_details,
            recommendation="Configure Teams messaging policies to restrict URL previews and other external content sources that could pose security risks",
            reference_url="https://docs.microsoft.com/en-us/microsoftteams/messaging-policies-in-teams"
        )