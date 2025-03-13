"""Identity security assessment for M365 tenants."""

from typing import Dict, Any, List
from .base import AssessmentBase, CheckResult, CheckSeverity


class IdentityAssessment(AssessmentBase):
    """Security assessment for Microsoft Entra ID (Azure AD)."""

    name = "Microsoft Entra ID Security Assessment"
    description = "Evaluates the security configuration of Microsoft Entra ID (formerly Azure AD)"

    def _register_checks(self) -> None:
        """Register identity security checks."""
        self.checks = {
            "mfa_enforcement": self.check_mfa_enforcement,
            "legacy_auth_blocked": self.check_legacy_auth_blocked,
            "pw_policy": self.check_password_policy,
            "conditional_access": self.check_conditional_access,
            "pim_usage": self.check_pim_usage,
            "guest_access": self.check_guest_access,
            "admin_mfa": self.check_admin_mfa,
            "privileged_roles": self.check_privileged_roles,
            "emergency_access": self.check_emergency_access,
        }

    def check_mfa_enforcement(self) -> CheckResult:
        """Check if MFA is enforced for all users.
        
        Returns:
            CheckResult with findings
        """
        # Get authentication methods policies
        policies = self.client.get("policies/authenticationMethodsPolicy")
        
        # Get conditional access policies related to MFA
        ca_policies = self.client.get_all("identity/conditionalAccess/policies")
        
        # Check for per-user MFA enforcement
        per_user_mfa = self.client.get("reports/credentialUserRegistrationDetails")

        # Analyze policies to see if MFA is required for all users
        mfa_enforced = False
        mfa_policy_details = {}
        
        # Check default authentication methods policy
        if "error" not in policies:
            mfa_policy_details["default_policy"] = {
                "mfa_required": policies.get("registrationEnforcement", {}).get("authenticationMethodsRegistrationCampaign", {}).get("state") == "enabled"
            }
        
        # Check conditional access policies
        mfa_ca_policies = []
        if "error" not in ca_policies:
            for policy in ca_policies:
                if policy.get("state") == "enabled":
                    # Check if policy requires MFA
                    grant_controls = policy.get("grantControls", {})
                    requires_mfa = "mfa" in grant_controls.get("builtInControls", [])
                    
                    # Check if policy applies to all users
                    all_users = False
                    user_config = policy.get("conditions", {}).get("users", {})
                    
                    if "includeUsers" in user_config and "all" in user_config["includeUsers"]:
                        all_users = True
                    
                    if requires_mfa:
                        mfa_ca_policies.append({
                            "id": policy.get("id"),
                            "displayName": policy.get("displayName"),
                            "applies_to_all_users": all_users
                        })
                        
                        if all_users:
                            mfa_enforced = True
        
        mfa_policy_details["ca_policies"] = mfa_ca_policies
        
        # Check per-user MFA registration
        if "error" not in per_user_mfa and "value" in per_user_mfa:
            total_users = len(per_user_mfa["value"])
            mfa_registered = sum(1 for user in per_user_mfa["value"] 
                               if user.get("isMfaRegistered", False))
            
            mfa_policy_details["per_user_stats"] = {
                "total_users": total_users,
                "mfa_registered": mfa_registered,
                "mfa_percentage": round((mfa_registered / total_users) * 100, 1) if total_users > 0 else 0
            }
        
        return CheckResult(
            name="MFA Enforcement",
            description="Checks if multi-factor authentication is enforced for all users",
            severity=CheckSeverity.CRITICAL,
            passed=mfa_enforced,
            details=mfa_policy_details,
            recommendation="Configure conditional access policies to require MFA for all users across all applications",
            reference_url="https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-getstarted"
        )

    def check_legacy_auth_blocked(self) -> CheckResult:
        """Check if legacy authentication protocols are blocked.
        
        Returns:
            CheckResult with findings
        """
        # Get conditional access policies
        ca_policies = self.client.get_all("identity/conditionalAccess/policies")
        
        # Get authentication methods policy
        auth_methods_policy = self.client.get("policies/authenticationMethodsPolicy")
        
        legacy_auth_blocked = False
        policy_details = {}
        
        # Check authentication methods policy
        if "error" not in auth_methods_policy:
            legacy_auth_settings = auth_methods_policy.get("policyMigration", {})
            policy_details["auth_methods_policy"] = {
                "legacy_auth_blocked": legacy_auth_settings.get("state") == "migrated"
            }
            
            if legacy_auth_settings.get("state") == "migrated":
                legacy_auth_blocked = True
        
        # Check conditional access policies
        legacy_auth_policies = []
        if "error" not in ca_policies:
            for policy in ca_policies:
                if policy.get("state") == "enabled":
                    # Check if policy targets legacy authentication
                    conditions = policy.get("conditions", {})
                    client_apps = conditions.get("clientAppTypes", [])
                    
                    targets_legacy = "exchangeActiveSync" in client_apps or "other" in client_apps
                    
                    # Check if policy blocks access
                    blocks_access = False
                    grant_controls = policy.get("grantControls", {})
                    
                    if grant_controls.get("operator") == "OR" and "block" in grant_controls.get("builtInControls", []):
                        blocks_access = True
                    
                    # Check if policy applies to all users
                    all_users = False
                    user_config = policy.get("conditions", {}).get("users", {})
                    
                    if "includeUsers" in user_config and "all" in user_config["includeUsers"]:
                        all_users = True
                    
                    if targets_legacy and blocks_access:
                        legacy_auth_policies.append({
                            "id": policy.get("id"),
                            "displayName": policy.get("displayName"),
                            "applies_to_all_users": all_users
                        })
                        
                        if all_users:
                            legacy_auth_blocked = True
        
        policy_details["ca_policies"] = legacy_auth_policies
        
        return CheckResult(
            name="Legacy Authentication Blocked",
            description="Checks if legacy authentication protocols are blocked",
            severity=CheckSeverity.HIGH,
            passed=legacy_auth_blocked,
            details=policy_details,
            recommendation="Configure conditional access policies to block legacy authentication protocols",
            reference_url="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication"
        )

    def check_password_policy(self) -> CheckResult:
        """Check if password policy meets security recommendations.
        
        Returns:
            CheckResult with findings
        """
        # Get password policy
        auth_policy = self.client.get("policies/authenticationMethodsPolicy")
        
        policy_details = {}
        passed = False
        
        if "error" not in auth_policy:
            password_policy = auth_policy.get("passwordAuthenticationMethod", {}).get("policy", {})
            
            policy_details = {
                "complexity_enabled": password_policy.get("enablePasswordReuseCheck", False),
                "length_enforced": password_policy.get("enforceCustomPasswordLength", False),
                "min_length": password_policy.get("minimumCustomPasswordLength", 0),
            }
            
            # Check if policy meets recommendations
            passed = (
                policy_details["complexity_enabled"] and
                policy_details["length_enforced"] and
                policy_details["min_length"] >= 12
            )
        
        return CheckResult(
            name="Password Policy",
            description="Checks if password policy meets security recommendations",
            severity=CheckSeverity.MEDIUM,
            passed=passed,
            details=policy_details,
            recommendation="Configure password policy to require complexity, enforce minimum length of 12 characters, and prevent password reuse",
            reference_url="https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad"
        )

    def check_conditional_access(self) -> CheckResult:
        """Check if conditional access policies are configured.
        
        Returns:
            CheckResult with findings
        """
        # Get conditional access policies
        ca_policies = self.client.get_all("identity/conditionalAccess/policies")
        
        policy_details = {
            "total_policies": 0,
            "enabled_policies": 0,
            "key_security_policies": {
                "mfa_required": False,
                "location_based": False,
                "device_compliance": False,
                "risk_based": False
            }
        }
        
        if "error" not in ca_policies:
            policy_details["total_policies"] = len(ca_policies)
            policy_details["enabled_policies"] = sum(1 for p in ca_policies if p.get("state") == "enabled")
            
            # Check for key security policies
            for policy in ca_policies:
                if policy.get("state") != "enabled":
                    continue
                    
                # Check for MFA requirement
                grant_controls = policy.get("grantControls", {})
                if "mfa" in grant_controls.get("builtInControls", []):
                    policy_details["key_security_policies"]["mfa_required"] = True
                
                # Check for location-based conditions
                conditions = policy.get("conditions", {})
                if "locations" in conditions and conditions["locations"].get("includeLocations"):
                    policy_details["key_security_policies"]["location_based"] = True
                
                # Check for device compliance requirement
                if "deviceComplianceNonCompliant" in grant_controls.get("builtInControls", []):
                    policy_details["key_security_policies"]["device_compliance"] = True
                
                # Check for risk-based policies
                if (
                    "signInRiskLevels" in conditions or
                    "userRiskLevels" in conditions
                ):
                    policy_details["key_security_policies"]["risk_based"] = True
        
        # Policy is considered sufficiently configured if there are enabled policies
        # covering at least 2 of the key security areas
        key_policies_count = sum(1 for value in policy_details["key_security_policies"].values() if value)
        passed = policy_details["enabled_policies"] > 0 and key_policies_count >= 2
        
        return CheckResult(
            name="Conditional Access Policies",
            description="Checks if conditional access policies are properly configured",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=policy_details,
            recommendation="Configure comprehensive conditional access policies including MFA, location-based, device compliance, and risk-based policies",
            reference_url="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview"
        )
    
    def check_pim_usage(self) -> CheckResult:
        """Check if Privileged Identity Management (PIM) is used.
        
        Returns:
            CheckResult with findings
        """
        # Check for PIM role assignments
        pim_assignments = self.client.get("roleManagement/directory/roleAssignmentScheduleInstances")
        
        policy_details = {
            "pim_enabled": False,
            "total_assignments": 0,
            "just_in_time": 0,
            "permanent": 0
        }
        
        if "error" not in pim_assignments and "value" in pim_assignments:
            policy_details["total_assignments"] = len(pim_assignments["value"])
            
            for assignment in pim_assignments["value"]:
                if assignment.get("assignmentType") == "Eligible":
                    policy_details["just_in_time"] += 1
                else:
                    policy_details["permanent"] += 1
            
            policy_details["pim_enabled"] = policy_details["just_in_time"] > 0
        
        return CheckResult(
            name="Privileged Identity Management",
            description="Checks if Privileged Identity Management (PIM) is used for just-in-time access",
            severity=CheckSeverity.MEDIUM,
            passed=policy_details["pim_enabled"],
            details=policy_details,
            recommendation="Configure Privileged Identity Management for just-in-time access to privileged roles",
            reference_url="https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure"
        )
    
    def check_guest_access(self) -> CheckResult:
        """Check if guest user access is properly restricted.
        
        Returns:
            CheckResult with findings
        """
        # Get external collaboration settings
        external_collab = self.client.get("policies/authorizationPolicy")
        
        policy_details = {
            "guest_invite_restrictions": "unknown",
            "guest_access_restrictions": "unknown"
        }
        
        passed = False
        
        if "error" not in external_collab:
            # Check invite restrictions
            invite_setting = external_collab.get("allowInvitesFrom", "everyone")
            policy_details["guest_invite_restrictions"] = invite_setting
            
            # Check access restrictions
            access_setting = external_collab.get("guestUserRoleId", "")
            restricted_access = access_setting != "a0b1b346-4d3e-4e8b-98f8-753987be4970"  # Global Guest User role
            policy_details["guest_access_restrictions"] = "restricted" if restricted_access else "full_access"
            
            # Check for conditional access policies targeting guests
            ca_policies = self.client.get_all("identity/conditionalAccess/policies")
            has_guest_policies = False
            
            if "error" not in ca_policies:
                for policy in ca_policies:
                    if policy.get("state") != "enabled":
                        continue
                        
                    user_config = policy.get("conditions", {}).get("users", {})
                    if "includeGuestsOrExternalUsers" in user_config:
                        has_guest_policies = True
                        break
            
            policy_details["has_guest_specific_policies"] = has_guest_policies
            
            # Check is passed if guest invites are restricted and either access is restricted
            # or there are specific conditional access policies for guests
            passed = (
                invite_setting != "everyone" and
                (restricted_access or has_guest_policies)
            )
        
        return CheckResult(
            name="Guest Access Restrictions",
            description="Checks if guest user access is properly restricted",
            severity=CheckSeverity.MEDIUM,
            passed=passed,
            details=policy_details,
            recommendation="Restrict guest invitations to administrators or users in specific roles, and implement conditional access policies specific to guest users",
            reference_url="https://docs.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings"
        )
    
    def check_admin_mfa(self) -> CheckResult:
        """Check if MFA is enforced for all administrators.
        
        Returns:
            CheckResult with findings
        """
        # Get admin users
        admin_roles = [
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # Exchange Administrator
            "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
            "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
        ]
        
        admin_users = []
        for role_id in admin_roles:
            role_members = self.client.get(f"directoryRoles/roleTemplateId={role_id}/members")
            if "error" not in role_members and "value" in role_members:
                admin_users.extend(role_members["value"])
        
        # Deduplicate admins that have multiple roles
        unique_admins = {user.get("id"): user for user in admin_users}.values()
        
        # Check if admins have MFA registered
        mfa_status = {}
        for admin in unique_admins:
            user_id = admin.get("id")
            mfa_methods = self.client.get(f"users/{user_id}/authentication/methods")
            
            has_mfa = False
            if "error" not in mfa_methods and "value" in mfa_methods:
                # Check for MFA methods (excluding password)
                mfa_types = [m.get("@odata.type") for m in mfa_methods["value"]]
                has_mfa = any(t for t in mfa_types if "password" not in t.lower())
            
            mfa_status[user_id] = {
                "displayName": admin.get("displayName"),
                "userPrincipalName": admin.get("userPrincipalName"),
                "has_mfa": has_mfa
            }
        
        # Check for conditional access policies requiring MFA for admins
        ca_policies = self.client.get_all("identity/conditionalAccess/policies")
        has_admin_mfa_policy = False
        
        if "error" not in ca_policies:
            for policy in ca_policies:
                if policy.get("state") != "enabled":
                    continue
                    
                # Check if policy requires MFA
                grant_controls = policy.get("grantControls", {})
                requires_mfa = "mfa" in grant_controls.get("builtInControls", [])
                
                if not requires_mfa:
                    continue
                
                # Check if policy targets admin roles
                conditions = policy.get("conditions", {})
                directory_roles = conditions.get("users", {}).get("includeRoles", [])
                
                targets_admins = any(role for role in directory_roles if role in admin_roles)
                
                if targets_admins:
                    has_admin_mfa_policy = True
                    break
        
        # Calculate stats
        total_admins = len(mfa_status)
        admins_with_mfa = sum(1 for data in mfa_status.values() if data["has_mfa"])
        
        details = {
            "total_admins": total_admins,
            "admins_with_mfa": admins_with_mfa,
            "mfa_percentage": round((admins_with_mfa / total_admins) * 100, 1) if total_admins > 0 else 0,
            "has_admin_mfa_policy": has_admin_mfa_policy,
            "admin_details": mfa_status
        }
        
        # Check passes if all admins have MFA or there's a CA policy requiring it
        passed = (
            (total_admins > 0 and admins_with_mfa == total_admins) or
            has_admin_mfa_policy
        )
        
        return CheckResult(
            name="Admin MFA Enforcement",
            description="Checks if multi-factor authentication is enforced for all administrators",
            severity=CheckSeverity.CRITICAL,
            passed=passed,
            details=details,
            recommendation="Configure conditional access policies to require MFA for all administrative roles and ensure all admins have MFA methods registered",
            reference_url="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa"
        )
    
    def check_privileged_roles(self) -> CheckResult:
        """Check if privileged roles are properly managed.
        
        Returns:
            CheckResult with findings
        """
        # Get privileged roles
        privileged_roles = [
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
            "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator  
            "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
            "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
            "966707d0-3269-4727-9be2-8c3a10f19b9d",  # Password Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # Exchange Administrator
        ]
        
        role_members = {}
        total_admins = 0
        
        for role_id in privileged_roles:
            role_data = self.client.get(f"directoryRoles/roleTemplateId={role_id}")
            
            if "error" not in role_data:
                role_name = role_data.get("displayName", f"Role {role_id}")
                members = self.client.get(f"directoryRoles/roleTemplateId={role_id}/members")
                
                if "error" not in members and "value" in members:
                    member_count = len(members["value"])
                    total_admins += member_count
                    
                    role_members[role_name] = {
                        "count": member_count,
                        "members": [
                            {
                                "id": m.get("id"),
                                "displayName": m.get("displayName"),
                                "userPrincipalName": m.get("userPrincipalName")
                            }
                            for m in members["value"]
                        ]
                    }
        
        # Check for PIM eligible assignments
        pim_assignments = self.client.get("roleManagement/directory/roleEligibilityScheduleInstances")
        has_pim = False
        
        if "error" not in pim_assignments and "value" in pim_assignments:
            has_pim = len(pim_assignments["value"]) > 0
        
        # Calculate the count of Global Administrators
        global_admin_count = role_members.get("Global Administrator", {}).get("count", 0)
        
        details = {
            "total_privileged_users": total_admins,
            "global_admin_count": global_admin_count,
            "uses_pim_for_eligibility": has_pim,
            "role_details": role_members
        }
        
        # Check passes if there are 2-4 Global Admins and PIM is used
        passed = (
            2 <= global_admin_count <= 4 and
            has_pim
        )
        
        return CheckResult(
            name="Privileged Role Management",
            description="Checks if privileged roles are properly managed",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Limit Global Administrators to 2-4 accounts, use PIM for just-in-time privileged access, and regularly review role assignments",
            reference_url="https://docs.microsoft.com/en-us/azure/active-directory/roles/security-planning"
        )
    
    def check_emergency_access(self) -> CheckResult:
        """Check if emergency access accounts are configured.
        
        Returns:
            CheckResult with findings
        """
        # Look for emergency access accounts
        # Convention is to look for accounts with "emergency" or "break glass" in the name
        emergency_patterns = ["emergency", "break glass", "breakglass", "emergency access"]
        
        # Search for users that might be emergency accounts
        potential_emergency_accounts = []
        
        for pattern in emergency_patterns:
            # Search by display name
            users = self.client.get(f"users?$filter=startswith(displayName,'{pattern}')")
            
            if "error" not in users and "value" in users:
                potential_emergency_accounts.extend(users["value"])
            
            # Search by UPN
            users = self.client.get(f"users?$filter=startswith(userPrincipalName,'{pattern}')")
            
            if "error" not in users and "value" in users:
                potential_emergency_accounts.extend(users["value"])
        
        # Look for service principals that might be emergency access
        service_principals = []
        for pattern in emergency_patterns:
            sp_results = self.client.get(f"servicePrincipals?$filter=startswith(displayName,'{pattern}')")
            
            if "error" not in sp_results and "value" in sp_results:
                service_principals.extend(sp_results["value"])
        
        # Deduplicate accounts
        unique_accounts = {account.get("id"): account for account in potential_emergency_accounts}.values()
        unique_sps = {sp.get("id"): sp for sp in service_principals}.values()
        
        # Verify if these accounts are administrators
        global_admin_role_id = "62e90394-69f5-4237-9190-012177145e10"
        admin_members = self.client.get(f"directoryRoles/roleTemplateId={global_admin_role_id}/members")
        
        admin_ids = []
        if "error" not in admin_members and "value" in admin_members:
            admin_ids = [m.get("id") for m in admin_members["value"]]
        
        # Check which potential emergency accounts are actually admins
        emergency_admins = [
            {
                "id": account.get("id"),
                "displayName": account.get("displayName"),
                "userPrincipalName": account.get("userPrincipalName"),
                "is_admin": account.get("id") in admin_ids
            }
            for account in unique_accounts
        ]
        
        # Filter to only include those that are actually admins
        emergency_admins = [acc for acc in emergency_admins if acc["is_admin"]]
        
        details = {
            "potential_emergency_accounts": len(unique_accounts),
            "emergency_admins": len(emergency_admins),
            "account_details": emergency_admins,
            "service_principals": len(unique_sps)
        }
        
        # Passed if at least one emergency admin account is found
        passed = len(emergency_admins) >= 1
        
        return CheckResult(
            name="Emergency Access Accounts",
            description="Checks if emergency access (break glass) accounts are configured",
            severity=CheckSeverity.HIGH,
            passed=passed,
            details=details,
            recommendation="Configure at least two emergency access accounts with Global Administrator privileges that don't rely on standard authentication methods",
            reference_url="https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access"
        )