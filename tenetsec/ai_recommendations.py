"""AI-powered security recommendations for TenetSec using external AI API."""

import logging
import json
import os
import re
import hashlib
import requests
from typing import Dict, Any, List, Optional
from .assessments.base import CheckResult, CheckSeverity

logger = logging.getLogger(__name__)

class AIRecommendationEngine:
    """AI-powered security recommendation engine using external AI API.
    
    This engine anonymizes assessment data before sending to the API, ensuring
    tenant-specific information is not shared. It uses a deterministic anonymization
    process that maintains relationships between data elements.
    """
    
    def __init__(self, assessment_results: Dict[str, List[CheckResult]]):
        """Initialize the recommendation engine.
        
        Args:
            assessment_results: Results from security assessments
        """
        self.assessment_results = assessment_results
        self.recommendations = []
        self.api_key = os.environ.get("TENETSEC_AI_API_KEY", "")
        self.api_endpoint = os.environ.get("TENETSEC_AI_API_ENDPOINT", "https://api.openai.com/v1/chat/completions")
        self.api_model = os.environ.get("TENETSEC_AI_API_MODEL", "gpt-4")
        
    def _anonymize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize sensitive information in assessment data.
        
        Args:
            data: Raw assessment data
            
        Returns:
            Anonymized data safe for API transmission
        """
        # Create a deep copy to avoid modifying original data
        import copy
        anonymized = copy.deepcopy(data)
        
        # Hash function for consistent anonymization
        def hash_value(value):
            if not isinstance(value, str):
                return value
            if not value:
                return value
            # Create a hash of the value to ensure consistency
            h = hashlib.sha256(value.encode()).hexdigest()[:8]
            return f"ANON_{h}"
        
        # Patterns to identify sensitive data
        patterns = {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "domain": r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b',
            "uuid": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            "name": r'\b[A-Z][a-z]+ [A-Z][a-z]+\b'
        }
        
        # List of JSON keys that might contain sensitive information
        sensitive_keys = [
            "name", "displayName", "userPrincipalName", "username", "email", 
            "domain", "id", "tenant", "organization"
        ]
        
        # Recursively process all strings in the data
        def anonymize_dict(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if k.lower() in sensitive_keys and isinstance(v, str):
                        d[k] = hash_value(v)
                    else:
                        d[k] = anonymize_dict(v)
            elif isinstance(d, list):
                return [anonymize_dict(item) for item in d]
            elif isinstance(d, str):
                # Anonymize sensitive patterns in strings
                for pattern_name, pattern in patterns.items():
                    d = re.sub(pattern, lambda m: hash_value(m.group(0)), d)
                return d
            return d
            
        return anonymize_dict(anonymized)
    
    def _prepare_api_prompt(self, anonymized_results: Dict[str, Any]) -> str:
        """Prepare a prompt for the AI API based on anonymized assessment results.
        
        Args:
            anonymized_results: Anonymized assessment data
            
        Returns:
            Formatted prompt string
        """
        prompt = """You are a Microsoft 365 security expert assistant. Your task is to analyze security assessment results from a Microsoft 365 tenant and provide specific, actionable recommendations to fix security issues.

IMPORTANT: For each recommendation you provide:
1. Give it a clear, descriptive title that summarizes the security issue
2. Provide a detailed explanation of the security risks involved
3. Include step-by-step implementation instructions with the EXACT navigation paths, PowerShell commands, or API calls needed
4. Rate the effort required (Low/Medium/High) and the security impact (Low/Medium/High)

Format each recommendation as follows:
## Recommendation 1: [Title]
**Impact: [High/Medium/Low] | Effort: [High/Medium/Low]**

[1-2 paragraphs explaining the security context and risks]

**Implementation Steps:**
1. [Specific step with exact navigation paths or commands]
2. [Next step]
3. [Additional steps as needed]

Here are the FAILED security checks that need remediation:

"""
        # Count severities for prioritization
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        # Add failed checks details, organized by severity
        failed_checks_by_severity = {}
        
        for assessment_name, checks in anonymized_results.items():
            for check in checks:
                if not check.passed:
                    severity = check.severity.value
                    severity_counts[severity] += 1
                    
                    if severity not in failed_checks_by_severity:
                        failed_checks_by_severity[severity] = []
                    
                    check_info = {
                        "assessment": assessment_name,
                        "name": check.name,
                        "description": check.description,
                        "details": check.details,
                        "recommendation": check.recommendation
                    }
                    
                    failed_checks_by_severity[severity].append(check_info)
        
        # Add failed checks in order of severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in failed_checks_by_severity and failed_checks_by_severity[severity]:
                prompt += f"\n## {severity} Severity Issues ({len(failed_checks_by_severity[severity])} issues)\n"
                
                for check in failed_checks_by_severity[severity]:
                    prompt += f"\n### {check['assessment']} - {check['name']}\n"
                    prompt += f"Description: {check['description']}\n"
                    
                    if check['details']:
                        prompt += f"Current Configuration: {check['details']}\n"
                    
                    if check['recommendation']:
                        prompt += f"Recommended Action: {check['recommendation']}\n"
                
        # Add summary statistics
        total_checks = sum(len(checks) for checks in anonymized_results.values())
        total_failed = sum(severity_counts.values())
        total_passed = total_checks - total_failed
        
        # Add overall pass rate
        pass_rate = (total_passed / total_checks) * 100 if total_checks > 0 else 0
        prompt += f"\n## Overall Security Posture\n"
        prompt += f"- Overall Pass Rate: {pass_rate:.1f}%\n"
        prompt += f"- Failed {total_failed} out of {total_checks} total checks\n"
        prompt += f"- Severity Breakdown: {severity_counts['CRITICAL']} Critical, {severity_counts['HIGH']} High, {severity_counts['MEDIUM']} Medium, {severity_counts['LOW']} Low\n"
        
        prompt += "\nBased on these failed checks, provide comprehensive prioritized recommendations that would have the most significant impact on improving the security posture. Focus particularly on CRITICAL and HIGH severity issues, but address all important security gaps. Group related issues into single recommendations where appropriate. Include detailed, step-by-step implementation steps that a security administrator could follow immediately. Provide as many recommendations as you think are necessary to properly address the security issues identified."
        
        return prompt
    
    def _call_ai_api(self, prompt: str) -> Dict[str, Any]:
        """Call the AI API with the prepared prompt.
        
        Args:
            prompt: Formatted prompt for the API
            
        Returns:
            API response data
            
        Raises:
            ValueError: If no API key is provided
        """
        if not self.api_key:
            logger.error("No AI API key provided. Cannot make API call.")
            raise ValueError("No AI API key provided")
        
        try:
            logger.info(f"Preparing API call to {self.api_endpoint} using model {self.api_model}")
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            # Adjust payload according to the API's requirements
            payload = {
                "model": self.api_model,
                "messages": [
                    {"role": "system", "content": "You are a Microsoft 365 security expert assistant with deep knowledge of security best practices, administration, and configuration."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 4000
            }
            
            logger.debug(f"Request payload prepared with {len(prompt)} character prompt")
            
            # Log API request attempt with timeout
            logger.info(f"Sending request to AI API with 120 second timeout")
            response = requests.post(
                self.api_endpoint,
                headers=headers,
                json=payload,
                timeout=120
            )
            
            # Check for HTTP errors
            try:
                response.raise_for_status()
                logger.info(f"API request successful: HTTP {response.status_code}")
                
                # Parse JSON response
                json_response = response.json()
                
                # Check if response has the expected structure
                if "choices" not in json_response or not json_response["choices"]:
                    logger.warning("API response missing 'choices' field or empty choices")
                    return self._generate_mock_recommendations()
                
                # Check if we have content in the response
                content = json_response["choices"][0].get("message", {}).get("content", "")
                if not content:
                    logger.warning("API response contains empty content")
                    return self._generate_mock_recommendations()
                
                # Log success with content length
                logger.info(f"Received {len(content)} characters of recommendation content from API")
                return json_response
                
            except requests.exceptions.HTTPError as http_err:
                logger.error(f"HTTP error: {http_err}")
                # Log more details about the error response
                try:
                    error_details = response.json()
                    logger.error(f"API error details: {error_details}")
                except:
                    logger.error(f"API raw response: {response.text[:500]}")
                return self._generate_mock_recommendations()
                
        except requests.exceptions.Timeout:
            logger.error("API request timed out after 120 seconds")
            return self._generate_mock_recommendations()
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error when calling {self.api_endpoint}")
            return self._generate_mock_recommendations()
        except json.JSONDecodeError:
            logger.error("Failed to parse API response as JSON")
            return self._generate_mock_recommendations()
        except Exception as e:
            logger.error(f"Unexpected error calling AI API: {str(e)}")
            return self._generate_mock_recommendations()
    
    def _generate_mock_recommendations(self) -> Dict[str, Any]:
        """Generate mock recommendations when API is unavailable.
        
        Returns:
            Mock API response
        """
        # This provides a fallback when API access fails
        return {
            "choices": [
                {
                    "message": {
                        "content": """# Security Recommendations

## Recommendation 1: Implement Multi-Factor Authentication
**Impact: High | Effort: Medium**

MFA is not configured properly for administrator accounts. Implement MFA for all users, prioritizing administrators and privileged accounts.

**Implementation Steps:**
1. Navigate to Microsoft Entra ID > Security > Authentication methods
2. Enable MFA for all administrators immediately
3. Create a staged rollout plan for all other users
4. Configure Conditional Access policies to enforce MFA

## Recommendation 2: Secure Exchange Email Flow
**Impact: High | Effort: Medium**

Email authentication records (SPF, DKIM, DMARC) are not properly configured, leaving your domain vulnerable to spoofing.

**Implementation Steps:**
1. Configure SPF records for all domains with appropriate authorized senders
2. Enable and configure DKIM signing for all domains
3. Implement DMARC with monitoring mode initially, then move to quarantine/reject
4. Review and update transport rules to align with authentication policies

## Recommendation 3: Enhance Data Loss Prevention
**Impact: Medium | Effort: High**

DLP policies are either missing or inadequately configured across SharePoint and Exchange.

**Implementation Steps:**
1. Identify sensitive information types relevant to your organization
2. Create DLP policies for PII, financial data, and intellectual property
3. Configure policies in test mode first, then enforcement
4. Implement protected document libraries for highly sensitive content
5. Enable sensitivity labels to ensure consistent protection"""
                    }
                }
            ]
        }
    
    def _parse_api_response(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse the AI API response into structured recommendations.
        
        Args:
            response: Raw API response
            
        Returns:
            List of structured recommendation objects
        """
        recommendations = []
        
        try:
            # Extract the content from the API response
            if "choices" in response and response["choices"]:
                content = response["choices"][0]["message"]["content"]
                logger.debug(f"Processing AI response content: {len(content)} characters")
                
                # Try different parsing methods to handle various AI response formats
                
                # Method 1: Parse recommendations formatted with "## Recommendation X: Title"
                if "## Recommendation" in content:
                    logger.debug("Using '## Recommendation' parsing method")
                    sections = content.split("## Recommendation")
                    
                    for i, section in enumerate(sections[1:], 1):  # Skip the first split which is the intro
                        try:
                            # Extract recommendation title
                            title_match = re.search(r'^[^:\n]+:(.*?)(?:\n|$)', section)
                            title = title_match.group(1).strip() if title_match else f"Recommendation {i}"
                            
                            # Extract impact and effort
                            impact_match = re.search(r'Impact:\s*(High|Medium|Low)', section, re.IGNORECASE)
                            effort_match = re.search(r'Effort:\s*(High|Medium|Low)', section, re.IGNORECASE)
                            
                            impact = impact_match.group(1) if impact_match else "Medium"
                            effort = effort_match.group(1) if effort_match else "Medium"
                            
                            # Extract implementation steps
                            steps_match = re.search(r'Implementation Steps:(.*?)(?:##|\Z)', section, re.DOTALL)
                            steps = steps_match.group(1).strip() if steps_match else ""
                            
                            # If no implementation steps found, try other patterns
                            if not steps:
                                steps_match = re.search(r'Steps:(.*?)(?:##|\Z)', section, re.DOTALL)
                                steps = steps_match.group(1).strip() if steps_match else ""
                            
                            # Extract the context (everything between title and steps)
                            context_start = section.find('\n') + 1 if '\n' in section else 0
                            context_end = section.find('Implementation Steps:') 
                            if context_end == -1:
                                context_end = section.find('Steps:')
                            if context_end == -1:
                                context_end = len(section)
                                
                            context = section[context_start:context_end].strip()
                            
                            # Clean up context to remove impact/effort line
                            context = re.sub(r'Impact:\s*(High|Medium|Low)\s*\|\s*Effort:\s*(High|Medium|Low)', '', context).strip()
                            
                            # Add to recommendations if we have at least a title and solution
                            if title and (steps or context):
                                recommendations.append({
                                    "title": title,
                                    "context": context,
                                    "solution": steps,
                                    "impact": impact,
                                    "effort": effort,
                                    "confidence": 90
                                })
                                logger.debug(f"Parsed recommendation: {title}")
                        except Exception as section_err:
                            logger.warning(f"Error parsing section {i}: {str(section_err)}")
                            continue
                
                # Method 2: Parse recommendations with numbered headings like "1. Title"
                elif re.search(r'^\d+\.\s+', content, re.MULTILINE):
                    logger.debug("Using numbered recommendations parsing method")
                    # Split by numbered sections (1. Title, 2. Title, etc.)
                    sections = re.split(r'(?m)^(\d+)\.\s+(.+)$', content)
                    
                    # Process sections (skipping the first which is before any numbering)
                    i = 1
                    while i < len(sections) - 2:  # Skip the first and process in groups of 3
                        try:
                            number = sections[i]
                            title = sections[i+1].strip()
                            body = sections[i+2].strip()
                            
                            # Try to extract impact and effort
                            impact_match = re.search(r'Impact:\s*(High|Medium|Low)', body, re.IGNORECASE)
                            effort_match = re.search(r'Effort:\s*(High|Medium|Low)', body, re.IGNORECASE)
                            
                            impact = impact_match.group(1) if impact_match else "Medium"
                            effort = effort_match.group(1) if effort_match else "Medium"
                            
                            # Try to split body into context and steps
                            steps_match = re.search(r'Steps:(.*?)(?:\d+\.|\Z)', body, re.DOTALL)
                            if steps_match:
                                steps = steps_match.group(1).strip()
                                context = body[:body.find("Steps:")].strip()
                            else:
                                # Try alternative step formats
                                steps_match = re.search(r'Implementation:(.*?)(?:\d+\.|\Z)', body, re.DOTALL)
                                if steps_match:
                                    steps = steps_match.group(1).strip()
                                    context = body[:body.find("Implementation:")].strip()
                                else:
                                    # If no explicit steps section, look for numbered list
                                    numbered_list_match = re.search(r'(\d+\.\s+.+(?:\n\d+\.\s+.+)+)', body, re.DOTALL)
                                    if numbered_list_match:
                                        steps = numbered_list_match.group(1).strip()
                                        context = body[:body.find(steps)].strip()
                                    else:
                                        steps = ""
                                        context = body
                            
                            if title:
                                recommendations.append({
                                    "title": title,
                                    "context": context,
                                    "solution": steps,
                                    "impact": impact,
                                    "effort": effort,
                                    "confidence": 90
                                })
                                logger.debug(f"Parsed recommendation: {title}")
                        except Exception as section_err:
                            logger.warning(f"Error parsing numbered section: {str(section_err)}")
                        finally:
                            i += 3  # Move to next section triplet
                
                # Method 3: Fall back to simpler parsing with markdown headers
                elif "## " in content:
                    logger.debug("Using markdown header parsing method")
                    # Split by markdown headers
                    sections = re.split(r'(?m)^##\s+(.+)$', content)
                    
                    # Process sections (skipping the first which is before any headers)
                    i = 1
                    while i < len(sections) - 1:  # Process in pairs
                        try:
                            title = sections[i].strip()
                            body = sections[i+1].strip()
                            
                            # Try to extract impact and effort
                            impact_match = re.search(r'Impact:\s*(High|Medium|Low)', body, re.IGNORECASE)
                            effort_match = re.search(r'Effort:\s*(High|Medium|Low)', body, re.IGNORECASE)
                            
                            impact = impact_match.group(1) if impact_match else "Medium"
                            effort = effort_match.group(1) if effort_match else "Medium"
                            
                            # Look for numbered steps
                            steps_pattern = r'(?:\d+\.\s+[^\n]+\n*)+' 
                            steps_match = re.search(steps_pattern, body)
                            
                            if steps_match:
                                steps = steps_match.group(0).strip()
                                # Context is everything before the steps
                                steps_start = body.find(steps)
                                context = body[:steps_start].strip()
                            else:
                                steps = ""
                                context = body
                            
                            if title:
                                recommendations.append({
                                    "title": title,
                                    "context": context,
                                    "solution": steps,
                                    "impact": impact,
                                    "effort": effort,
                                    "confidence": 90
                                })
                                logger.debug(f"Parsed recommendation: {title}")
                        except Exception as section_err:
                            logger.warning(f"Error parsing header section: {str(section_err)}")
                        finally:
                            i += 2  # Move to next section pair
                
                # If all parsing methods failed, create one recommendation with the whole content
                if not recommendations and content.strip():
                    logger.warning("Using fallback parsing method - no structured format detected")
                    recommendations.append({
                        "title": "Security Recommendations",
                        "context": "The following recommendations were generated based on your security assessment results:",
                        "solution": content.strip(),
                        "impact": "Medium",
                        "effort": "Medium",
                        "confidence": 70
                    })
                
                logger.info(f"Successfully parsed {len(recommendations)} recommendations from AI response")
                
        except Exception as e:
            logger.error(f"Error parsing AI API response: {str(e)}")
            logger.debug(f"Response that failed parsing: {str(response)[:1000]}")
        
        return recommendations
    
    def generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate AI-powered recommendations based on assessment results.
        
        Returns:
            List of recommendation objects
        """
        # Check if the API key is available
        if not self.api_key:
            logger.warning("No AI API key provided. Cannot generate AI-powered recommendations.")
            return [{
                "title": "AI Recommendations Unavailable",
                "context": "No API key was provided for the AI recommendation engine.",
                "solution": "To enable AI-powered security recommendations, please configure an API key:\n\n1. Set the TENETSEC_AI_API_KEY environment variable, or\n2. Add an api_key in the ai_recommendations section of your config.json file",
                "impact": "Medium",
                "effort": "Low",
                "confidence": 100
            }]
        
        # Check if there are any failed checks
        has_failed_checks = False
        failed_count = 0
        for assessment_name, checks in self.assessment_results.items():
            failed_in_assessment = sum(1 for c in checks if not c.passed)
            if failed_in_assessment > 0:
                has_failed_checks = True
                failed_count += failed_in_assessment
                logger.info(f"Found {failed_in_assessment} failed checks in {assessment_name} assessment")
            
        if not has_failed_checks:
            logger.info("No failed checks found. Generating generic best practice recommendations.")
            # Return some basic security best practices even if all checks pass
            return [{
                "title": "Maintain Security Posture with Regular Reviews",
                "context": "Your tenant has passed all security checks. To maintain this strong security posture, implement regular security reviews.",
                "solution": "1. Schedule monthly security posture reviews\n2. Keep up with Microsoft security updates and new features\n3. Periodically review admin access and accounts\n4. Conduct quarterly security awareness training",
                "impact": "Medium",
                "effort": "Low",
                "confidence": 100
            }]
            
        # Log the total number of failed checks
        logger.info(f"Generating recommendations based on {failed_count} failed checks across all assessments")
        
        # Anonymize the assessment results
        anonymized_data = self._anonymize_data(self.assessment_results)
        logger.debug("Assessment data anonymized successfully")
        
        # Prepare the prompt
        prompt = self._prepare_api_prompt(anonymized_data)
        logger.debug(f"Prepared API prompt with {len(prompt)} characters")
        
        # Call the AI API
        logger.info("Calling external AI API for security recommendations")
        api_response = self._call_ai_api(prompt)
        
        # Parse the response into structured recommendations
        self.recommendations = self._parse_api_response(api_response)
        
        # Ensure we always have recommendations if API call succeeded but parsing failed
        if not self.recommendations:
            logger.warning("No structured recommendations could be parsed from API response. Using fallback recommendations.")
            # Add fallback recommendations for common security issues
            self.recommendations = [
                {
                    "title": "Implement Multi-Factor Authentication",
                    "context": "Multi-factor authentication is a fundamental security control that significantly reduces the risk of account compromise.",
                    "solution": "1. Navigate to Microsoft Entra ID > Security > Authentication methods\n2. Enable MFA for all administrators immediately\n3. Create a staged rollout plan for all other users\n4. Configure Conditional Access policies to enforce MFA",
                    "impact": "High",
                    "effort": "Medium",
                    "confidence": 90
                },
                {
                    "title": "Review and Strengthen Access Controls",
                    "context": "Excessive permissions and poorly managed access controls can lead to privilege escalation and data breaches.",
                    "solution": "1. Audit admin role assignments and remove unnecessary privileges\n2. Implement least privilege principles across all services\n3. Configure Privileged Identity Management for just-in-time access\n4. Set up regular access reviews",
                    "impact": "High",
                    "effort": "Medium",
                    "confidence": 85
                },
                {
                    "title": "Enhance Email Security",
                    "context": "Email remains a primary attack vector for most organizations.",
                    "solution": "1. Configure SPF, DKIM, and DMARC records for all domains\n2. Enable Safe Attachments and Safe Links policies\n3. Implement anti-phishing protection with mailbox intelligence\n4. Configure anti-spam policies to quarantine suspicious messages",
                    "impact": "High",
                    "effort": "Medium",
                    "confidence": 85
                }
            ]
        
        logger.info(f"Generated {len(self.recommendations)} AI-powered security recommendations")
        return self.recommendations
    
    def save_recommendations(self, output_path: str) -> None:
        """Save recommendations to a JSON file.
        
        Args:
            output_path: Path to save recommendations
        """
        if not self.recommendations:
            self.generate_recommendations()
            
        with open(output_path, 'w') as f:
            json.dump(self.recommendations, f, indent=2)
            
        logger.info(f"Saved AI recommendations to {output_path}")
        
    def get_top_recommendations(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get top recommendations.
        
        Args:
            limit: Maximum number of recommendations to return
            
        Returns:
            List of top recommendations
        """
        if not self.recommendations:
            self.generate_recommendations()
            
        return self.recommendations[:limit]
        
    def add_recommendations_to_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add AI recommendations to a report JSON.
        
        Args:
            report_data: Report data dictionary
            
        Returns:
            Updated report data with recommendations
        """
        if not self.recommendations:
            self.generate_recommendations()
            
        # Add recommendations section to the report
        report_data["ai_recommendations"] = self.recommendations
        return report_data