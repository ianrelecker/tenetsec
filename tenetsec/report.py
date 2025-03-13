"""Report generation module for TenetSec."""

import json
import os
import logging
from typing import Dict, Any, List
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from .assessments.base import CheckResult, CheckSeverity
from .ai_recommendations import AIRecommendationEngine

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates security assessment reports."""

    def __init__(self, results: Dict[str, List[CheckResult]], tenant_info: Dict[str, Any]):
        """Initialize the report generator.
        
        Args:
            results: Assessment results by module name
            tenant_info: Tenant information
        """
        self.results = results
        self.tenant_info = tenant_info
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.console = Console()
        self.ai_recommendation_engine = AIRecommendationEngine(results)
        self.ai_recommendations = []
    
    def _get_summary_stats(self) -> Dict[str, Any]:
        """Calculate summary statistics for all assessments.
        
        Returns:
            Dict containing summary statistics
        """
        total_checks = 0
        passed_checks = 0
        failed_checks = 0
        
        by_severity = {
            CheckSeverity.CRITICAL: {"total": 0, "passed": 0, "failed": 0},
            CheckSeverity.HIGH: {"total": 0, "passed": 0, "failed": 0},
            CheckSeverity.MEDIUM: {"total": 0, "passed": 0, "failed": 0},
            CheckSeverity.LOW: {"total": 0, "passed": 0, "failed": 0},
            CheckSeverity.INFO: {"total": 0, "passed": 0, "failed": 0},
        }
        
        by_assessment = {}
        
        # Calculate stats
        for assessment_name, checks in self.results.items():
            assessment_total = len(checks)
            assessment_passed = sum(1 for c in checks if c.passed)
            
            by_assessment[assessment_name] = {
                "total": assessment_total,
                "passed": assessment_passed,
                "failed": assessment_total - assessment_passed,
                "pass_percentage": round((assessment_passed / assessment_total) * 100, 1) if assessment_total > 0 else 0
            }
            
            total_checks += assessment_total
            passed_checks += assessment_passed
            
            # Group by severity
            for check in checks:
                severity = check.severity
                by_severity[severity]["total"] += 1
                
                if check.passed:
                    by_severity[severity]["passed"] += 1
                else:
                    by_severity[severity]["failed"] += 1
        
        failed_checks = total_checks - passed_checks
        
        # Calculate percentages
        for severity in by_severity:
            severity_total = by_severity[severity]["total"]
            if severity_total > 0:
                by_severity[severity]["pass_percentage"] = round(
                    (by_severity[severity]["passed"] / severity_total) * 100, 1
                )
            else:
                by_severity[severity]["pass_percentage"] = 0
        
        return {
            "tenant_name": self.tenant_info.get("displayName", "Unknown Tenant"),
            "tenant_id": self.tenant_info.get("id", "Unknown ID"),
            "timestamp": self.timestamp,
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "pass_percentage": round((passed_checks / total_checks) * 100, 1) if total_checks > 0 else 0,
            "by_severity": {s.value: v for s, v in by_severity.items()},
            "by_assessment": by_assessment
        }
    
    def _get_failed_checks(self, max_items: int = 10) -> List[Dict[str, Any]]:
        """Get a list of the most severe failed checks.
        
        Args:
            max_items: Maximum number of items to return
            
        Returns:
            List of failed checks, sorted by severity
        """
        all_failures = []
        
        # Collect all failed checks
        for assessment_name, checks in self.results.items():
            for check in checks:
                if not check.passed:
                    all_failures.append({
                        "assessment": assessment_name,
                        "name": check.name,
                        "description": check.description,
                        "severity": check.severity,
                        "recommendation": check.recommendation,
                        "reference_url": check.reference_url
                    })
        
        # Sort by severity (Critical first, then High, etc.)
        severity_order = {
            CheckSeverity.CRITICAL: 0,
            CheckSeverity.HIGH: 1,
            CheckSeverity.MEDIUM: 2,
            CheckSeverity.LOW: 3,
            CheckSeverity.INFO: 4
        }
        
        all_failures.sort(key=lambda x: severity_order[x["severity"]])
        
        # Return top N items
        return all_failures[:max_items]

    def print_console_report(self) -> None:
        """Print a summary report to the console."""
        summary = self._get_summary_stats()
        
        # Print header
        self.console.print()
        self.console.print(Panel(
            Text(f"TenetSec Security Assessment Report for {summary['tenant_name']}", style="bold white"),
            style="blue"
        ))
        self.console.print()
        
        # Print summary
        self.console.print("[bold]Summary[/bold]")
        self.console.print(f"Date: {summary['timestamp']}")
        self.console.print(f"Tenant ID: {summary['tenant_id']}")
        self.console.print(f"Total Checks: {summary['total_checks']}")
        self.console.print(f"Pass Rate: {summary['pass_percentage']}% ({summary['passed_checks']} passed, {summary['failed_checks']} failed)")
        self.console.print()
        
        # Print by severity
        self.console.print("[bold]Results by Severity[/bold]")
        severity_table = Table()
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Total", justify="right")
        severity_table.add_column("Passed", justify="right")
        severity_table.add_column("Failed", justify="right")
        severity_table.add_column("Pass Rate", justify="right")
        
        severity_styles = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "blue"
        }
        
        for severity, stats in summary["by_severity"].items():
            if stats["total"] > 0:
                severity_table.add_row(
                    f"[{severity_styles.get(severity, 'white')}]{severity}[/]",
                    str(stats["total"]),
                    str(stats["passed"]),
                    str(stats["failed"]),
                    f"{stats['pass_percentage']}%"
                )
        
        self.console.print(severity_table)
        self.console.print()
        
        # Print by assessment
        self.console.print("[bold]Results by Assessment[/bold]")
        assessment_table = Table()
        assessment_table.add_column("Assessment", style="bold")
        assessment_table.add_column("Total", justify="right")
        assessment_table.add_column("Passed", justify="right")
        assessment_table.add_column("Failed", justify="right")
        assessment_table.add_column("Pass Rate", justify="right")
        
        for assessment, stats in summary["by_assessment"].items():
            # Set color based on pass rate
            color = "green"
            if stats["pass_percentage"] < 50:
                color = "red"
            elif stats["pass_percentage"] < 80:
                color = "yellow"
                
            assessment_table.add_row(
                assessment,
                str(stats["total"]),
                str(stats["passed"]),
                str(stats["failed"]),
                f"[{color}]{stats['pass_percentage']}%[/]"
            )
        
        self.console.print(assessment_table)
        self.console.print()
        
        # Print top failures
        top_failures = self._get_failed_checks(10)
        
        if top_failures:
            self.console.print("[bold]Priority Findings[/bold]")
            
            for i, failure in enumerate(top_failures, 1):
                severity = failure["severity"].value
                severity_style = severity_styles.get(severity, "white")
                
                self.console.print(Panel(
                    f"[bold]{i}. {failure['name']}[/bold]\n"
                    f"Assessment: {failure['assessment']}\n"
                    f"Severity: [{severity_style}]{severity}[/]\n"
                    f"Description: {failure['description']}\n"
                    f"Recommendation: {failure['recommendation']}\n"
                    f"Reference: {failure['reference_url']}",
                    title=f"Finding {i}",
                    title_align="left"
                ))
            
            self.console.print()
        
        # Generate AI recommendations if not already done
        if not self.ai_recommendations:
            self.ai_recommendations = self.ai_recommendation_engine.generate_recommendations()
        
        # Print AI recommendations
        if self.ai_recommendations:
            self.console.print("[bold]AI-Powered Recommendations[/bold]")
            
            effort_styles = {
                "Low": "green",
                "Medium": "yellow",
                "High": "red"
            }
            
            impact_styles = {
                "Low": "green",
                "Medium": "yellow",
                "High": "red"
            }
            
            for i, rec in enumerate(self.ai_recommendations[:5], 1):  # Show top 5
                effort_style = effort_styles.get(rec["effort"], "white")
                impact_style = impact_styles.get(rec["impact"], "white")
                
                self.console.print(Panel(
                    f"[bold]{i}. {rec.get('title', f'Recommendation {i}')}[/bold]\n"
                    f"Confidence: {rec.get('confidence', 90)}%\n"
                    f"Effort: [{effort_style}]{rec['effort']}[/] | Impact: [{impact_style}]{rec['impact']}[/]\n"
                    f"Context: {rec['context']}\n"
                    f"Implementation Steps: {rec['solution']}",
                    title=f"Recommendation {i}",
                    title_align="left"
                ))
            
            self.console.print()
        
        # Print footer
        self.console.print(Panel(
            "Generated with TenetSec - Microsoft 365 Security Assessment Tool",
            style="blue"
        ))
        self.console.print()

    def save_json_report(self, output_dir: str = "reports") -> str:
        """Save a JSON report to file.
        
        Args:
            output_dir: Directory to save the report
            
        Returns:
            Path to the saved report
        """
        summary = self._get_summary_stats()
        
        # Prepare report data
        report_data = {
            "summary": summary,
            "findings": {}
        }
        
        # Add detailed findings
        for assessment_name, checks in self.results.items():
            report_data["findings"][assessment_name] = []
            
            for check in checks:
                # Convert Enum to string for JSON serialization
                check_data = {
                    "name": check.name,
                    "description": check.description,
                    "severity": check.severity.value,
                    "passed": check.passed,
                    "details": check.details,
                    "recommendation": check.recommendation,
                    "reference_url": check.reference_url
                }
                
                report_data["findings"][assessment_name].append(check_data)
        
        # Generate and add AI recommendations
        self.ai_recommendations = self.ai_recommendation_engine.generate_recommendations()
        report_data["ai_recommendations"] = self.ai_recommendations
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Save to file
        tenant_name = self.tenant_info.get("displayName", "unknown_tenant")
        tenant_name = tenant_name.lower().replace(" ", "_")
        
        filename = f"{output_dir}/tenetsec_report_{tenant_name}_{self.timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"JSON report saved to {filename}")
        
        return filename

    def save_html_report(self, output_dir: str = "reports") -> str:
        """Save an HTML report to file.
        
        Args:
            output_dir: Directory to save the report
            
        Returns:
            Path to the saved report
        """
        summary = self._get_summary_stats()
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Create dataframes for plotting
        severity_df = pd.DataFrame([
            {
                "Severity": severity,
                "Passed": stats["passed"],
                "Failed": stats["failed"]
            }
            for severity, stats in summary["by_severity"].items()
            if stats["total"] > 0
        ])
        
        assessment_df = pd.DataFrame([
            {
                "Assessment": assessment,
                "Passed": stats["passed"],
                "Failed": stats["failed"]
            }
            for assessment, stats in summary["by_assessment"].items()
        ])
        
        # Set up the page
        plt.figure(figsize=(12, 16))
        
        # Severity plot
        plt.subplot(3, 1, 1)
        severity_pivot = severity_df.melt(id_vars=["Severity"], var_name="Status", value_name="Count")
        sns.barplot(data=severity_pivot, x="Severity", y="Count", hue="Status", palette={"Passed": "green", "Failed": "red"})
        plt.title("Results by Severity")
        plt.tight_layout()
        
        # Assessment plot
        plt.subplot(3, 1, 2)
        assessment_pivot = assessment_df.melt(id_vars=["Assessment"], var_name="Status", value_name="Count")
        sns.barplot(data=assessment_pivot, x="Assessment", y="Count", hue="Status", palette={"Passed": "green", "Failed": "red"})
        plt.title("Results by Assessment")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        
        # Overall summary plot
        plt.subplot(3, 1, 3)
        plt.pie(
            [summary["passed_checks"], summary["failed_checks"]],
            labels=["Passed", "Failed"],
            colors=["green", "red"],
            autopct="%1.1f%%",
            startangle=90
        )
        plt.title(f"Overall Pass Rate: {summary['pass_percentage']}%")
        plt.tight_layout()
        
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>TenetSec Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2, h3 {{ color: #0078d4; }}
                .summary {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; }}
                .critical {{ background-color: #d13438; }}
                .high {{ background-color: #ff8c00; }}
                .medium {{ background-color: #ffd700; color: black; }}
                .low {{ background-color: #107c10; }}
                .info {{ background-color: #0078d4; }}
                .passed {{ color: green; font-weight: bold; }}
                .failed {{ color: red; font-weight: bold; }}
                .passed-row {{ background-color: rgba(0, 128, 0, 0.05); }}
                .failed-row {{ background-color: rgba(255, 0, 0, 0.05); }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #0078d4; color: white; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .findings {{ margin-top: 30px; }}
                .finding {{ border: 1px solid #ddd; padding: 10px; margin-bottom: 10px; border-radius: 5px; }}
                .plot {{ text-align: center; margin: 30px 0; }}
                .plot img {{ max-width: 100%; height: auto; }}
                
                /* Tabs styling */
                .tabs {{ margin-top: 30px; }}
                .tab-links {{ margin: 0; padding: 0; list-style: none; display: flex; border-bottom: 1px solid #ddd; }}
                .tab-links li {{ margin-right: 5px; }}
                .tab-links a {{ padding: 10px 15px; display: inline-block; border: 1px solid #ddd; 
                               border-bottom: none; border-radius: 3px 3px 0 0; text-decoration: none; 
                               color: #333; background: #f5f5f5; }}
                .tab-links li.active a {{ background: #0078d4; color: white; }}
                .tab-content {{ padding: 15px; border: 1px solid #ddd; border-top: none; }}
                .tab {{ display: none; }}
                .tab.active {{ display: block; }}
                
                /* AI Recommendations styling */
                .ai-recommendations {{ margin: 20px 0; }}
                .ai-recommendation {{ background-color: #f8f9fa; border: 1px solid #ddd; 
                                     border-radius: 8px; padding: 20px; margin-bottom: 25px;
                                     box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .ai-recommendation h3 {{ margin-top: 0; color: #0078d4; font-size: 18px;
                                        border-bottom: 1px solid #e0e0e0; padding-bottom: 8px; }}
                .recommendation-details {{ display: flex; flex-direction: column; }}
                .recommendation-metadata {{ display: flex; margin-bottom: 15px; flex-wrap: wrap; }}
                .recommendation-metadata span {{ margin-right: 15px; padding: 5px 10px; border-radius: 3px;
                                              font-size: 0.9em; margin-bottom: 5px; font-weight: bold; }}
                .confidence {{ background-color: #007bff; color: white; }}
                .effort.low, .impact.low {{ background-color: #28a745; color: white; }}
                .effort.medium, .impact.medium {{ background-color: #ffc107; color: black; }}
                .effort.high, .impact.high {{ background-color: #dc3545; color: white; }}
                .recommendation-content {{ background-color: white; padding: 15px; border-radius: 5px;
                                        border-left: 4px solid #0078d4; line-height: 1.5; }}
                .recommendation-content p, .recommendation-content div {{ margin-bottom: 12px; }}
                .recommendation-content strong {{ color: #0078d4; }}
            </style>
        </head>
        <body>
            <h1>TenetSec Security Assessment Report</h1>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Tenant:</strong> {summary['tenant_name']} ({summary['tenant_id']})</p>
                <p><strong>Date:</strong> {summary['timestamp']}</p>
                <p><strong>Overall Pass Rate:</strong> <span class="{'passed' if summary['pass_percentage'] >= 80 else 'failed'}">{summary['pass_percentage']}%</span> ({summary['passed_checks']} passed, {summary['failed_checks']} failed out of {summary['total_checks']} checks)</p>
            </div>
            
            <h2>Results by Severity</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Total</th>
                    <th>Passed</th>
                    <th>Failed</th>
                    <th>Pass Rate</th>
                </tr>
        """
        
        for severity, stats in summary["by_severity"].items():
            if stats["total"] > 0:
                severity_class = severity.lower()
                html_content += f"""
                <tr>
                    <td><span class="severity {severity_class}">{severity}</span></td>
                    <td>{stats['total']}</td>
                    <td>{stats['passed']}</td>
                    <td>{stats['failed']}</td>
                    <td class="{'passed' if stats['pass_percentage'] >= 80 else 'failed'}">{stats['pass_percentage']}%</td>
                </tr>
                """
        
        html_content += """
            </table>
            
            <h2>Results by Assessment</h2>
            <table>
                <tr>
                    <th>Assessment</th>
                    <th>Total</th>
                    <th>Passed</th>
                    <th>Failed</th>
                    <th>Pass Rate</th>
                </tr>
        """
        
        for assessment, stats in summary["by_assessment"].items():
            html_content += f"""
            <tr>
                <td>{assessment}</td>
                <td>{stats['total']}</td>
                <td>{stats['passed']}</td>
                <td>{stats['failed']}</td>
                <td class="{'passed' if stats['pass_percentage'] >= 80 else 'failed'}">{stats['pass_percentage']}%</td>
            </tr>
            """
        
        html_content += """
            </table>
            
            <div class="plot">
                <img src="data:image/png;base64,
        """
        
        # Save the plot to a temporary file
        plot_filename = f"{output_dir}/temp_plot.png"
        plt.savefig(plot_filename, format="png", bbox_inches="tight")
        plt.close()
        
        # Embed the plot as base64
        import base64
        with open(plot_filename, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode()
        
        html_content += encoded_string
        
        html_content += """
                " alt="Security Assessment Results">
            </div>
            
            <h2>Priority Findings</h2>
            <div class="findings">
        """
        
        # Add top failures
        top_failures = self._get_failed_checks()
        
        for failure in top_failures:
            severity = failure["severity"].value
            severity_class = severity.lower()
            
            html_content += f"""
            <div class="finding">
                <h3>{failure['name']}</h3>
                <p><strong>Assessment:</strong> {failure['assessment']}</p>
                <p><strong>Severity:</strong> <span class="severity {severity_class}">{severity}</span></p>
                <p><strong>Description:</strong> {failure['description']}</p>
                <p><strong>Recommendation:</strong> {failure['recommendation']}</p>
                <p><strong>Reference:</strong> <a href="{failure['reference_url']}" target="_blank">{failure['reference_url']}</a></p>
            </div>
            """
        
        html_content += """
            </div>
            
            <h2>AI-Powered Recommendations</h2>
            <p>Based on the assessment results, we recommend the following actions to improve your security posture:</p>
            
            <div class="ai-recommendations">
        """
        
        # Add AI recommendations
        if self.ai_recommendations:
            # Show all recommendations
            for i, rec in enumerate(self.ai_recommendations, 1):
                effort_class = rec["effort"].lower()
                impact_class = rec["impact"].lower()
                
                # Convert newlines in solution to HTML line breaks
                solution_html = rec["solution"].replace('\n', '<br>')
                
                html_content += f"""
                <div class="ai-recommendation">
                    <h3>{i}. {rec.get("title", f"Recommendation {i}")}</h3>
                    <div class="recommendation-details">
                        <div class="recommendation-metadata">
                            <span class="confidence">Confidence: {rec.get("confidence", 90)}%</span>
                            <span class="effort {effort_class}">Effort: {rec["effort"]}</span>
                            <span class="impact {impact_class}">Impact: {rec["impact"]}</span>
                        </div>
                        <div class="recommendation-content">
                            <p><strong>Context:</strong> {rec["context"]}</p>
                            <div><strong>Implementation Steps:</strong><br> {solution_html}</div>
                        </div>
                    </div>
                </div>
                """
        else:
            html_content += """
            <p>No AI recommendations generated. This could be because all checks passed or because there were no clear patterns in the failed checks.</p>
            """
            
        html_content += """
            </div>
            
            <h2>All Findings</h2>
            <p>Below is a complete list of all checks performed during the assessment.</p>
        """
        
        # Add tabs for each assessment module
        html_content += """
            <div class="tabs">
                <ul class="tab-links">
        """
        
        # Generate tabs for each assessment
        for i, assessment_name in enumerate(self.results.keys()):
            active_class = "active" if i == 0 else ""
            html_content += f"""
                <li class="{active_class}"><a href="#{assessment_name.replace(' ', '_')}">{assessment_name}</a></li>
            """
            
        html_content += """
                </ul>
                
                <div class="tab-content">
        """
        
        # Generate content for each tab
        for i, (assessment_name, checks) in enumerate(self.results.items()):
            active_class = "active" if i == 0 else ""
            assessment_id = assessment_name.replace(' ', '_')
            
            html_content += f"""
                <div id="{assessment_id}" class="tab {active_class}">
                    <h3>{assessment_name}</h3>
                    <table>
                        <tr>
                            <th>Status</th>
                            <th>Severity</th>
                            <th>Check</th>
                            <th>Description</th>
                            <th>Recommendation</th>
                            <th>Reference</th>
                        </tr>
            """
            
            # Sort checks by severity and then by status (failed first)
            severity_order = {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "INFO": 4
            }
            
            sorted_checks = sorted(checks, 
                                  key=lambda x: (severity_order.get(x.severity.value, 999), 
                                                x.passed))
            
            for check in sorted_checks:
                severity = check.severity.value
                severity_class = severity.lower()
                status_class = "passed" if check.passed else "failed"
                status_text = "PASS" if check.passed else "FAIL"
                
                # Handle reference URL - create link if present
                reference_link = ""
                if check.reference_url:
                    reference_link = f'<a href="{check.reference_url}" target="_blank">Documentation</a>'
                
                html_content += f"""
                        <tr class="{status_class}-row">
                            <td class="{status_class}">{status_text}</td>
                            <td><span class="severity {severity_class}">{severity}</span></td>
                            <td>{check.name}</td>
                            <td>{check.description}</td>
                            <td>{check.recommendation}</td>
                            <td>{reference_link}</td>
                        </tr>
                """
                
            html_content += """
                    </table>
                </div>
            """
            
        html_content += """
                </div>
            </div>
            
            <footer>
                <p style="text-align: center; margin-top: 30px; color: #666;">
                    Generated with TenetSec - Microsoft 365 Security Assessment Tool
                </p>
            </footer>
            <script>
                // Simple tabs functionality
                document.addEventListener('DOMContentLoaded', function() {
                    const tabs = document.querySelectorAll('.tab-links a');
                    tabs.forEach(tab => {
                        tab.addEventListener('click', function(e) {
                            e.preventDefault();
                            
                            // Remove active class from all tabs and content
                            document.querySelectorAll('.tab-links li').forEach(li => {
                                li.classList.remove('active');
                            });
                            document.querySelectorAll('.tab-content .tab').forEach(content => {
                                content.classList.remove('active');
                            });
                            
                            // Add active class to current tab and content
                            this.parentElement.classList.add('active');
                            document.querySelector(this.getAttribute('href')).classList.add('active');
                        });
                    });
                });
            </script>
        </body>
        </html>
        """
        
        # Save to file
        tenant_name = self.tenant_info.get("displayName", "unknown_tenant")
        tenant_name = tenant_name.lower().replace(" ", "_")
        
        filename = f"{output_dir}/tenetsec_report_{tenant_name}_{self.timestamp}.html"
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        # Remove temporary plot file
        if os.path.exists(plot_filename):
            os.remove(plot_filename)
        
        logger.info(f"HTML report saved to {filename}")
        
        return filename