"""TenetSec - M365 Tenant Security Assessment Tool."""

import argparse
import logging
import os
import sys
import json
from typing import Dict, Any, List, Type
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from .auth import GraphAuth
from .graph_client import GraphClient
from .assessments import ALL_ASSESSMENTS
from .assessments.base import AssessmentBase, CheckResult
from .report import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("tenetsec")


def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from a JSON file.
    
    Args:
        config_file: Path to config file
        
    Returns:
        Dict containing configuration
    """
    if not os.path.exists(config_file):
        logger.error(f"Config file not found: {config_file}")
        sys.exit(1)
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in config file: {config_file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading config file: {str(e)}")
        sys.exit(1)


def get_tenant_info(client: GraphClient) -> Dict[str, Any]:
    """Get information about the current tenant.
    
    Args:
        client: Authenticated GraphClient
        
    Returns:
        Dict containing tenant info
    """
    # Get the tenant info from MS Graph API
    result = client.get("organization")
    
    if "error" in result:
        logger.error(f"Failed to get tenant info: {result.get('error')}")
        return {"displayName": "Unknown Tenant", "id": "Unknown ID"}
    
    # If we have a value property, extract the first organization
    if "value" in result and len(result["value"]) > 0:
        tenant = result["value"][0]
        return {
            "displayName": tenant.get("displayName", "Unknown Tenant"),
            "id": tenant.get("id", "Unknown ID"),
            "defaultDomain": tenant.get("verifiedDomains", [{}])[0].get("name", "Unknown Domain")
        }
    
    return {"displayName": "Unknown Tenant", "id": "Unknown ID"}


def run_assessments(
    client: GraphClient,
    assessment_classes: List[Type[AssessmentBase]] = None
) -> Dict[str, List[CheckResult]]:
    """Run security assessments against the M365 tenant.
    
    Args:
        client: Authenticated GraphClient
        assessment_classes: List of assessment classes to run
        
    Returns:
        Dict mapping assessment names to lists of check results
    """
    console = Console()
    
    if assessment_classes is None:
        assessment_classes = ALL_ASSESSMENTS
    
    results = {}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Running security assessments...", total=len(assessment_classes))
        
        for assessment_class in assessment_classes:
            assessment_name = assessment_class.name
            progress.update(task, description=f"Running {assessment_name}...")
            
            try:
                # Initialize the assessment with our Graph client
                assessment = assessment_class(client)
                
                # Run the assessment
                assessment_results = assessment.run_assessment()
                
                # Store results
                results[assessment_name] = assessment_results
                
                # Display summary
                total = len(assessment_results)
                passed = sum(1 for r in assessment_results if r.passed)
                pass_rate = round((passed / total) * 100) if total > 0 else 0
                
                logger.info(f"{assessment_name}: {passed}/{total} checks passed ({pass_rate}%)")
                
            except Exception as e:
                logger.error(f"Error running {assessment_name}: {str(e)}")
                results[assessment_name] = []
            
            progress.update(task, advance=1)
    
    return results


def main():
    """Main entry point for TenetSec."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="TenetSec - Microsoft 365 Security Assessment Tool")
    
    parser.add_argument(
        "--config", 
        help="Path to configuration file",
        default="config.json"
    )
    
    parser.add_argument(
        "--output-dir",
        help="Directory to save reports",
        default="reports"
    )
    
    parser.add_argument(
        "--format",
        help="Report format (console, json, html, all)",
        choices=["console", "json", "html", "all"],
        default="all"
    )
    
    parser.add_argument(
        "--assessment",
        help="Run specific assessment(s)",
        choices=["identity", "defender", "exchange", "sharepoint", "teams", "all"],
        default="all",
        nargs="+"
    )
    
    parser.add_argument(
        "--debug",
        help="Enable debug logging",
        action="store_true"
    )
    
    args = parser.parse_args()
    
    # Set up logging
    if args.debug:
        logging.getLogger("tenetsec").setLevel(logging.DEBUG)
    
    console = Console()
    
    # Load environment variables
    load_dotenv()
    
    try:
        # Load config
        config = {}
        if os.path.exists(args.config):
            config = load_config(args.config)
        
        # Set up AI API configuration if present
        if "ai_recommendations" in config and config["ai_recommendations"].get("enabled", True):
            ai_config = config["ai_recommendations"]
            os.environ["TENETSEC_AI_API_KEY"] = ai_config.get("api_key", "")
            os.environ["TENETSEC_AI_API_ENDPOINT"] = ai_config.get("api_endpoint", "https://api.openai.com/v1/chat/completions")
            os.environ["TENETSEC_AI_API_MODEL"] = ai_config.get("api_model", "gpt-4")
        
        # Set up authentication
        auth = GraphAuth(
            tenant_id=config.get("tenant_id"),
            client_id=config.get("client_id"),
            client_secret=config.get("client_secret"),
            scopes=config.get("scopes"),
            config_file=args.config if os.path.exists(args.config) else None
        )
        
        # Initialize the Graph client
        client = GraphClient(auth)
        
        # Get tenant info
        tenant_info = get_tenant_info(client)
        console.print(f"[bold green]Connected to tenant:[/] [bold]{tenant_info['displayName']}[/]")
        
        # Determine which assessments to run
        assessment_classes = []
        if "all" in args.assessment:
            assessment_classes = ALL_ASSESSMENTS
        else:
            # Map assessment names to classes
            assessment_map = {
                "identity": next((a for a in ALL_ASSESSMENTS if a.__name__ == "IdentityAssessment"), None),
                "defender": next((a for a in ALL_ASSESSMENTS if a.__name__ == "DefenderAssessment"), None),
                "exchange": next((a for a in ALL_ASSESSMENTS if a.__name__ == "ExchangeAssessment"), None),
                "sharepoint": next((a for a in ALL_ASSESSMENTS if a.__name__ == "SharePointAssessment"), None),
                "teams": next((a for a in ALL_ASSESSMENTS if a.__name__ == "TeamsAssessment"), None),
            }
            
            for assessment_name in args.assessment:
                if assessment_name in assessment_map and assessment_map[assessment_name]:
                    assessment_classes.append(assessment_map[assessment_name])
        
        # Run the assessments
        console.print("[bold]Starting security assessment...[/]")
        results = run_assessments(client, assessment_classes)
        
        # Generate reports
        report_generator = ReportGenerator(results, tenant_info)
        
        if args.format in ["console", "all"]:
            report_generator.print_console_report()
        
        if args.format in ["json", "all"]:
            json_path = report_generator.save_json_report(args.output_dir)
            console.print(f"[green]JSON report saved to:[/] {json_path}")
        
        if args.format in ["html", "all"]:
            html_path = report_generator.save_html_report(args.output_dir)
            console.print(f"[green]HTML report saved to:[/] {html_path}")
        
    except Exception as e:
        logger.error(f"Error running assessment: {str(e)}")
        console.print(f"[bold red]Error:[/] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()