#!/usr/bin/env python3
"""
ADSecEval - Active Directory Security Evaluation Tool.

This is the main entry point for the ADSecEval tool. It handles command-line arguments,
loads configuration, initializes assessment modules, and orchestrates the overall
assessment process.
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, Any, List, Optional

from .ad_client import ADClient
from .report import ReportGenerator
from .assessments.privileged_accounts import PrivilegedAccountsAssessment
from .assessments.password_policy import PasswordPolicyAssessment
from .assessments.domain_controllers import DomainControllerAssessment
from .assessments.trust_relationships import TrustRelationshipsAssessment
from .assessments.auth_protocols import AuthProtocolsAssessment
from .assessments.tiered_admin import TieredAdminAssessment
from .assessments.adcs import ADCSAssessment

logger = logging.getLogger(__name__)


def setup_logging(log_level: str, log_file: Optional[str] = None) -> None:
    """
    Configure logging for the application.
    
    Args:
        log_level: The desired logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to a log file
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
    
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=numeric_level,
            format=log_format,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    else:
        logging.basicConfig(
            level=numeric_level,
            format=log_format
        )


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Configuration as a dictionary
    """
    if not os.path.exists(config_path):
        logger.error(f"Configuration file not found: {config_path}")
        sys.exit(1)
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        logger.debug(f"Loaded configuration from {config_path}")
        return config
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing configuration file: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Active Directory Security Assessment Tool")
    
    parser.add_argument(
        "--config",
        type=str,
        default="config.json",
        help="Path to configuration file (default: config.json)"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        default="reports",
        help="Output directory for assessment reports (default: reports)"
    )
    
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set logging level (default: INFO)"
    )
    
    parser.add_argument(
        "--log-file",
        type=str,
        help="Path to log file (default: None, logs to console only)"
    )
    
    parser.add_argument(
        "--assessments",
        type=str,
        nargs="+",
        choices=["all", "privileged_accounts", "password_policy", "domain_controllers", 
                "trust_relationships", "auth_protocols", "tiered_admin", "adcs"],
        default=["all"],
        help="Specific assessments to run (default: all)"
    )
    
    parser.add_argument(
        "--format",
        type=str,
        choices=["html", "json", "csv"],
        default=None,
        help="Override report output format from config (default: use config setting)"
    )
    
    return parser.parse_args()


def main() -> int:
    """
    Main function.
    
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    # Parse command-line arguments
    args = parse_args()
    
    # Setup logging
    setup_logging(args.log_level, args.log_file)
    
    logger.info("Starting ADSecEval - Active Directory Security Evaluation Tool")
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Override report format if specified
        if args.format:
            if "reporting" not in config:
                config["reporting"] = {}
            config["reporting"]["formats"] = [args.format]
        
        # Create output directory if it doesn't exist
        os.makedirs(args.output, exist_ok=True)
        
        # Initialize AD client
        logger.info("Initializing Active Directory client")
        client = ADClient(config)
        
        # Connect to AD
        logger.info("Connecting to Active Directory")
        if not client.connect():
            logger.error("Failed to connect to Active Directory")
            return 1
        
        try:
            # Initialize assessments
            logger.info("Initializing assessment modules")
            assessments = []
            
            if "all" in args.assessments or "privileged_accounts" in args.assessments:
                assessments.append(PrivilegedAccountsAssessment(client, config))
            
            if "all" in args.assessments or "password_policy" in args.assessments:
                assessments.append(PasswordPolicyAssessment(client, config))
            
            if "all" in args.assessments or "domain_controllers" in args.assessments:
                assessments.append(DomainControllerAssessment(client, config))
            
            if "all" in args.assessments or "trust_relationships" in args.assessments:
                assessments.append(TrustRelationshipsAssessment(client, config))
            
            if "all" in args.assessments or "auth_protocols" in args.assessments:
                assessments.append(AuthProtocolsAssessment(client, config))
            
            if "all" in args.assessments or "tiered_admin" in args.assessments:
                assessments.append(TieredAdminAssessment(client, config))
            
            if "all" in args.assessments or "adcs" in args.assessments:
                assessments.append(ADCSAssessment(client, config))
            
            if not assessments:
                logger.error("No assessment modules selected")
                return 1
            
            # Run assessments
            logger.info("Running security assessments")
            results = {}
            
            for assessment in assessments:
                logger.info(f"Running assessment: {assessment.name}")
                assessment_result = assessment.run()
                results[assessment.name] = assessment_result
            
            # Generate report
            logger.info("Generating reports")
            report_generator = ReportGenerator(args.output, config)
            report_files = report_generator.generate(results)
            
            # Print report locations
            logger.info("Assessment complete. Reports available at:")
            for format_type, file_path in report_files.items():
                if file_path:
                    logger.info(f"  - {format_type.upper()}: {file_path}")
            
            return 0
            
        finally:
            # Always close the AD connection
            client.close()
            
    except Exception as e:
        logger.exception(f"Error during assessment: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())