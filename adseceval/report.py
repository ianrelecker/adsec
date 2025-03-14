"""
Report generation module for Active Directory security assessments.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
import html

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates security assessment reports in various formats."""
    
    def __init__(self, output_dir: str, config: Dict[str, Any]):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory where reports will be saved
            config: Report configuration options
        """
        self.output_dir = output_dir
        self.config = config
        self.report_formats = config.get("reporting", {}).get("formats", ["html"])
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
    
    def generate(self, assessment_results: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate reports for assessment results.
        
        Args:
            assessment_results: Results from security assessments
            
        Returns:
            Dictionary mapping report formats to file paths
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_files = {}
        
        for format_type in self.report_formats:
            if format_type.lower() == "html":
                report_path = self._generate_html_report(assessment_results, timestamp)
                report_files["html"] = report_path
            elif format_type.lower() == "json":
                report_path = self._generate_json_report(assessment_results, timestamp)
                report_files["json"] = report_path
            elif format_type.lower() == "csv":
                report_path = self._generate_csv_report(assessment_results, timestamp)
                report_files["csv"] = report_path
            elif format_type.lower() == "pdf":
                # PDF generation would require additional dependencies
                logger.warning("PDF report generation is not implemented yet")
                report_files["pdf"] = None
            else:
                logger.warning(f"Unsupported report format: {format_type}")
        
        return report_files
    
    def _generate_html_report(self, assessment_results: Dict[str, Any], timestamp: str) -> str:
        """
        Generate an HTML report.
        
        Args:
            assessment_results: Results from security assessments
            timestamp: Timestamp for the report filename
            
        Returns:
            Path to the generated report
        """
        report_file = os.path.join(self.output_dir, f"adseceval_report_{timestamp}.html")
        
        # Generate HTML content
        html_content = self._generate_html_content(assessment_results)
        
        # Write to file
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {report_file}")
        return report_file
    
    def _generate_html_content(self, assessment_results: Dict[str, Any]) -> str:
        """
        Generate HTML content for the report.
        
        Args:
            assessment_results: Results from security assessments
            
        Returns:
            HTML content as a string
        """
        # Calculate summary statistics
        total_checks = 0
        total_passed = 0
        total_failed = 0
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0
        }
        
        for assessment_name, assessment in assessment_results.items():
            for check in assessment.get("checks", []):
                total_checks += 1
                if check.get("passed", False):
                    total_passed += 1
                else:
                    total_failed += 1
                    severity = check.get("severity", "Informational")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Start building HTML
        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "    <meta charset='UTF-8'>",
            "    <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            "    <title>Active Directory Security Assessment Report</title>",
            "    <style>",
            "        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }",
            "        h1, h2, h3 { color: #0066cc; }",
            "        h1 { border-bottom: 2px solid #0066cc; padding-bottom: 10px; }",
            "        .summary-box { background-color: #f5f5f5; border-radius: 5px; padding: 15px; margin: 20px 0; }",
            "        .remediation-box { background-color: #fff8e1; border-radius: 5px; padding: 15px; margin: 20px 0; border-left: 5px solid #ffa000; }",
            "        .remediation-list li { margin-bottom: 12px; line-height: 1.4; }",
            "        .severity-critical { color: #d32f2f; }",
            "        .severity-high { color: #f57c00; }",
            "        .severity-medium { color: #fbc02d; }",
            "        .severity-low { color: #388e3c; }",
            "        .severity-info { color: #0288d1; }",
            "        .status-passed { color: #388e3c; font-weight: bold; }",
            "        .status-failed { color: #d32f2f; font-weight: bold; }",
            "        table { border-collapse: collapse; width: 100%; margin: 15px 0; }",
            "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
            "        th { background-color: #f2f2f2; }",
            "        tr:nth-child(even) { background-color: #f9f9f9; }",
            "        .details-container { margin-top: 10px; border-left: 3px solid #ddd; padding-left: 10px; }",
            "        .recommendation-box { background-color: #e8f5e9; border-radius: 3px; padding: 12px; margin: 8px 0; border-left: 3px solid #388e3c; }",
            "        .reference-box { background-color: #e3f2fd; border-radius: 3px; padding: 12px; margin: 8px 0; }",
            "        .collapsible { cursor: pointer; padding: 10px; border: none; text-align: left; outline: none; width: 100%; background-color: #eeeeee; border-radius: 3px; }",
            "        .active, .collapsible:hover { background-color: #e0e0e0; }",
            "        .content { padding: 12px; display: none; overflow: hidden; background-color: #f9f9f9; margin-top: 5px; border-radius: 3px; }",
            "        #summary-chart { width: 100%; height: 300px; }",
            "        pre { white-space: pre-wrap; word-wrap: break-word; }",
            "    </style>",
            "</head>",
            "<body>",
            f"    <h1>Active Directory Security Assessment Report</h1>",
            f"    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            "    <div class='summary-box'>",
            "        <h2>Executive Summary</h2>",
            f"        <p>Total checks: {total_checks} ({total_passed} passed, {total_failed} failed)</p>",
            "        <p>Findings by severity:</p>",
            "        <ul>",
            f"            <li class='severity-critical'>Critical: {severity_counts.get('Critical', 0)}</li>",
            f"            <li class='severity-high'>High: {severity_counts.get('High', 0)}</li>",
            f"            <li class='severity-medium'>Medium: {severity_counts.get('Medium', 0)}</li>",
            f"            <li class='severity-low'>Low: {severity_counts.get('Low', 0)}</li>",
            f"            <li class='severity-info'>Informational: {severity_counts.get('Informational', 0)}</li>",
            "        </ul>",
            "    </div>",
            "    <div class='remediation-box'>",
            "        <h2>Top Remediation Recommendations</h2>",
            "        <p>The following high-priority issues should be addressed first:</p>",
            "        <ol class='remediation-list'>"
        ]
        
        # Collect critical and high severity failed checks for top remediation list
        top_remediation_items = []
        for assessment_name, assessment in assessment_results.items():
            for check in assessment.get("checks", []):
                if not check.get("passed", False):
                    severity = check.get("severity", "")
                    if severity in ["Critical", "High"]:
                        top_remediation_items.append({
                            "name": check.get("name", ""),
                            "severity": severity,
                            "recommendation": check.get("recommendation", ""),
                            "assessment": assessment.get("name", assessment_name)
                        })
        
        # Sort by severity (Critical first, then High)
        top_remediation_items.sort(key=lambda x: 0 if x["severity"] == "Critical" else 1)
        
        # Add top 5 items to remediation list
        for item in top_remediation_items[:5]:
            severity_class = "severity-critical" if item["severity"] == "Critical" else "severity-high"
            html_parts.append(f"            <li class='{severity_class}'><strong>{html.escape(item['assessment'])}: {html.escape(item['name'])}</strong> - {html.escape(item['recommendation'])}</li>")
        
        # Close the remediation list
        html_parts.append("        </ol>")
        html_parts.append("    </div>")
        
        # Add assessment results
        for assessment_name, assessment in assessment_results.items():
            html_parts.extend([
                f"    <h2>{assessment.get('name', assessment_name)}</h2>",
                f"    <p>{assessment.get('description', '')}</p>",
                "    <table>",
                "        <tr>",
                "            <th>Check</th>",
                "            <th>Status</th>",
                "            <th>Severity</th>",
                "            <th>Description</th>",
                "        </tr>"
            ])
            
            # Add checks for this assessment
            for check in assessment.get("checks", []):
                status = "PASSED" if check.get("passed", False) else "FAILED"
                status_class = "status-passed" if check.get("passed", False) else "status-failed"
                severity = check.get("severity", "Informational")
                severity_class = f"severity-{severity.lower()}"
                
                html_parts.extend([
                    "        <tr>",
                    f"            <td>{html.escape(check.get('name', ''))}</td>",
                    f"            <td class='{status_class}'>{status}</td>",
                    f"            <td class='{severity_class}'>{severity}</td>",
                    f"            <td>{html.escape(check.get('description', ''))}</td>",
                    "        </tr>"
                ])
                
                # Add details for failed checks
                if not check.get("passed", False):
                    html_parts.extend([
                        "        <tr>",
                        "            <td colspan='4'>",
                        "                <div class='details-container'>",
                        "                    <div class='recommendation-box'>",
                        f"                        <h3>🔧 Remediation Steps</h3>",
                        f"                        <p>{html.escape(check.get('recommendation', ''))}</p>",
                        "                    </div>",
                    ])
                    
                    # Add steps list if details has recommendations field
                    if check.get("details") and isinstance(check.get("details"), dict) and "recommendations" in check.get("details", {}):
                        html_parts.extend([
                            "                    <div class='recommendation-box'>",
                            "                        <h3>📋 Specific Steps</h3>",
                            "                        <ol>"
                        ])
                        
                        for rec in check.get("details", {}).get("recommendations", []):
                            html_parts.append(f"                            <li>{html.escape(rec)}</li>")
                        
                        html_parts.append("                        </ol>")
                        html_parts.append("                    </div>")
                    
                    # Add reference if available
                    if check.get("reference_url"):
                        html_parts.extend([
                            "                    <div class='reference-box'>",
                            f"                        <p><strong>📚 Reference Documentation:</strong> <a href='{check.get('reference_url')}' target='_blank'>{check.get('reference_url')}</a></p>",
                            "                    </div>"
                        ])
                    
                    # Add details button if there are details
                    if check.get("details"):
                        check_id = f"check_{assessment_name}_{check.get('name', '').replace(' ', '_').lower()}"
                        html_parts.extend([
                            f"                    <button class='collapsible'>🔍 Show Technical Details</button>",
                            f"                    <div class='content'>",
                            f"                        <pre>{html.escape(json.dumps(check.get('details', {}), indent=2, default=str))}</pre>",
                            f"                    </div>"
                        ])
                    
                    html_parts.extend([
                        "                </div>",
                        "            </td>",
                        "        </tr>"
                    ])
            
            html_parts.append("    </table>")
        
        # Close HTML and add JavaScript for collapsible sections
        html_parts.extend([
            "    <script>",
            "    var coll = document.getElementsByClassName('collapsible');",
            "    for (var i = 0; i < coll.length; i++) {",
            "        coll[i].addEventListener('click', function() {",
            "            this.classList.toggle('active');",
            "            var content = this.nextElementSibling;",
            "            if (content.style.display === 'block') {",
            "                content.style.display = 'none';",
            "            } else {",
            "                content.style.display = 'block';",
            "            }",
            "        });",
            "    }",
            "    </script>",
            "</body>",
            "</html>"
        ])
        
        return "\n".join(html_parts)
    
    def _generate_json_report(self, assessment_results: Dict[str, Any], timestamp: str) -> str:
        """
        Generate a JSON report.
        
        Args:
            assessment_results: Results from security assessments
            timestamp: Timestamp for the report filename
            
        Returns:
            Path to the generated report
        """
        report_file = os.path.join(self.output_dir, f"adseceval_report_{timestamp}.json")
        
        # Calculate summary statistics
        total_checks = 0
        total_passed = 0
        total_failed = 0
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0
        }
        
        # Add metadata and collect remediation items
        top_remediation_items = []
        for assessment_name, assessment in assessment_results.items():
            for check in assessment.get("checks", []):
                total_checks += 1
                if check.get("passed", False):
                    total_passed += 1
                else:
                    total_failed += 1
                    severity = check.get("severity", "Informational")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    top_remediation_items.append({
                        "name": check.get("name", ""),
                        "severity": severity,
                        "recommendation": check.get("recommendation", ""),
                        "reference_url": check.get("reference_url", ""),
                        "assessment": assessment.get("name", assessment_name),
                        "specific_steps": check.get("details", {}).get("recommendations", []) 
                            if isinstance(check.get("details"), dict) else []
                    })
        
        # Sort by severity (Critical first, then High, Medium, etc.)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        top_remediation_items.sort(key=lambda x: severity_order.get(x["severity"], 5))
        
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool_version": "0.1.0",
                "summary": {
                    "total_checks": total_checks,
                    "passed": total_passed,
                    "failed": total_failed,
                    "severity_counts": severity_counts
                }
            },
            "remediation_plan": top_remediation_items,
            "results": assessment_results
        }
        
        # Write to file
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {report_file}")
        return report_file
    
    def _generate_csv_report(self, assessment_results: Dict[str, Any], timestamp: str) -> str:
        """
        Generate a CSV report.
        
        Args:
            assessment_results: Results from security assessments
            timestamp: Timestamp for the report filename
            
        Returns:
            Path to the generated report
        """
        report_file = os.path.join(self.output_dir, f"adseceval_report_{timestamp}.csv")
        
        # Generate CSV rows
        csv_rows = ["Assessment,Check,Status,Severity,Description,Recommendation,Reference"]
        
        for assessment_name, assessment in assessment_results.items():
            for check in assessment.get("checks", []):
                status = "PASSED" if check.get("passed", False) else "FAILED"
                severity = check.get("severity", "Informational")
                
                # Escape CSV special characters
                name = check.get("name", "").replace(",", "\"\"").replace("\n", " ")
                description = check.get("description", "").replace(",", "\"\"").replace("\n", " ")
                recommendation = check.get("recommendation", "").replace(",", "\"\"").replace("\n", " ")
                reference = check.get("reference_url", "").replace(",", "\"\"").replace("\n", " ")
                
                csv_rows.append(f'"{assessment.get("name", assessment_name)}","{name}",{status},{severity},"{description}","{recommendation}","{reference}"')
        
        # Write to file
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("\n".join(csv_rows))
        
        logger.info(f"CSV report generated: {report_file}")
        return report_file