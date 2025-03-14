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
        
        # Exploitation stats
        exploitable_vulnerabilities = 0
        simulation_only_count = 0
        
        # Compliance framework tracking
        compliance_frameworks = {}
        mitre_techniques = []
        
        for assessment_name, assessment in assessment_results.items():
            for check in assessment.get("checks", []):
                total_checks += 1
                if check.get("passed", False):
                    total_passed += 1
                else:
                    total_failed += 1
                    severity = check.get("severity", "Informational")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    # Track exploitation results
                    if check.get("exploitation_results"):
                        if check.get("exploitation_results", {}).get("success", False):
                            exploitable_vulnerabilities += 1
                        if check.get("exploitation_results", {}).get("simulation_only", True):
                            simulation_only_count += 1
                    
                    # Track compliance mappings
                    if check.get("compliance_mappings"):
                        for framework, controls in check.get("compliance_mappings", {}).items():
                            if framework == "MITRE ATT&CK":
                                # Add MITRE ATT&CK techniques to the list
                                technique_list = controls if isinstance(controls, list) else [controls]
                                mitre_techniques.extend(technique_list)
                            else:
                                # Add to compliance frameworks
                                if framework not in compliance_frameworks:
                                    compliance_frameworks[framework] = {
                                        "controls": []
                                    }
                                
                                control_list = controls if isinstance(controls, list) else [controls]
                                compliance_frameworks[framework]["controls"].extend(control_list)
        
        # Deduplicate MITRE techniques and compliance controls
        mitre_techniques = list(set(mitre_techniques))
        for framework in compliance_frameworks:
            compliance_frameworks[framework]["controls"] = list(set(compliance_frameworks[framework]["controls"]))
            compliance_frameworks[framework]["control_count"] = len(compliance_frameworks[framework]["controls"])
        
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
            "        .compliance-box { background-color: #e8f4f8; border-radius: 5px; padding: 15px; margin: 20px 0; border-left: 5px solid #0066cc; }",
            "        .exploitation-box { background-color: #fbe9e7; border-radius: 5px; padding: 15px; margin: 20px 0; border-left: 5px solid #d32f2f; }",
            "        .mitre-box { background-color: #f3e5f5; border-radius: 5px; padding: 15px; margin: 20px 0; border-left: 5px solid #7b1fa2; }",
            "        .remediation-list li, .compliance-list li, .mitre-list li { margin-bottom: 12px; line-height: 1.4; }",
            "        .severity-critical { color: #d32f2f; }",
            "        .severity-high { color: #f57c00; }",
            "        .severity-medium { color: #fbc02d; }",
            "        .severity-low { color: #388e3c; }",
            "        .severity-info { color: #0288d1; }",
            "        .status-passed { color: #388e3c; font-weight: bold; }",
            "        .status-failed { color: #d32f2f; font-weight: bold; }",
            "        .exploitable { color: #d32f2f; font-weight: bold; }",
            "        .not-exploitable { color: #388e3c; font-weight: bold; }",
            "        table { border-collapse: collapse; width: 100%; margin: 15px 0; }",
            "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
            "        th { background-color: #f2f2f2; }",
            "        tr:nth-child(even) { background-color: #f9f9f9; }",
            "        .details-container { margin-top: 10px; border-left: 3px solid #ddd; padding-left: 10px; }",
            "        .recommendation-box { background-color: #e8f5e9; border-radius: 3px; padding: 12px; margin: 8px 0; border-left: 3px solid #388e3c; }",
            "        .reference-box { background-color: #e3f2fd; border-radius: 3px; padding: 12px; margin: 8px 0; }",
            "        .compliance-detail-box { background-color: #e8f4f8; border-radius: 3px; padding: 12px; margin: 8px 0; border-left: 3px solid #0066cc; }",
            "        .exploitation-detail-box { background-color: #fbe9e7; border-radius: 3px; padding: 12px; margin: 8px 0; border-left: 3px solid #d32f2f; }",
            "        .mitre-detail-box { background-color: #f3e5f5; border-radius: 3px; padding: 12px; margin: 8px 0; border-left: 3px solid #7b1fa2; }",
            "        .collapsible { cursor: pointer; padding: 10px; border: none; text-align: left; outline: none; width: 100%; background-color: #eeeeee; border-radius: 3px; }",
            "        .active, .collapsible:hover { background-color: #e0e0e0; }",
            "        .content { padding: 12px; display: none; overflow: hidden; background-color: #f9f9f9; margin-top: 5px; border-radius: 3px; }",
            "        #summary-chart { width: 100%; height: 300px; }",
            "        pre { white-space: pre-wrap; word-wrap: break-word; }",
            "        .tabs { display: flex; margin-bottom: -1px; }",
            "        .tab { padding: 10px 15px; border: 1px solid #ddd; background-color: #f8f8f8; margin-right: 5px; cursor: pointer; border-radius: 5px 5px 0 0; }",
            "        .tab.active { background-color: white; border-bottom: 1px solid white; }",
            "        .tab-content { display: none; padding: 15px; border: 1px solid #ddd; margin-top: -1px; }",
            "        .tab-content.active { display: block; }",
            "        .progress-container { width: 100%; background-color: #f1f1f1; border-radius: 5px; margin: 5px 0; }",
            "        .progress-bar { height: 20px; border-radius: 5px; text-align: center; line-height: 20px; color: white; }",
            "        .progress-bar-red { background-color: #d32f2f; }",
            "        .progress-bar-orange { background-color: #f57c00; }",
            "        .progress-bar-yellow { background-color: #fbc02d; }",
            "        .progress-bar-green { background-color: #388e3c; }",
            "        .progress-bar-blue { background-color: #0288d1; }",
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
        ]
        
        # Add exploitation summary if there are exploitation results
        if exploitable_vulnerabilities > 0 or simulation_only_count > 0:
            html_parts.extend([
                "        <div class='exploitation-detail-box'>",
                "            <h3>Exploitation Summary</h3>",
                f"            <p><strong>Confirmed Exploitable Vulnerabilities:</strong> <span class='exploitable'>{exploitable_vulnerabilities}</span></p>",
                f"            <p><strong>Simulated Exploitation Tests:</strong> {simulation_only_count}</p>",
                "        </div>"
            ])
        
        # Add compliance summary if there are compliance mappings
        if compliance_frameworks:
            html_parts.extend([
                "        <div class='compliance-detail-box'>",
                "            <h3>Compliance Summary</h3>",
                "            <table>",
                "                <tr>",
                "                    <th>Framework</th>",
                "                    <th>Failed Controls</th>",
                "                </tr>"
            ])
            
            for framework, data in compliance_frameworks.items():
                html_parts.append(f"                <tr><td>{html.escape(framework)}</td><td>{data['control_count']} controls</td></tr>")
            
            html_parts.append("            </table>")
            html_parts.append("        </div>")
        
        # Close the summary box
        html_parts.append("    </div>")
        
        # Add remediation recommendations
        html_parts.extend([
            "    <div class='remediation-box'>",
            "        <h2>Top Remediation Recommendations</h2>",
            "        <p>The following high-priority issues should be addressed first:</p>",
            "        <ol class='remediation-list'>"
        ])
        
        # Collect critical and high severity failed checks for top remediation list
        top_remediation_items = []
        for assessment_name, assessment in assessment_results.items():
            for check in assessment.get("checks", []):
                if not check.get("passed", False):
                    severity = check.get("severity", "")
                    if severity in ["Critical", "High"]:
                        exploitable = check.get("exploitation_results", {}).get("success", False)
                        
                        top_remediation_items.append({
                            "name": check.get("name", ""),
                            "severity": severity,
                            "recommendation": check.get("recommendation", ""),
                            "assessment": assessment.get("name", assessment_name),
                            "exploitable": exploitable
                        })
        
        # Sort by exploitability first, then severity
        top_remediation_items.sort(key=lambda x: (not x["exploitable"], 0 if x["severity"] == "Critical" else 1))
        
        # Add top 5 items to remediation list
        for item in top_remediation_items[:5]:
            severity_class = "severity-critical" if item["severity"] == "Critical" else "severity-high"
            exploitable_tag = " <span class='exploitable'>[EXPLOITABLE]</span>" if item["exploitable"] else ""
            
            html_parts.append(
                f"            <li class='{severity_class}'><strong>{html.escape(item['assessment'])}: "
                f"{html.escape(item['name'])}</strong>{exploitable_tag} - {html.escape(item['recommendation'])}</li>"
            )
        
        # Close the remediation list
        html_parts.append("        </ol>")
        html_parts.append("    </div>")
        
        # Add compliance frameworks section if there are mappings
        if compliance_frameworks:
            html_parts.extend([
                "    <div class='compliance-box'>",
                "        <h2>Compliance Frameworks Impact</h2>",
                "        <p>The findings in this report affect the following compliance frameworks:</p>",
                "        <div class='tabs-container'>",
                "            <div class='tabs'>"
            ])
            
            # Add tab for each framework
            for i, framework in enumerate(compliance_frameworks.keys()):
                active = " active" if i == 0 else ""
                html_parts.append(f"                <div class='tab{active}' onclick='openTab(event, \"{framework.replace(' ', '_')}_tab\")'>{html.escape(framework)}</div>")
            
            html_parts.append("            </div>")
            
            # Add content for each framework tab
            for i, (framework, data) in enumerate(compliance_frameworks.items()):
                active = " active" if i == 0 else ""
                framework_id = framework.replace(' ', '_')
                
                html_parts.extend([
                    f"            <div id='{framework_id}_tab' class='tab-content{active}'>",
                    f"                <h3>{html.escape(framework)} Controls</h3>",
                    "                <p>The following controls are affected by the findings in this report:</p>",
                    "                <ul class='compliance-list'>"
                ])
                
                # Add all controls for this framework
                for control in sorted(data["controls"]):
                    html_parts.append(f"                    <li>{html.escape(control)}</li>")
                
                html_parts.extend([
                    "                </ul>",
                    "            </div>"
                ])
            
            html_parts.append("        </div>")
            html_parts.append("    </div>")
        
        # Add MITRE ATT&CK section if there are techniques
        if mitre_techniques:
            html_parts.extend([
                "    <div class='mitre-box'>",
                "        <h2>MITRE ATT&CK Techniques</h2>",
                "        <p>The following attack techniques are relevant to the findings in this report:</p>",
                "        <ul class='mitre-list'>"
            ])
            
            # Add all MITRE techniques
            for technique in sorted(mitre_techniques):
                # Extract technique ID for URL linking
                technique_id = technique.split(":")[0].strip() if ":" in technique else technique
                url = f"https://attack.mitre.org/techniques/{technique_id}/"
                html_parts.append(f"            <li><a href='{url}' target='_blank'>{html.escape(technique)}</a></li>")
            
            html_parts.extend([
                "        </ul>",
                "    </div>"
            ])
        
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
                    
                    # Add compliance mapping if available
                    if check.get("compliance_mappings") and isinstance(check.get("compliance_mappings"), dict):
                        html_parts.extend([
                            "                    <div class='compliance-box'>",
                            "                        <h3>🔐 Compliance Impact</h3>",
                            "                        <div class='compliance-table'>",
                            "                            <table>",
                            "                                <tr>",
                            "                                    <th>Framework</th>",
                            "                                    <th>Controls</th>",
                            "                                </tr>"
                        ])
                        
                        for framework, controls in check.get("compliance_mappings", {}).items():
                            controls_str = ", ".join(controls) if isinstance(controls, list) else str(controls)
                            html_parts.extend([
                                "                                <tr>",
                                f"                                    <td><strong>{html.escape(framework)}</strong></td>",
                                f"                                    <td>{html.escape(controls_str)}</td>",
                                "                                </tr>"
                            ])
                        
                        html_parts.extend([
                            "                            </table>",
                            "                        </div>",
                            "                    </div>"
                        ])
                    
                    # Add exploitation results if available
                    if check.get("exploitation_results") and isinstance(check.get("exploitation_results"), dict):
                        html_parts.extend([
                            "                    <div class='exploitation-box'>",
                            "                        <h3>🛡️ Exploitation Results</h3>"
                        ])
                        
                        # Add exploitation summary
                        if "simulation_only" in check.get("exploitation_results", {}):
                            simulation_mode = check.get("exploitation_results", {}).get("simulation_only", True)
                            test_status = "Simulated Only (No actual exploitation attempted)" if simulation_mode else "Actual Exploitation Test Performed"
                            test_success = check.get("exploitation_results", {}).get("success", False)
                            
                            html_parts.extend([
                                f"                        <p><strong>Test Mode:</strong> {test_status}</p>",
                                f"                        <p><strong>Vulnerability Status:</strong> {'<span class=\"severity-critical\">Confirmed Exploitable</span>' if test_success else '<span class=\"status-passed\">Not Exploitable</span>'}</p>"
                            ])
                            
                        html_parts.append("                    </div>")
                    
                    # Add reference if available
                    if check.get("reference_url"):
                        html_parts.extend([
                            "                    <div class='reference-box'>",
                            f"                        <p><strong>📚 Reference Documentation:</strong> <a href='{check.get('reference_url')}' target='_blank'>{check.get('reference_url')}</a></p>",
                            "                    </div>"
                        ])
                    
                    # Add MITRE ATT&CK mapping if available
                    if check.get("compliance_mappings", {}).get("MITRE ATT&CK"):
                        mitre_techniques = check.get("compliance_mappings", {}).get("MITRE ATT&CK", [])
                        html_parts.extend([
                            "                    <div class='mitre-box'>",
                            "                        <h3>⚔️ MITRE ATT&CK Techniques</h3>",
                            "                        <ul>"
                        ])
                        
                        for technique in mitre_techniques:
                            # Extract technique ID for URL linking
                            technique_id = technique.split(":")[0].strip() if ":" in technique else technique
                            url = f"https://attack.mitre.org/techniques/{technique_id}/"
                            html_parts.append(f"                            <li><a href='{url}' target='_blank'>{html.escape(technique)}</a></li>")
                        
                        html_parts.extend([
                            "                        </ul>",
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
        
        # Close HTML and add JavaScript for collapsible sections and tabs
        html_parts.extend([
            "    <script>",
            "    // Script for collapsible sections",
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
            "",
            "    // Script for tabs",
            "    function openTab(evt, tabName) {",
            "        var i, tabcontent, tablinks;",
            "        tabcontent = document.getElementsByClassName('tab-content');",
            "        for (i = 0; i < tabcontent.length; i++) {",
            "            tabcontent[i].className = tabcontent[i].className.replace(' active', '');",
            "        }",
            "        tablinks = document.getElementsByClassName('tab');",
            "        for (i = 0; i < tablinks.length; i++) {",
            "            tablinks[i].className = tablinks[i].className.replace(' active', '');",
            "        }",
            "        document.getElementById(tabName).className += ' active';",
            "        evt.currentTarget.className += ' active';",
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
        
        # Compliance summary
        compliance_frameworks = {}
        exploitable_vulnerabilities = 0
        
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
                    
                    # Process compliance mappings for failed checks
                    if check.get("compliance_mappings"):
                        for framework, controls in check.get("compliance_mappings", {}).items():
                            # Skip MITRE ATT&CK as it's not a compliance framework
                            if framework == "MITRE ATT&CK":
                                continue
                                
                            if framework not in compliance_frameworks:
                                compliance_frameworks[framework] = {
                                    "total_controls": 0,
                                    "failed_controls": 0,
                                    "controls": []
                                }
                            
                            # Add controls to the framework
                            control_list = controls if isinstance(controls, list) else [controls]
                            compliance_frameworks[framework]["total_controls"] += len(control_list)
                            compliance_frameworks[framework]["failed_controls"] += len(control_list)
                            compliance_frameworks[framework]["controls"].extend(control_list)
                    
                    # Check for exploitation results
                    if check.get("exploitation_results", {}).get("success", False):
                        exploitable_vulnerabilities += 1
                    
                    # Build remediation item
                    remediation_item = {
                        "name": check.get("name", ""),
                        "severity": severity,
                        "recommendation": check.get("recommendation", ""),
                        "reference_url": check.get("reference_url", ""),
                        "assessment": assessment.get("name", assessment_name),
                        "specific_steps": check.get("details", {}).get("recommendations", []) 
                            if isinstance(check.get("details"), dict) else []
                    }
                    
                    # Add compliance and exploitation data if available
                    if check.get("compliance_mappings"):
                        remediation_item["compliance_impact"] = check.get("compliance_mappings")
                    
                    if check.get("exploitation_results"):
                        remediation_item["exploitation_status"] = check.get("exploitation_results")
                    
                    top_remediation_items.append(remediation_item)
        
        # Sort by severity (Critical first, then High, Medium, etc.)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        top_remediation_items.sort(key=lambda x: severity_order.get(x["severity"], 5))
        
        # Process compliance frameworks (deduplicate controls and calculate percentages)
        for framework in compliance_frameworks:
            compliance_frameworks[framework]["controls"] = list(set(compliance_frameworks[framework]["controls"]))
            compliance_frameworks[framework]["unique_failed_controls"] = len(compliance_frameworks[framework]["controls"])
        
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool_version": "0.1.0",
                "summary": {
                    "total_checks": total_checks,
                    "passed": total_passed,
                    "failed": total_failed,
                    "severity_counts": severity_counts,
                    "exploitable_vulnerabilities": exploitable_vulnerabilities
                },
                "compliance_summary": compliance_frameworks
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
        
        # Generate CSV rows - enhanced with compliance and exploitation data
        csv_rows = ["Assessment,Check,Status,Severity,Description,Recommendation,Reference,Compliance Impact,Exploitable,MITRE ATT&CK,Exploitation Details"]
        
        for assessment_name, assessment in assessment_results.items():
            for check in assessment.get("checks", []):
                status = "PASSED" if check.get("passed", False) else "FAILED"
                severity = check.get("severity", "Informational")
                
                # Escape CSV special characters
                name = check.get("name", "").replace(",", "\"\"").replace("\n", " ")
                description = check.get("description", "").replace(",", "\"\"").replace("\n", " ")
                recommendation = check.get("recommendation", "").replace(",", "\"\"").replace("\n", " ")
                reference = check.get("reference_url", "").replace(",", "\"\"").replace("\n", " ")
                
                # Process compliance mappings
                compliance_info = ""
                mitre_attacks = ""
                
                if check.get("compliance_mappings"):
                    compliance_parts = []
                    for framework, controls in check.get("compliance_mappings", {}).items():
                        if framework == "MITRE ATT&CK":
                            mitre_list = controls if isinstance(controls, list) else [controls]
                            mitre_attacks = "; ".join(mitre_list).replace(",", "\"\"").replace("\n", " ")
                        else:
                            control_list = controls if isinstance(controls, list) else [controls]
                            controls_str = ",".join(control_list).replace(",", "\"\"").replace("\n", " ")
                            compliance_parts.append(f"{framework}: {controls_str}")
                    
                    compliance_info = "; ".join(compliance_parts).replace(",", "\"\"").replace("\n", " ")
                
                # Process exploitation results
                exploitable = "No"
                exploitation_details = ""
                
                if check.get("exploitation_results"):
                    exploitable = "Yes" if check.get("exploitation_results", {}).get("success", False) else "No"
                    simulation_mode = check.get("exploitation_results", {}).get("simulation_only", True)
                    mode_str = "Simulation" if simulation_mode else "Actual"
                    
                    # Extract additional exploitation details if available
                    details_list = []
                    for key, value in check.get("exploitation_results", {}).items():
                        if key not in ["success", "simulation_only"] and value:
                            details_list.append(f"{key}: {value}".replace(",", "\"\"").replace("\n", " "))
                    
                    details_str = "; ".join(details_list)
                    exploitation_details = f"Mode: {mode_str}; {details_str}" if details_str else f"Mode: {mode_str}"
                
                # Create the CSV row
                csv_rows.append(
                    f'"{assessment.get("name", assessment_name)}","{name}",{status},{severity},'
                    f'"{description}","{recommendation}","{reference}","{compliance_info}",'
                    f'"{exploitable}","{mitre_attacks}","{exploitation_details}"'
                )
        
        # Write to file
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("\n".join(csv_rows))
        
        logger.info(f"CSV report generated: {report_file}")
        return report_file