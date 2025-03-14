# ADSecEval Usage Guide

This guide explains how to use ADSecEval to assess the security of your Active Directory environment and interpret the reports it generates.

## Basic Usage

Once you've [installed and configured](setup.md) ADSecEval, you can run it with the default settings:

```bash
python -m adseceval.main --config config.json
```

This will execute all enabled assessments and generate a report in the format specified in your configuration file.

## Command Line Options

ADSecEval provides several command-line options to customize its behavior:

```
usage: python -m adseceval.main [options]

Active Directory Security Assessment Tool

options:
  --config CONFIG           Path to configuration file (default: config.json)
  --output OUTPUT           Output directory for assessment reports (default: ./reports)
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                            Set logging level (default: INFO)
  --assessments ASSESSMENTS [ASSESSMENTS ...]
                            Specific assessments to run (default: all)
  --format {html,pdf,json,csv}
                            Report output format (default: html)
```

### Examples

Run only specific assessments:

```bash
python -m adseceval.main --config config.json --assessments privileged_accounts password_policy
```

Generate a report in JSON format:

```bash
python -m adseceval.main --config config.json --format json
```

Specify a custom output directory:

```bash
python -m adseceval.main --config config.json --output /path/to/reports
```

Increase logging verbosity:

```bash
python -m adseceval.main --config config.json --log-level DEBUG
```

## Assessment Modules

ADSecEval includes comprehensive assessment modules, each focusing on a specific aspect of Active Directory security:

1. **Privileged Accounts** - Evaluates security of administrator and other privileged accounts
2. **Password Policy** - Assesses password policy settings and enforcement
3. **Domain Controllers** - Checks security configurations on domain controllers
4. **Trust Relationships** - Analyzes trust relationships for security issues
5. **Exploitation** - Validates vulnerabilities through safe exploitation testing
6. **Compliance** - Maps findings to regulatory frameworks and standards
7. **Group Policy** - Assesses GPO security configurations and best practices
8. **Privileged Access** - Evaluates advanced privileged access management controls

### Customizing Assessments

You can enable/disable specific assessments using command-line options:

```bash
python -m adseceval.main --config config.json --assessments privileged_accounts password_policy domain_controllers trust_relationships
```

Or enable all assessments with the `all` option:

```bash
python -m adseceval.main --config config.json --assessments all
```

### Safe Mode and Exploitation Testing

The exploitation assessment module includes tests that validate vulnerabilities by attempting safe exploitation. By default, these tests run in a simulation mode that doesn't perform actual exploitation. To enable full testing:

```bash
python -m adseceval.main --config config.json --assessments exploitation --exploitation
```

To ensure all tests run in a completely safe mode:

```bash
python -m adseceval.main --config config.json --safe-mode
```

### Compliance Framework Selection

You can specify which compliance frameworks to assess against:

```bash
python -m adseceval.main --config config.json --assessments compliance --compliance-framework nist
```

Available frameworks:
- `nist` - NIST SP 800-53
- `cis` - CIS Controls
- `iso27001` - ISO 27001
- `pci-dss` - PCI DSS
- `hipaa` - HIPAA Security Rule
- `all` - All frameworks (default)

## Understanding Reports

ADSecEval generates comprehensive reports that include:

1. **Executive Summary** - Overview of findings with risk levels
2. **Detailed Findings** - Specific security issues identified
3. **Recommendations** - Actionable steps to remediate identified issues
4. **Technical Details** - Detailed information for security professionals

### Report Formats

Reports can be generated in multiple formats:

- **HTML** - Interactive web-based report (default)
- **JSON** - Machine-readable format for integration with other tools
- **CSV** - Spreadsheet format for further analysis

### Enhanced HTML Report Structure

The HTML report includes the following sections:

1. **Executive Summary**
   - Assessment summary and overview
   - Risk score and compliance status
   - Critical findings count by severity
   - Top remediation recommendations

2. **Findings by Category**
   - Each assessment module's findings
   - Severity indicators and impact assessment
   - Affected objects and detailed context
   - Compliance framework mappings
   - Exploitation test results (when applicable)

3. **Remediation Action Plan**
   - Prioritized remediation steps by risk
   - Detailed implementation guidance
   - Best practice references with external links
   - Specific configuration steps for remediation
   - Compliance impact of remediation actions

4. **Compliance Mapping**
   - Mapping to NIST SP 800-53 controls
   - CIS Controls alignment
   - ISO 27001 controls mapping
   - PCI DSS requirements alignment
   - HIPAA Security Rule compliance mapping

5. **Technical Details**
   - Detailed configuration information
   - Raw assessment data and context
   - Exploitation test details (when applicable)
   - Group Policy configuration details
   - Privileged access assessment details

### JSON Report Structure

The JSON report includes structured data for easy integration with other security tools and includes:

1. **Metadata Section**
   - Assessment information 
   - Environment details
   - Execution timestamp and version

2. **Remediation Plan Section**
   - Prioritized list of findings to address
   - Step-by-step remediation guidance
   - Compliance impact information

3. **Assessment Results Section**
   - Results from all assessment modules
   - Detailed finding information
   - Technical context and configuration details

4. **Compliance Mapping Section**
   - Complete mapping to compliance frameworks
   - Gap analysis information
   - Compliance status by framework

## Regular Assessment Schedule

For optimal security monitoring, it's recommended to run ADSecEval:

- After major Active Directory changes
- Once per quarter for routine assessments
- As part of compliance verification processes
- After security incidents to verify remediation

## Troubleshooting

If you encounter issues while running assessments:

1. Check the log file at the location specified in your config
2. Verify that your authentication credentials have sufficient permissions
3. Ensure the account can connect to all required domain controllers
4. For timeout issues, consider running individual assessments separately

## Best Practices

For best results with ADSecEval:

1. Use a dedicated service account with read-only permissions
2. Schedule regular automated assessments
3. Archive reports for compliance and comparison purposes
4. Integrate findings into your security remediation workflow
5. Document exceptions for findings that cannot be remediated

## Next Steps

After running your assessment, review the [Concepts Guide](concepts.md) to better understand the security principles being evaluated and how to implement the recommended remediation steps.