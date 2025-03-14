# ADSecEval Usage Guide

This guide explains how to use ADSecEval to assess the security of your Active Directory environment and interpret the reports it generates.

## Basic Usage

Once you've [installed and configured](setup.md) ADSecEval, you can run it with the default settings:

```bash
adseceval --config config.json
```

This will execute all enabled assessments and generate a report in the format specified in your configuration file.

## Command Line Options

ADSecEval provides several command-line options to customize its behavior:

```
usage: adseceval [options]

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
adseceval --config config.json --assessments privileged_accounts password_policy
```

Generate a report in JSON format:

```bash
adseceval --config config.json --format json
```

Specify a custom output directory:

```bash
adseceval --config config.json --output /path/to/reports
```

Increase logging verbosity:

```bash
adseceval --config config.json --log-level DEBUG
```

## Assessment Modules

ADSecEval includes several assessment modules, each focusing on a specific aspect of Active Directory security:

1. **Privileged Accounts** - Evaluates security of administrator and other privileged accounts
2. **Password Policy** - Assesses password policy settings and enforcement
3. **Domain Controllers** - Checks security configurations on domain controllers
4. **Trust Relationships** - Analyzes trust relationships for security issues

### Customizing Assessments

You can enable/disable specific assessments in your configuration file:

```json
"scan_options": {
    "privileged_accounts": true,
    "password_policies": true,
    "security_groups": true,
    "trust_relationships": true,
    "domain_controllers": true,
    "service_accounts": true
}
```

## Understanding Reports

ADSecEval generates comprehensive reports that include:

1. **Executive Summary** - Overview of findings with risk levels
2. **Detailed Findings** - Specific security issues identified
3. **Recommendations** - Actionable steps to remediate identified issues
4. **Technical Details** - Detailed information for security professionals

### Report Formats

Reports can be generated in multiple formats:

- **HTML** - Interactive web-based report (default)
- **PDF** - Printable document format
- **JSON** - Machine-readable format for integration with other tools
- **CSV** - Spreadsheet format for further analysis

### Sample Report Structure

The HTML report is organized as follows:

1. **Overview**
   - Assessment summary
   - Risk score
   - Critical findings count

2. **Findings by Category**
   - Each assessment module's findings
   - Severity indicators
   - Affected objects

3. **Recommendations**
   - Prioritized remediation steps
   - Implementation guidance
   - Best practice references

4. **Technical Details**
   - Detailed configuration information
   - Raw assessment data

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