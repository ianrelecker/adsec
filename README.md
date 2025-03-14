# ADSecEval - Active Directory Security Evaluation Tool

ADSecEval is a Python-based tool for evaluating the security posture of Active Directory environments. This project is currently in development and provides a framework for assessing various aspects of AD security.

## Project Overview

Active Directory is a critical component in many enterprise environments and a common target for attackers. ADSecEval helps identify security weaknesses by examining:

- Privileged account configurations
- Password policies
- Domain controller security
- Trust relationships

The tool connects to your AD environment via LDAP, performs security checks against industry best practices, and generates detailed reports with remediation recommendations.

## Current Features

### Assessment Modules

- **Privileged Accounts Security**
  - Admin account proliferation detection
  - Dormant privileged account identification
  - Service accounts with excessive privileges
  - Nested group detection
  - Protected Users group utilization check
  - Smart card requirement assessment

- **Password Policy Security**
  - Password complexity verification
  - Minimum length requirements
  - Password history enforcement
  - Account lockout policy assessment
  - Fine-grained password policy review
  - Reversible encryption detection

- **Domain Controller Security**
  - Operating system version verification
  - LDAP/LDAPS configuration check
  - SMB signing assessment
  - DNS security evaluation
  - FSMO roles distribution review

- **Trust Relationships Security**
  - Trust inventory and mapping
  - SID filtering validation
  - Transitive trust identification
  - External trust security inspection
  - Forest trust configuration evaluation

### Reporting Capabilities

- HTML reports with executive summaries and detailed findings
- JSON output for integration with other tools
- CSV output for spreadsheet analysis
- Severity-based categorization of findings

## Project Status

This project is **in development** and not yet ready for production use. Key points:

- Not yet published on PyPI
- Documentation is being developed
- Core LDAP functionality is implemented but some assessment checks are stubs
- Report generation is functional

## Installation 

### Requirements

- Python 3.7 or higher
- Access to an Active Directory environment
- Python libraries (see requirements.txt)

### Development Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ADSecEval.git
cd ADSecEval

# Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

## Basic Usage

1. Create a configuration file:

```json
{
    "domain": {
        "name": "yourdomain.com",
        "server": "dc01.yourdomain.com",
        "port": 389,
        "use_ssl": false,
        "use_tls": true
    },
    "auth": {
        "username": "domain\\username",
        "password_env": "ADSECEVAL_PASSWORD",
        "use_kerberos": false
    },
    "reporting": {
        "output_dir": "./reports",
        "formats": ["html", "json"]
    }
}
```

2. Set your AD password as an environment variable:
```bash
# Linux/macOS
export ADSECEVAL_PASSWORD="your_password"

# Windows
set ADSECEVAL_PASSWORD=your_password
```

3. Run the assessment:
```bash
python -m adseceval.main --config config.json
```

## Documentation

Documentation is located in the `docs/` directory:

- [Setup Guide](docs/setup.md)
- [Usage Guide](docs/usage.md)
- [Security Concepts](docs/concepts.md)

## Development and Contribution

This is an open-source project in early development. Contributions are welcome:

- Code contributions via pull requests
- Bug reports and feature requests via issues
- Documentation improvements
- Testing in different AD environments

## Future Roadmap

- Complete implementation of assessment modules
- Detailed remediation guidance
- Integration with AD management tools
- Historical trend analysis
- Support for Azure AD/Entra ID assessment

## License

This project is available under the MIT License.

## Acknowledgments

This project was inspired by various AD security assessment methodologies:

- Microsoft Active Directory security best practices
- CIS benchmarks
- NIST guidelines
- MITRE ATT&CK framework for Active Directory