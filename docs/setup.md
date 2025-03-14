# ADSecEval Setup Guide

This guide will walk you through the process of installing and configuring the ADSecEval tool for assessing your Active Directory environment's security posture.

## Prerequisites

Before installing ADSecEval, ensure you have the following:

- Python 3.7 or higher
- pip (Python package installer)
- Access to an Active Directory environment with appropriate permissions
- A user account with at least read access to the AD objects you want to evaluate

## Installation

### Option 1: Install from PyPI (Recommended)

```bash
pip install adseceval
```

### Option 2: Install from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ADSecEval.git
   cd ADSecEval
   ```

2. Install the package:
   ```bash
   pip install -r requirements.txt
   python setup.py install
   ```

## Configuration

1. Create a configuration file by copying the example:
   ```bash
   cp config.json.example config.json
   ```

2. Edit the `config.json` file to configure your environment:
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
       "scan_options": {
           "privileged_accounts": true,
           "password_policies": true,
           "security_groups": true,
           "trust_relationships": true,
           "domain_controllers": true,
           "service_accounts": true
       },
       "reporting": {
           "output_dir": "./reports",
           "formats": ["html", "pdf", "json"],
           "include_recommendations": true,
           "risk_threshold": "medium"
       },
       "logging": {
           "level": "INFO",
           "file": "./logs/adseceval.log",
           "max_size_mb": 10,
           "backup_count": 5
       }
   }
   ```

3. Set the password environment variable:
   ```bash
   # For Linux/macOS
   export ADSECEVAL_PASSWORD='your_password'
   
   # For Windows Command Prompt
   set ADSECEVAL_PASSWORD=your_password
   
   # For Windows PowerShell
   $env:ADSECEVAL_PASSWORD = 'your_password'
   ```

## Required Permissions

ADSecEval requires specific permissions to perform a comprehensive security assessment. The account used should have:

1. **For basic assessment**: Domain User permissions
2. **For comprehensive assessment**: Domain Admin or equivalent read permissions
3. **For detailed security assessment**: Enterprise Admin or equivalent read permissions

## Troubleshooting Installation

If you encounter issues during installation:

1. Ensure your Python version is 3.7 or higher:
   ```bash
   python --version
   ```

2. Verify that all dependencies are installed correctly:
   ```bash
   pip install -r requirements.txt --force-reinstall
   ```

3. Check for any errors in the installation logs.

4. For connection issues, ensure your firewall allows connections to your domain controllers on the required ports (typically 389 for LDAP, 636 for LDAPS).

## Next Steps

Once you've completed the installation and configuration, proceed to the [Usage Guide](usage.md) to learn how to use ADSecEval to assess your Active Directory environment.