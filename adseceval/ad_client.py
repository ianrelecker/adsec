"""
Active Directory client module for interacting with AD environments.
"""

import logging
import os
from typing import Dict, Any, List, Optional, Union, Tuple
import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES
import json

logger = logging.getLogger(__name__)


class ADClient:
    """Client for interacting with Active Directory."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the AD client.
        
        Args:
            config: Configuration options including AD connection details
        """
        self.config = config
        self.domain_config = config.get("domain", {})
        self.auth_config = config.get("auth", {})
        self.conn = None
        self.server = None
        self.domain_info = {}
        self.domain_name = self.domain_config.get("name", "")
        self.base_dn = self._get_base_dn(self.domain_name)
    
    def _get_base_dn(self, domain_name: str) -> str:
        """
        Convert a domain name to a base DN.
        
        Args:
            domain_name: Domain name (e.g., example.com)
            
        Returns:
            Base DN (e.g., DC=example,DC=com)
        """
        if not domain_name:
            return ""
            
        parts = domain_name.split(".")
        return ",".join([f"DC={part}" for part in parts])
    
    def connect(self) -> bool:
        """
        Connect to Active Directory.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            server_name = self.domain_config.get("server", "")
            use_ssl = self.domain_config.get("use_ssl", False)
            use_tls = self.domain_config.get("use_tls", True)
            port = self.domain_config.get("port", 389)
            
            if not server_name:
                logger.error("No AD server specified in config")
                return False
            
            # Create server object
            self.server = Server(
                server_name, 
                port=port, 
                use_ssl=use_ssl, 
                get_info=ALL
            )
            
            # Get authentication parameters
            username = self.auth_config.get("username", "")
            password_env = self.auth_config.get("password_env", "")
            use_kerberos = self.auth_config.get("use_kerberos", False)
            
            if use_kerberos:
                # Use Kerberos authentication
                logger.info("Using Kerberos authentication")
                self.conn = Connection(self.server, authentication=ldap3.SASL, sasl_mechanism='GSSAPI')
            else:
                # Use username/password authentication
                if not username:
                    logger.error("No username specified in config")
                    return False
                    
                # Get password from environment variable
                password = ""
                if password_env:
                    password = os.environ.get(password_env, "")
                
                if not password:
                    logger.error(f"No password found in environment variable {password_env}")
                    return False
                
                logger.info(f"Connecting to AD as {username}")
                self.conn = Connection(
                    self.server,
                    user=username,
                    password=password,
                    authentication=NTLM,
                    auto_bind=True
                )
            
            # Bind to the server
            if not self.conn.bound:
                if not self.conn.bind():
                    logger.error(f"Failed to bind to AD: {self.conn.result}")
                    return False
            
            # Start TLS if requested
            if use_tls and not use_ssl:
                if not self.conn.start_tls():
                    logger.error(f"Failed to start TLS: {self.conn.result}")
                    return False
            
            # Get domain information
            self._get_domain_info()
            
            logger.info(f"Successfully connected to AD domain {self.domain_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to AD: {str(e)}", exc_info=True)
            return False
    
    def _get_domain_info(self) -> None:
        """Get basic information about the domain."""
        try:
            # Search for the domain object
            search_filter = f"(objectClass=domain)"
            self.conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES
            )
            
            if self.conn.entries:
                entry = self.conn.entries[0]
                self.domain_info = {
                    "name": self.domain_name,
                    "distinguishedName": entry.distinguishedName.value if hasattr(entry, 'distinguishedName') else "",
                    "objectSid": entry.objectSid.value if hasattr(entry, 'objectSid') else "",
                    "whenCreated": entry.whenCreated.value if hasattr(entry, 'whenCreated') else "",
                    "functional_level": entry.msDS_Behavior_Version.value if hasattr(entry, 'msDS_Behavior_Version') else "",
                }
            
        except Exception as e:
            logger.error(f"Failed to get domain info: {str(e)}", exc_info=True)
    
    def search(
        self, 
        search_base: Optional[str] = None, 
        search_filter: str = "(objectClass=*)",
        attributes: Optional[List[str]] = None,
        search_scope: str = SUBTREE
    ) -> List[Dict[str, Any]]:
        """
        Search Active Directory.
        
        Args:
            search_base: Base DN for the search (defaults to domain base DN)
            search_filter: LDAP filter for the search
            attributes: List of attributes to retrieve (None for all)
            search_scope: Scope of the search (SUBTREE, LEVEL, BASE)
            
        Returns:
            List of matching objects
        """
        if not self.conn:
            logger.error("Not connected to AD")
            return []
        
        if not search_base:
            search_base = self.base_dn
        
        if not attributes:
            attributes = ALL_ATTRIBUTES
        
        try:
            logger.debug(f"Searching AD: base={search_base}, filter={search_filter}")
            
            self.conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=search_scope,
                attributes=attributes
            )
            
            results = []
            for entry in self.conn.entries:
                entry_dict = entry.entry_attributes_as_dict
                
                # Convert binary values to strings where possible
                for key, value in entry_dict.items():
                    if isinstance(value, list) and value and isinstance(value[0], bytes):
                        try:
                            entry_dict[key] = [v.decode('utf-8') if isinstance(v, bytes) else v for v in value]
                        except UnicodeDecodeError:
                            # Keep as bytes if can't decode
                            pass
                
                results.append(entry_dict)
            
            logger.debug(f"Found {len(results)} results")
            return results
            
        except Exception as e:
            logger.error(f"Error searching AD: {str(e)}", exc_info=True)
            return []
    
    def get_domain_controllers(self) -> List[Dict[str, Any]]:
        """
        Get all domain controllers.
        
        Returns:
            List of domain controllers
        """
        search_filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        attributes = [
            "name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
            "whenCreated", "lastLogonTimestamp", "msDS-SupportedEncryptionTypes"
        ]
        
        return self.search(search_filter=search_filter, attributes=attributes)
    
    def get_privileged_groups(self) -> List[Dict[str, Any]]:
        """
        Get privileged security groups.
        
        Returns:
            List of privileged groups
        """
        # List of well-known privileged groups
        privileged_groups = [
            "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
            "Account Operators", "Backup Operators", "Print Operators", "Server Operators",
            "Domain Controllers", "Read-only Domain Controllers", "Group Policy Creator Owners",
            "DNSAdmins"
        ]
        
        # Build filter to find these groups
        group_filters = []
        for group in privileged_groups:
            group_filters.append(f"(sAMAccountName={group})")
        
        search_filter = f"(&(objectClass=group)(objectCategory=group)(|{''.join(group_filters)}))"
        attributes = ["name", "sAMAccountName", "description", "member", "whenCreated", "adminCount"]
        
        return self.search(search_filter=search_filter, attributes=attributes)
    
    def get_group_members(self, group_dn: str) -> List[Dict[str, Any]]:
        """
        Get members of a group.
        
        Args:
            group_dn: Distinguished name of the group
            
        Returns:
            List of group members
        """
        # First get the group's member attribute
        search_filter = f"(distinguishedName={group_dn})"
        group_results = self.search(search_filter=search_filter, attributes=["member"])
        
        if not group_results:
            return []
        
        members = group_results[0].get("member", [])
        if not members:
            return []
        
        # Now get the details for each member
        member_details = []
        for member_dn in members:
            search_filter = f"(distinguishedName={member_dn})"
            attributes = [
                "sAMAccountName", "objectClass", "userAccountControl", 
                "lastLogonTimestamp", "pwdLastSet", "memberOf"
            ]
            
            member_results = self.search(search_filter=search_filter, attributes=attributes)
            if member_results:
                member_details.append(member_results[0])
        
        return member_details
    
    def get_password_policy(self) -> Dict[str, Any]:
        """
        Get the domain password policy.
        
        Returns:
            Domain password policy settings
        """
        search_filter = f"(objectClass=domainDNS)"
        attributes = [
            "maxPwdAge", "minPwdAge", "minPwdLength", "pwdHistoryLength",
            "pwdProperties", "lockoutThreshold", "lockoutDuration", "lockoutObservationWindow"
        ]
        
        results = self.search(search_filter=search_filter, attributes=attributes)
        
        if not results:
            return {}
        
        policy = results[0]
        
        # Convert timedelta values (negative 100-nanosecond intervals)
        # These are stored as negative 100-nanosecond intervals
        # To convert to days: value / -864000000000
        if "maxPwdAge" in policy and policy["maxPwdAge"]:
            max_pwd_age = int(policy["maxPwdAge"][0]) if isinstance(policy["maxPwdAge"], list) else int(policy["maxPwdAge"])
            if max_pwd_age < 0:  # If 0, passwords never expire
                policy["maxPwdAgeDays"] = abs(max_pwd_age) / 864000000000
            else:
                policy["maxPwdAgeDays"] = 0  # Never expire
        
        if "minPwdAge" in policy and policy["minPwdAge"]:
            min_pwd_age = int(policy["minPwdAge"][0]) if isinstance(policy["minPwdAge"], list) else int(policy["minPwdAge"])
            policy["minPwdAgeDays"] = abs(min_pwd_age) / 864000000000
        
        if "lockoutDuration" in policy and policy["lockoutDuration"]:
            lockout_duration = int(policy["lockoutDuration"][0]) if isinstance(policy["lockoutDuration"], list) else int(policy["lockoutDuration"])
            policy["lockoutDurationMinutes"] = abs(lockout_duration) / 600000000
        
        if "lockoutObservationWindow" in policy and policy["lockoutObservationWindow"]:
            lockout_window = int(policy["lockoutObservationWindow"][0]) if isinstance(policy["lockoutObservationWindow"], list) else int(policy["lockoutObservationWindow"])
            policy["lockoutObservationWindowMinutes"] = abs(lockout_window) / 600000000
        
        # Interpret pwdProperties flags
        if "pwdProperties" in policy and policy["pwdProperties"]:
            pwd_props = int(policy["pwdProperties"][0]) if isinstance(policy["pwdProperties"], list) else int(policy["pwdProperties"])
            policy["complexityEnabled"] = bool(pwd_props & 1)
            policy["reversibleEncryptionEnabled"] = bool(pwd_props & 16)
        
        return policy
    
    def get_fine_grained_password_policies(self) -> List[Dict[str, Any]]:
        """
        Get fine-grained password policies.
        
        Returns:
            List of fine-grained password policies
        """
        search_filter = "(objectClass=msDS-PasswordSettings)"
        attributes = [
            "cn", "msDS-PasswordSettingsPrecedence", "msDS-PasswordReversibleEncryptionEnabled",
            "msDS-PasswordHistoryLength", "msDS-PasswordComplexityEnabled",
            "msDS-MinimumPasswordLength", "msDS-MinimumPasswordAge",
            "msDS-MaximumPasswordAge", "msDS-LockoutThreshold",
            "msDS-LockoutObservationWindow", "msDS-LockoutDuration",
            "msDS-PSOAppliesTo"
        ]
        
        return self.search(search_filter=search_filter, attributes=attributes)
    
    def get_trusts(self) -> List[Dict[str, Any]]:
        """
        Get domain trusts.
        
        Returns:
            List of domain trusts
        """
        search_filter = "(objectClass=trustedDomain)"
        attributes = [
            "name", "flatName", "trustDirection", "trustType",
            "trustAttributes", "whenCreated", "whenChanged"
        ]
        
        results = self.search(search_filter=search_filter, attributes=attributes)
        
        # Interpret trust direction and type
        for trust in results:
            if "trustDirection" in trust:
                direction = int(trust["trustDirection"][0]) if isinstance(trust["trustDirection"], list) else int(trust["trustDirection"])
                if direction == 0:
                    trust["trustDirectionText"] = "Disabled"
                elif direction == 1:
                    trust["trustDirectionText"] = "Inbound"
                elif direction == 2:
                    trust["trustDirectionText"] = "Outbound"
                elif direction == 3:
                    trust["trustDirectionText"] = "Bidirectional"
            
            if "trustType" in trust:
                trust_type = int(trust["trustType"][0]) if isinstance(trust["trustType"], list) else int(trust["trustType"])
                if trust_type == 1:
                    trust["trustTypeText"] = "Windows NT (Downlevel)"
                elif trust_type == 2:
                    trust["trustTypeText"] = "Active Directory"
                elif trust_type == 3:
                    trust["trustTypeText"] = "Kerberos"
                elif trust_type == 4:
                    trust["trustTypeText"] = "DCE"
            
            if "trustAttributes" in trust:
                attr = int(trust["trustAttributes"][0]) if isinstance(trust["trustAttributes"], list) else int(trust["trustAttributes"])
                trust["trustAttributesDetails"] = {
                    "non_transitive": bool(attr & 0x1),
                    "uplevel_only": bool(attr & 0x2),
                    "quarantined": bool(attr & 0x4),
                    "forest_trust": bool(attr & 0x8),
                    "cross_organization": bool(attr & 0x10),
                    "within_forest": bool(attr & 0x20),
                    "treat_as_external": bool(attr & 0x40),
                    "uses_rc4_encryption": bool(attr & 0x80)
                }
        
        return results
    
    def close(self) -> None:
        """Close the connection to Active Directory."""
        if self.conn:
            self.conn.unbind()
            self.conn = None
            logger.info("Disconnected from AD")