# core/bloodhound_integration.py
"""
BloodHound Enterprise API integration module.
Provides functionality for interacting with BloodHound to retrieve account data.
"""

import hmac
import hashlib
import base64
import requests
import datetime
import json
from typing import Optional, List, Dict, Any
from core.config import BHE_CONFIG
from collections import defaultdict
from utils.misc import error_suppression


class Credentials:
    """BloodHound Enterprise API credentials."""
    
    def __init__(self, token_id: str, token_key: str) -> None:
        """Initialize credentials with token ID and key."""
        self.token_id = token_id
        self.token_key = token_key


class APIVersion:
    """BloodHound Enterprise API version."""
    
    def __init__(self, api_version: str, server_version: str) -> None:
        """Initialize with API and server versions."""
        self.api_version = api_version
        self.server_version = server_version


class Domain:
    """Domain information from BloodHound."""
    
    def __init__(self, name: str, id: str, collected: bool, domain_type: str) -> None:
        """Initialize domain with properties."""
        self.name = name
        self.id = id
        self.type = domain_type
        self.collected = collected


class Client:
    """BloodHound Enterprise API client."""
    
    def __init__(self, scheme: str, host: str, port: int, credentials: Credentials) -> None:
        """Initialize client with connection parameters and credentials."""
        self._scheme = scheme
        self._host = host
        self._port = port
        self._credentials = credentials

    def _format_url(self, uri: str) -> str:
        """Format the URL for API requests."""
        formatted_uri = uri
        if uri.startswith("/"):
            formatted_uri = formatted_uri[1:]
        return f"{self._scheme}://{self._host}:{self._port}/{formatted_uri}"

    def _request(self, method: str, uri: str, body: Optional[bytes] = None, logger=None) -> requests.Response:
        """Make an authenticated request to the BloodHound API."""
        with error_suppression(logger.debug if logger else None):
            digester = hmac.new(self._credentials.token_key.encode(), None, hashlib.sha256)
            digester.update(f"{method}{uri}".encode())
            digester = hmac.new(digester.digest(), None, hashlib.sha256)
            datetime_formatted = datetime.datetime.now().astimezone().isoformat("T")
            digester.update(datetime_formatted[:13].encode())
            digester = hmac.new(digester.digest(), None, hashlib.sha256)
            if body is not None:
                digester.update(body)

            try:
                return requests.request(
                    method=method,
                    url=self._format_url(uri),
                    headers={
                        "User-Agent": "bhe-python-sdk 0001",
                        "Authorization": f"bhesignature {self._credentials.token_id}",
                        "RequestDate": datetime_formatted,
                        "Signature": base64.b64encode(digester.digest()),
                        "Content-Type": "application/json",
                    },
                    data=body,
                )
            except Exception as e:
                if logger:
                    logger.debug(f"Request failed for {method} {uri}: {str(e)}")
                raise

    def get_version(self, logger=None) -> APIVersion:
        """Get the BloodHound API version information."""
        with error_suppression(logger.debug if logger else None):
            response = self._request("GET", "/api/version", logger=logger)
            payload = response.json()
            return APIVersion(api_version=payload["data"]["API"]["current_version"], server_version=payload["data"]["server_version"])

    def get_domains(self, logger=None) -> List[Domain]:
        """Get all available domains from BloodHound."""
        with error_suppression(logger.debug if logger else None):
            response = self._request('GET', '/api/v2/available-domains', logger=logger)
            payload = response.json()['data']
            domains = [Domain(domain["name"], domain["id"], domain["collected"], domain["type"]) for domain in payload]
            return domains

    def get_computer(self, computername: str, logger=None) -> Dict:
        """Get computer information from BloodHound."""
        with error_suppression(logger.debug if logger else None):
            response = self._request("GET", f"/api/v2/search?q={computername}&type=Computer&limit=1", logger=logger)
            if response.status_code != 200:
                if logger:
                    logger.debug(f"Error retrieving computer {computername}: {response.text}")
                return {}
            data = response.json().get("data", [])
            if not data:
                if logger:
                    logger.debug(f"Computer {computername} not found")
                return {}
            return data[0]

    def get_computer_full(self, object_id: str, logger=None) -> Dict:
        """Get detailed computer information from BloodHound."""
        with error_suppression(logger.debug if logger else None):
            response = self._request("GET", f"/api/v2/base/{object_id}", logger=logger)
            if response.status_code != 200:
                if logger:
                    logger.debug(f"Error retrieving computer {object_id}: {response.text}")
                return {}
            data = response.json().get("data")
            if not data:
                if logger:
                    logger.debug(f"Computer {object_id} not found")
                return {}
            return data

    def get_user(self, username: str, logger=None) -> Dict:
        """Get user information from BloodHound."""
        with error_suppression(logger.debug if logger else None):
            response = self._request("GET", f"/api/v2/search?q={username}&type=User&limit=1", logger=logger)
            if response.status_code != 200:
                if logger:
                    logger.debug(f"Error retrieving user {username}: {response.text}")
                return {}
            data = response.json().get("data", [])
            if not data:
                if logger:
                    logger.debug(f"User {username} not found")
                return {}
            return data[0]

    def get_user_full(self, object_id: str, logger=None) -> Dict:
        """Get detailed user information from BloodHound."""
        with error_suppression(logger.debug if logger else None):
            response = self._request("GET", f"/api/v2/users/{object_id}", logger=logger)
            if response.status_code != 200:
                if logger:
                    logger.debug(f"Error retrieving user {object_id}: {response.text}")
                return {}
            data = response.json().get("data")
            if not data:
                if logger:
                    logger.debug(f"User {object_id} not found")
                return {}
            return data

    def get_group(self, groupname: str, logger=None) -> Dict:
        """Get group information from BloodHound."""
        with error_suppression(logger.debug if logger else None):
            groupname = groupname.replace(" ", "%20")
            response = self._request("GET", f"/api/v2/search?q={groupname}&type=Group&limit=1", logger=logger)
            if response.status_code != 200:
                if logger:
                    logger.debug(f"Error retrieving group {groupname}: {response.text}")
                return {}
            data = response.json().get("data", [])
            if not data:
                if logger:
                    logger.debug(f"Group {groupname} not found")
                return {}
            return data[0]

    def get_user_controllables(self, object_id: str, logger=None) -> Dict:
        """Get objects controllable by a user from BloodHound."""
        with error_suppression(logger.debug if logger else None):
            response = self._request("GET", f"/api/v2/base/{object_id}/controllables?skip=0&limit=10&type=list", logger=logger)
            if response.status_code != 200:
                if logger:
                    logger.debug(f"Error retrieving user controllables for {object_id}: {response.text}")
                return {}
            
            count = response.json().get("count", 0)
            response = self._request("GET", f"/api/v2/base/{object_id}/controllables?skip=0&limit={count}&type=list", logger=logger)
            if response.status_code != 200:
                if logger:
                    logger.debug(f"Error retrieving full user controllables for {object_id}: {response.text}")
                return {}
            
            controllables_json = response.json().get("data", [])
            controllables_lable_and_count = {}
            
            for controllable in controllables_json:
                label = controllable.get("label", "Unknown")
                name = controllable.get("name", "Unknown")
                domain = "Unknown"
                
                if '@' in name:
                    domain = name.split('@')[-1]
                elif '.' in name:
                    parts = name.split('.', 1)
                    if len(parts) > 1:
                        domain = parts[1]
                
                if domain in ("LOCALDOMAIN", "Unknown", "INT"):
                    try:
                        result = self.get_computer(name, logger=logger)
                        object_id = result.get("objectid", "")
                        result = self.get_computer_full(object_id, logger=logger)
                        domain = result.get("props", {}).get("domain", "Unknown")
                    except Exception as e:
                        if logger:
                            logger.debug(f"Error resolving domain for {name}: {str(e)}")
                
                if domain not in controllables_lable_and_count:
                    controllables_lable_and_count[domain] = {}
                if label not in controllables_lable_and_count[domain]:
                    controllables_lable_and_count[domain][label] = 0
                controllables_lable_and_count[domain][label] += 1
            
            return controllables_lable_and_count

    def get_shortest_path(self, source_object_id: str, target_object_id: str, logger=None) -> Dict:
        """Get the shortest path between two objects in BloodHound."""
        with error_suppression(logger.debug if logger else None):
            response = self._request("GET", f"/api/v2/graphs/shortest-path?start_node={source_object_id}&end_node={target_object_id}&relationship_kinds=in:Contains,GPLink,HasSIDHistory,MemberOf,TrustedBy,AdminTo,AllowedToAct,AllowedToDelegate,CanPSRemote,CanRDP,ExecuteDCOM,SQLAdmin,CoerceToTGT,DCSync,DumpSMSAPassword,HasSession,ReadGMSAPassword,ReadLAPSPassword,SyncLAPSPassword,AddMember,AddSelf,AllExtendedRights,ForceChangePassword,GenericAll,Owns,GenericWrite,WriteDacl,WriteOwner,AddAllowedToAct,AddKeyCredentialLink,WriteAccountRestrictions,WriteGPLink,WriteSPN,GoldenCert,ADCSESC1,ADCSESC3,ADCSESC4,ADCSESC6a,ADCSESC6b,ADCSESC9a,ADCSESC9b,ADCSESC10a,ADCSESC10b,ADCSESC13,SyncedToEntraUser,CoerceAndRelayNTLMToSMB,CoerceAndRelayNTLMToADCS,CoerceAndRelayNTLMToLDAP,CoerceAndRelayNTLMToLDAPS,AZAppAdmin,AZCloudAppAdmin,AZContains,AZGlobalAdmin,AZHasRole,AZManagedIdentity,AZMemberOf,AZNodeResourceGroup,AZPrivilegedAuthAdmin,AZPrivilegedRoleAdmin,AZRunsAs,AZAddMembers,AZAddOwner,AZAddSecret,AZExecuteCommand,AZGrant,AZGrantSelf,AZOwns,AZResetPassword,AZMGAddMember,AZMGAddOwner,AZMGAddSecret,AZMGGrantAppRoles,AZMGGrantRole,AZGetCertificates,AZGetKeys,AZGetSecrets,AZAvereContributor,AZKeyVaultContributor,AZOwner,AZContributor,AZUserAccessAdministrator,AZVMAdminLogin,AZVMContributor,AZAKSContributor,AZAutomationContributor,AZLogicAppContributor,AZWebsiteContributor,SyncedToADUser", logger=logger)
            if response.status_code == 200:
                return {"has_path": True, "path": response.json().get("data", [])}
            elif response.status_code == 404:
                return {"has_path": False}
            else:
                if logger:
                    logger.debug(f"Error retrieving shortest path between {source_object_id} and {target_object_id}: {response.text}")
                return {}

    def run_cypher(self, query, include_properties=False, logger=None) -> Dict:
        """Run a Cypher query in BloodHound."""
        with error_suppression(logger.debug if logger else None):
            data = {"include_properties": include_properties, "query": query}
            body = json.dumps(data).encode('utf8')
            response = self._request("POST", "/api/v2/graphs/cypher", body, logger=logger)
            return response.json()


def process_user_da_path(client: Client, domain_name: str, user_sid: str, logger=None) -> Dict:
    """Process Domain Admin pathway for a user."""
    with error_suppression(logger.debug if logger else None):
        try:
            groupname = f"DOMAIN ADMINS@{domain_name}"
            group = client.get_group(groupname, logger=logger)
            group_sid = group['objectid']
            shortest_path = client.get_shortest_path(user_sid, group_sid, logger=logger)
            return {"domain": domain_name, "has_da_path": shortest_path['has_path']}
        except Exception as e:
            if logger:
                logger.debug(f"Error processing DA path for {user_sid} in {domain_name}: {str(e)}")
            return {"domain": domain_name, "has_da_path": "Unknown"}


def fetch_bhe_data(username, logger=None):
    """Fetch BloodHound Enterprise data for a given username."""
    with error_suppression(logger.debug if logger else None):
        try:
            return get_user_data(username, logger=logger)
        except Exception as e:
            if logger:
                logger.debug(f"Error fetching BloodHound data for {username}: {str(e)}")
            return {}


def get_user_data(username: str, logger=None) -> List[Dict]:
    """Get user data from BloodHound Enterprise."""
    with error_suppression(logger.debug if logger else None):
        try:
            credentials = Credentials(token_id=BHE_CONFIG["TOKEN_ID"], token_key=BHE_CONFIG["TOKEN_KEY"])
            client = Client(scheme=BHE_CONFIG["SCHEME"], host=BHE_CONFIG["DOMAIN"], port=BHE_CONFIG["PORT"], credentials=credentials)
            
            DOMAINS = {domain.name: domain.id for domain in client.get_domains(logger=logger) if domain.collected}
            
            user = client.get_user(username, logger=logger)
            user_sid = user['objectid']
            controllables_by_count = client.get_user_controllables(user_sid, logger=logger)
            user_full = client.get_user_full(user['objectid'], logger=logger)
            
            if not user_full:
                if logger:
                    logger.debug(f"User full data not found for {username}")
                return {}
            
            # Extract properties from user data
            props = user_full.get('props', {})
            pwdlastset = props.get('pwdlastset', 0)
            pwdneverexpires = props.get('pwdneverexpires', False)
            enabled = props.get('enabled', False)
            whencreated = props.get('whencreated', 0)
            distinguishedname = props.get('distinguishedname', "Unknown")
            controllables = user_full.get('controllables', {})
            lastlogon = props.get('lastlogon', 0)
            lastlogontimestamp = props.get('lastlogontimestamp', 0)
            passwordcantchange = props.get('passwordcantchange', False)
            
            result = {
                "username": user['name'],
                "objectid": user['objectid'],
                "props": [{
                    "pwdlastset": pwdlastset,
                    "pwdneverexpires": pwdneverexpires,
                    "enabled": enabled,
                    "whencreated": whencreated,
                    "distinguishedname": distinguishedname,
                    "controllables": controllables,
                    "lastlogon": lastlogon,
                    "lastlogontimestamp": lastlogontimestamp,
                    "passwordcantchange": passwordcantchange
                }],
                "controllables": [{"domain": domain, "labels": controllables_by_count.get(domain, {})} for domain in controllables_by_count]
            }
            
            # Process DA paths for each domain
            for domain_name in DOMAINS.keys():
                process_domain = process_user_da_path(client, domain_name, user_sid, logger=logger)
                for domain in result['controllables']:
                    if domain['domain'] == domain_name:
                        domain['labels']["has_da_path"] = process_domain['has_da_path']
                        break
                else:
                    result['controllables'].append({"domain": domain_name, "labels": {"has_da_path": process_domain['has_da_path']}})
            
            return [result]
        except Exception as e:
            if logger:
                logger.debug(f"Error retrieving user data for {username}: {str(e)}")
            return []
    

def handle_bhe_data(bhe_data):
    """Helper function to safely extract BloodHound data regardless of format"""
    if isinstance(bhe_data, list) and bhe_data:
        bhe_item = bhe_data[0]
        return bhe_item.get('props', [{}])[0] if isinstance(bhe_item, dict) else {}
    elif isinstance(bhe_data, dict):
        return bhe_data.get('props', [{}])[0]
    return {}

def extract_da_domains(bhe_data):
    """Helper function to extract DA domains safely"""
    if isinstance(bhe_data, list) and bhe_data:
        bhe_item = bhe_data[0]
        if isinstance(bhe_item, dict):
            return [c['domain'] for c in bhe_item.get('controllables', []) 
                   if isinstance(c, dict) and c.get('labels', {}).get('has_da_path') == True] or 'None'
    elif isinstance(bhe_data, dict):
        return [c['domain'] for c in bhe_data.get('controllables', []) 
               if isinstance(c, dict) and c.get('labels', {}).get('has_da_path') == True] or 'None'
    return 'None'

def extract_controllable_count(bhe_data):
    """Helper function to extract controllable count safely"""
    controllables = []
    if isinstance(bhe_data, list) and bhe_data:
        bhe_item = bhe_data[0]
        if isinstance(bhe_item, dict):
            controllables = bhe_item.get('controllables', [])
    elif isinstance(bhe_data, dict):
        controllables = bhe_data.get('controllables', [])
    
    # Sum up controlled objects safely
    total = 0
    for c in controllables:
        if isinstance(c, dict):
            for k, v in c.get('labels', {}).items():
                if k != 'has_da_path' and str(v).isdigit():
                    total += int(v)
    return total