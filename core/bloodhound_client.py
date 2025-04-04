"""
To utilize this example please install requests. The rest of the dependencies are part of the Python 3 standard
library.

# pip install --upgrade requests

Note: this script was written for Python 3.6.X or greater.

Insert your BHE API creds in the BHE constants and change the PRINT constants to print desired data.
"""

import hmac
import hashlib
import base64
import requests
import datetime
import json
from typing import Optional
import argparse

import sys
import os

# Add the parent directory of 'utils' to the system path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.logging import setup_logging

# Update with your BloodHound info
BHE_DOMAIN = ""
BHE_PORT = 8080
BHE_SCHEME = "http"
BHE_TOKEN_ID = ""
BHE_TOKEN_KEY = ""

PRINT_PRINCIPALS = False
PRINT_ATTACK_PATH_TIMELINE_DATA = False
PRINT_POSTURE_DATA = False

DATA_START = "1970-01-01T00:00:00.000Z"
DATA_END = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'  # Now

class Credentials(object):
    def __init__(self, token_id: str, token_key: str) -> None:
        self.token_id = token_id
        self.token_key = token_key

class APIVersion(object):
    def __init__(self, api_version: str, server_version: str) -> None:
        self.api_version = api_version
        self.server_version = server_version

class Domain(object):
    def __init__(self, name: str, id: str, collected: bool, domain_type: str) -> None:
        self.name = name
        self.id = id
        self.type = domain_type
        self.collected = collected

class Client(object):
    def __init__(self, scheme: str, host: str, port: int, credentials: Credentials) -> None:
        self._scheme = scheme
        self._host = host
        self._port = port
        self._credentials = credentials

    def _format_url(self, uri: str) -> str:
        formatted_uri = uri
        if uri.startswith("/"):
            formatted_uri = formatted_uri[1:]
        return f"{self._scheme}://{self._host}:{self._port}/{formatted_uri}"

    def _request(self, method: str, uri: str, body: Optional[bytes] = None, logger=None) -> requests.Response:
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
                logger.error(f"Request failed for {method} {uri}: {str(e)}")
            raise

    def get_version(self, logger=None) -> APIVersion:
        response = self._request("GET", "/api/version", logger=logger)
        payload = response.json()
        return APIVersion(api_version=payload["data"]["API"]["current_version"], server_version=payload["data"]["server_version"])

    def get_domains(self, logger=None) -> list[Domain]:
        response = self._request('GET', '/api/v2/available-domains', logger=logger)
        payload = response.json()['data']
        domains = [Domain(domain["name"], domain["id"], domain["collected"], domain["type"]) for domain in payload]
        return domains

    def get_computer(self, computername: str, logger=None) -> dict:
        response = self._request("GET", f"/api/v2/search?q={computername}&type=Computer&limit=1", logger=logger)
        if response.status_code != 200:
            logger.error(f"Error retrieving computer {computername}: {response.text}")
            return {}
        data = response.json().get("data", [])
        if not data:
            logger.error(f"Computer {computername} not found")
            return {}
        return data[0]

    def get_computer_full(self, object_id: str, logger=None) -> dict:
        response = self._request("GET", f"/api/v2/base/{object_id}", logger=logger)
        if response.status_code != 200:
            logger.error(f"Error retrieving computer {object_id}: {response.text}")
            return {}
        data = response.json().get("data")
        if not data:
            logger.error(f"Computer {object_id} not found")
            return {}
        return data

    def get_user(self, username: str, logger=None) -> dict:
        response = self._request("GET", f"/api/v2/search?q={username}&type=User&limit=1", logger=logger)
        if response.status_code != 200:
            logger.error(f"Error retrieving user {username}: {response.text}")
            return {}
        data = response.json().get("data", [])
        if not data:
            logger.error(f"User {username} not found")
            return {}
        return data[0]

    def get_user_full(self, object_id: str, logger=None) -> dict:
        response = self._request("GET", f"/api/v2/users/{object_id}", logger=logger)
        if response.status_code != 200:
            logger.error(f"Error retrieving user {object_id}: {response.text}")
            return {}
        data = response.json().get("data")
        if not data:
            logger.error(f"User {object_id} not found")
            return {}
        return data

    def get_group(self, groupname: str, logger=None) -> dict:
        groupname = groupname.replace(" ", "%20")
        response = self._request("GET", f"/api/v2/search?q={groupname}&type=Group&limit=1", logger=logger)
        if response.status_code != 200:
            logger.error(f"Error retrieving group {groupname}: {response.text}")
            return {}
        data = response.json().get("data", [])
        if not data:
            logger.error(f"Group {groupname} not found")
            return {}
        return data[0]

    def get_user_controllables(self, object_id: str, logger=None) -> dict:
        response = self._request("GET", f"/api/v2/base/{object_id}/controllables?skip=0&limit=10&type=list", logger=logger)
        if response.status_code != 200:
            logger.error(f"Error retrieving user controllables for {object_id}: {response.text}")
            return {}
        
        count = response.json().get("count", 0)
        response = self._request("GET", f"/api/v2/base/{object_id}/controllables?skip=0&limit={count}&type=list", logger=logger)
        if response.status_code != 200:
            logger.error(f"Error retrieving full user controllables for {object_id}: {response.text}")
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
                    logger.error(f"Error resolving domain for {name}: {str(e)}")
            
            if domain not in controllables_lable_and_count:
                controllables_lable_and_count[domain] = {}
            if label not in controllables_lable_and_count[domain]:
                controllables_lable_and_count[domain][label] = 0
            controllables_lable_and_count[domain][label] += 1
        
        return controllables_lable_and_count

    def get_shortest_path(self, source_object_id: str, target_object_id: str, logger=None) -> dict:
        response = self._request("GET", f"/api/v2/graphs/shortest-path?start_node={source_object_id}&end_node={target_object_id}&relationship_kinds=in:Contains,GPLink,HasSIDHistory,MemberOf,TrustedBy,AdminTo,AllowedToAct,AllowedToDelegate,CanPSRemote,CanRDP,ExecuteDCOM,SQLAdmin,CoerceToTGT,DCSync,DumpSMSAPassword,HasSession,ReadGMSAPassword,ReadLAPSPassword,SyncLAPSPassword,AddMember,AddSelf,AllExtendedRights,ForceChangePassword,GenericAll,Owns,GenericWrite,WriteDacl,WriteOwner,AddAllowedToAct,AddKeyCredentialLink,WriteAccountRestrictions,WriteGPLink,WriteSPN,GoldenCert,ADCSESC1,ADCSESC3,ADCSESC4,ADCSESC6a,ADCSESC6b,ADCSESC9a,ADCSESC9b,ADCSESC10a,ADCSESC10b,ADCSESC13,SyncedToEntraUser,CoerceAndRelayNTLMToSMB,CoerceAndRelayNTLMToADCS,CoerceAndRelayNTLMToLDAP,CoerceAndRelayNTLMToLDAPS,AZAppAdmin,AZCloudAppAdmin,AZContains,AZGlobalAdmin,AZHasRole,AZManagedIdentity,AZMemberOf,AZNodeResourceGroup,AZPrivilegedAuthAdmin,AZPrivilegedRoleAdmin,AZRunsAs,AZAddMembers,AZAddOwner,AZAddSecret,AZExecuteCommand,AZGrant,AZGrantSelf,AZOwns,AZResetPassword,AZMGAddMember,AZMGAddOwner,AZMGAddSecret,AZMGGrantAppRoles,AZMGGrantRole,AZGetCertificates,AZGetKeys,AZGetSecrets,AZAvereContributor,AZKeyVaultContributor,AZOwner,AZContributor,AZUserAccessAdministrator,AZVMAdminLogin,AZVMContributor,AZAKSContributor,AZAutomationContributor,AZLogicAppContributor,AZWebsiteContributor,SyncedToADUser", logger=logger)
        if response.status_code == 200:
            return {"has_path": True, "path": response.json().get("data", [])}
        elif response.status_code == 404:
            return {"has_path": False}
        else:
            logger.error(f"Error retrieving shortest path between {source_object_id} and {target_object_id}: {response.text}")
            return {}

    def run_cypher(self, query, include_properties=False, logger=None) -> dict:
        data = {"include_properties": include_properties, "query": query}
        body = json.dumps(data).encode('utf8')
        response = self._request("POST", "/api/v2/graphs/cypher", body, logger=logger)
        return response.json()

def process_user_da_path(client: Client, domain_name: str, user_sid: str, logger=None) -> dict:
    groupname = f"DOMAIN ADMINS@{domain_name}"
    try:
        group = client.get_group(groupname, logger=logger)
        group_sid = group['objectid']
        shortest_path = client.get_shortest_path(user_sid, group_sid, logger=logger)
        return {"domain": domain_name, "has_da_path": shortest_path['has_path']}
    except Exception as e:
        logger.error(f"Error processing DA path for {user_sid} in {domain_name}: {str(e)}")
        return {"domain": domain_name, "has_da_path": "Unknown"}

def get_user_data(username: str, logger=None) -> dict:
    credentials = Credentials(token_id=BHE_TOKEN_ID, token_key=BHE_TOKEN_KEY)
    client = Client(scheme=BHE_SCHEME, host=BHE_DOMAIN, port=BHE_PORT, credentials=credentials)
    
    DOMAINS = {domain.name: domain.id for domain in client.get_domains(logger=logger) if domain.collected}
    
    try:
        user = client.get_user(username, logger=logger)
        user_sid = user['objectid']
        controllables_by_count = client.get_user_controllables(user_sid, logger=logger)
        user_full = client.get_user_full(user['objectid'], logger=logger)
        
        if not user_full:
            logger.error(f"User full data not found for {username}")
            return {}
        
        pwdlastset = user_full.get('props', {}).get('pwdlastset', 0)
        pwdneverexpires = user_full.get('props', {}).get('pwdneverexpires', False)
        enabled = user_full.get('props', {}).get('enabled', False)
        whencreated = user_full.get('props', {}).get('whencreated', DATA_START)
        distinguishedname = user_full.get('props', {}).get('distinguishedname', "Unknown")
        controllables = user_full.get('controllables', {})
        lastlogon = user_full.get('props', {}).get('lastlogon', DATA_START)
        lastlogontimestamp = user_full.get('props', {}).get('lastlogontimestamp', DATA_START)
        passwordcantchange = user_full.get('props', {}).get('passwordcantchange', False)
        
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
        logger.error(f"Error retrieving user data for {username}: {str(e)}")
        return []

def main():
    parser = argparse.ArgumentParser(description='Get user data from BHE API')
    parser.add_argument('username', type=str, help='The username to query')
    args = parser.parse_args()

    logger = setup_logging()
    user_data = get_user_data(args.username, logger=logger)
    print(json.dumps(user_data, indent=4))

if __name__ == "__main__":
    main()