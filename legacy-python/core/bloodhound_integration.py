# core/bloodhound_integration.py
"""
BloodHound Enterprise API integration module.
Provides functionality for interacting with BloodHound to retrieve account data.
"""

import base64
import datetime
import hashlib
import hmac
import json
import random
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import requests

from core.config import BHE_CONFIG
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

    def __init__(self, scheme: str, host: str, port: int, credentials: Credentials,
                 timeout=None) -> None:
        """Initialize client with connection parameters and credentials.

        Args:
            timeout: (connect, read) seconds tuple for requests. Defaults to the
                values in BHE_CONFIG; prevents hanging on an unreachable host.
        """
        self._scheme = scheme
        self._host = host
        self._port = port
        self._credentials = credentials
        self._last_request_time = 0
        self._min_request_interval = 0.1  # Minimum 100ms between requests
        self._max_jitter = 0.05  # Up to 50ms random jitter
        self._timeout = timeout or (
            BHE_CONFIG.get("CONNECT_TIMEOUT", 5),
            BHE_CONFIG.get("READ_TIMEOUT", 30),
        )

    def _format_url(self, uri: str) -> str:
        """Format the URL for API requests."""
        formatted_uri = uri
        if uri.startswith("/"):
            formatted_uri = formatted_uri[1:]
        return f"{self._scheme}://{self._host}:{self._port}/{formatted_uri}"

    def _request(self, method: str, uri: str, body: Optional[bytes] = None, logger=None) -> requests.Response:
        """Make an authenticated request to the BloodHound API with rate limiting."""
        with error_suppression(logger.debug if logger else None):
            # Rate limiting: ensure minimum time between requests with jitter
            current_time = time.time()
            time_since_last_request = current_time - self._last_request_time

            if time_since_last_request < self._min_request_interval:
                # Add base delay to meet minimum interval
                sleep_time = self._min_request_interval - time_since_last_request
                # Add random jitter to spread out requests
                sleep_time += random.uniform(0, self._max_jitter)
                time.sleep(sleep_time)

            self._last_request_time = time.time()

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
                    timeout=self._timeout,
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

    def get_domain_users(self, domain_name: str, domain_id: str = None, skip: int = 0, limit: int = 100, logger=None) -> List[Dict]:
        """
        Get all users for a specific domain using REST API.

        Args:
            domain_name: Domain name (e.g., DOMAIN.LOCAL)
            domain_id: Domain object ID (optional)
            skip: Number of results to skip (pagination)
            limit: Maximum results per page
            logger: Optional logger

        Returns:
            List of user dictionaries with name and objectid
        """
        with error_suppression(logger.debug if logger else None):
            all_users = []
            current_skip = skip

            while True:
                # Use search endpoint - search for @DOMAIN.NAME to get domain users
                # This leverages BloodHound's search indexing
                search_query = f"@{domain_name}"
                response = self._request(
                    "GET",
                    f"/api/v2/search?q={search_query}&type=User&skip={current_skip}&limit={limit}",
                    logger=logger
                )

                if response.status_code != 200:
                    if logger:
                        logger.debug(f"Error retrieving users for {domain_name}: {response.text}")
                    break

                data = response.json().get("data", [])

                if not data:
                    break

                # Add users from this page
                all_users.extend(data)

                # Check if we got fewer results than limit (last page)
                if len(data) < limit:
                    break

                current_skip += limit

                # Safety limit to avoid infinite loops
                if current_skip > 5000:
                    if logger:
                        logger.debug(f"Hit safety limit of 5000 users for {domain_name}")
                    break

            if logger:
                logger.debug(f"Retrieved {len(all_users)} users for {domain_name}")

            return all_users

    def get_computer(self, computername: str, logger=None) -> Dict:
        """Get computer information from BloodHound."""
        with error_suppression(logger.debug if logger else None):
            # Properly URL-encode the computer name for the query parameter
            encoded_computername = urllib.parse.quote(computername, safe='')
            search_limit = BHE_CONFIG["SEARCH_LIMIT"]
            response = self._request("GET", f"/api/v2/search?q={encoded_computername}&type=Computer&limit={search_limit}", logger=logger)
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
            # Properly URL-encode the username for the query parameter
            encoded_username = urllib.parse.quote(username, safe='')
            search_limit = BHE_CONFIG["SEARCH_LIMIT"]
            response = self._request("GET", f"/api/v2/search?q={encoded_username}&type=User&limit={search_limit}", logger=logger)
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
            # Properly URL-encode the group name for the query parameter
            encoded_groupname = urllib.parse.quote(groupname, safe='')
            search_limit = BHE_CONFIG["SEARCH_LIMIT"]
            response = self._request("GET", f"/api/v2/search?q={encoded_groupname}&type=Group&limit={search_limit}", logger=logger)
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
            controllables_limit = BHE_CONFIG["CONTROLLABLES_LIMIT"]
            response = self._request("GET", f"/api/v2/base/{object_id}/controllables?skip=0&limit={controllables_limit}&type=list", logger=logger)
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

    def get_shortest_path(self, source_object_id: str, target_object_id: str,
                          only_traversable: bool = True, logger=None) -> Dict:
        """Get the shortest path between two objects in BloodHound.

        Args:
            only_traversable: When True (default), pathfinding is restricted to
                BloodHound's traversable (attack-path) edge kinds, so a returned
                path represents a real privilege-escalation route rather than mere
                graph connectivity. When False, all edge kinds (including purely
                informational ones) are searched, which over-reports DA pathways.
        """
        with error_suppression(logger.debug if logger else None):
            uri = (f"/api/v2/graphs/shortest-path?start_node={source_object_id}"
                   f"&end_node={target_object_id}")
            if only_traversable:
                uri += "&only_traversable=true"
            response = self._request("GET", uri, logger=logger)
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

    def get_group_members(self, group_id: str, limit: int = 1000, logger=None) -> List[Dict]:
        """
        Get members of a group using REST API (Community Edition compatible).

        Uses: GET /api/v2/groups/{group_id}/members?type=list

        Args:
            group_id: Group object ID (SID)
            limit: Maximum number of members to return
            logger: Optional logger

        Returns:
            List of member dictionaries with 'name', 'objectid', 'label' fields
        """
        with error_suppression(logger.debug if logger else None):
            members = []
            skip = 0
            page_size = min(limit, 1000)

            while skip < limit:
                response = self._request(
                    "GET",
                    f"/api/v2/groups/{group_id}/members?type=list&skip={skip}&limit={page_size}",
                    logger=logger
                )

                if response.status_code != 200:
                    if logger:
                        logger.debug(f"Error getting group members for {group_id}: {response.text}")
                    break

                data = response.json().get("data", [])
                if not data:
                    break

                members.extend(data)
                skip += len(data)

                # If we got fewer results than requested, we've reached the end
                if len(data) < page_size:
                    break

            return members[:limit]

    def get_user_memberships(self, user_id: str, limit: int = 1000, logger=None) -> List[Dict]:
        """
        Get groups a user is a member of using REST API (Community Edition compatible).

        Uses: GET /api/v2/users/{user_id}/memberships?type=list

        Args:
            user_id: User object ID (SID)
            limit: Maximum number of groups to return
            logger: Optional logger

        Returns:
            List of group dictionaries with 'name', 'objectid', 'label' fields
        """
        with error_suppression(logger.debug if logger else None):
            groups = []
            skip = 0
            page_size = min(limit, 1000)

            while skip < limit:
                response = self._request(
                    "GET",
                    f"/api/v2/users/{user_id}/memberships?type=list&skip={skip}&limit={page_size}",
                    logger=logger
                )

                if response.status_code != 200:
                    if logger:
                        logger.debug(f"Error getting user memberships for {user_id}: {response.text}")
                    break

                data = response.json().get("data", [])
                if not data:
                    break

                groups.extend(data)
                skip += len(data)

                if len(data) < page_size:
                    break

            return groups[:limit]


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
                   if isinstance(c, dict) and c.get('labels', {}).get('has_da_path') is True] or 'None'
    elif isinstance(bhe_data, dict):
        return [c['domain'] for c in bhe_data.get('controllables', []) 
               if isinstance(c, dict) and c.get('labels', {}).get('has_da_path') is True] or 'None'
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


def test_bloodhound_connection(verbose: bool = True, config_override: Optional[Dict] = None) -> Tuple[bool, Dict[str, Any]]:
    """
    Test BloodHound API connection and credentials.

    Args:
        verbose: Print detailed output to console
        config_override: Optional config dict to override BHE_CONFIG (for testing)

    Returns:
        Tuple of (success: bool, results: dict)
        results dict contains:
            - connected: bool
            - version: APIVersion object (if successful)
            - domains: List[Domain] (if successful)
            - sample_user: dict (if successful)
            - error: str (if failed)
    """
    config = config_override if config_override else BHE_CONFIG
    results = {
        'connected': False,
        'version': None,
        'domains': [],
        'sample_user': None,
        'error': None
    }

    if verbose:
        print("\n" + "="*70)
        print("BloodHound Connection Test")
        print("="*70)
        print(f"Host: {config['SCHEME']}://{config['DOMAIN']}:{config['PORT']}")
        print(f"Token ID: {config['TOKEN_ID'][:20]}..." if len(config['TOKEN_ID']) > 20 else f"Token ID: {config['TOKEN_ID']}")
        print("="*70 + "\n")

    try:
        # Step 1: Initialize client
        if verbose:
            print("Step 1: Initializing BloodHound client...")

        credentials = Credentials(
            token_id=config['TOKEN_ID'],
            token_key=config['TOKEN_KEY']
        )
        client = Client(
            scheme=config['SCHEME'],
            host=config['DOMAIN'],
            port=config['PORT'],
            credentials=credentials
        )

        if verbose:
            print("✓ Client initialized\n")

        # Step 2: Test API connection and get version
        if verbose:
            print("Step 2: Testing API connection (GET /api/version)...")

        try:
            version = client.get_version()
            results['version'] = version
            results['connected'] = True

            if verbose:
                print("✓ Successfully connected to BloodHound!")
                print(f"  Server Version: {version.server_version}")
                print(f"  API Version: {version.api_version}\n")
        except requests.exceptions.ConnectionError as e:
            results['error'] = f"Connection failed: Unable to reach {config['DOMAIN']}:{config['PORT']}"
            if verbose:
                print("✗ Connection failed")
                print(f"  Error: Unable to reach {config['DOMAIN']}:{config['PORT']}")
                print(f"  Details: {str(e)}\n")
            return False, results
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                results['error'] = "Authentication failed: Invalid token ID or token key"
                if verbose:
                    print("✗ Authentication failed")
                    print("  Error: Invalid credentials (401 Unauthorized)")
                    print("  Please check your token_id and token_key in config/bloodhound.json\n")
            else:
                results['error'] = f"HTTP Error: {e.response.status_code}"
                if verbose:
                    print(f"✗ HTTP Error: {e.response.status_code}")
                    print(f"  Details: {str(e)}\n")
            return False, results
        except Exception as e:
            results['error'] = f"Unexpected error: {str(e)}"
            if verbose:
                print("✗ Unexpected error")
                print(f"  Error: {str(e)}\n")
            return False, results

        # Step 3: Get available domains
        if verbose:
            print("Step 3: Fetching available domains...")

        try:
            domains = client.get_domains()
            results['domains'] = domains

            if verbose:
                if domains:
                    print(f"✓ Found {len(domains)} domain(s):")
                    for domain in domains:
                        collected_status = "✓ Collected" if domain.collected else "✗ Not Collected"
                        print(f"  - {domain.name} ({domain.type}) - {collected_status}")
                else:
                    print("  ⚠ No domains found in BloodHound")
                print()
        except Exception as e:
            if verbose:
                print("⚠ Warning: Could not fetch domains")
                print(f"  Error: {str(e)}\n")

        # Step 4: Test sample query (get one user from first domain)
        if verbose:
            print("Step 4: Testing sample data query...")

        if results['domains']:
            try:
                first_domain = results['domains'][0]
                users = client.get_domain_users(first_domain.name, first_domain.id, limit=1)

                if users:
                    results['sample_user'] = users[0]
                    if verbose:
                        print(f"✓ Successfully queried domain '{first_domain.name}'")
                        print(f"  Sample user: {users[0].get('name', 'Unknown')}")
                        print()
                else:
                    if verbose:
                        print(f"⚠ No users found in domain '{first_domain.name}'")
                        print()
            except Exception as e:
                if verbose:
                    print("⚠ Warning: Sample query failed")
                    print(f"  Error: {str(e)}\n")
        else:
            if verbose:
                print("⚠ Skipping sample query (no domains available)\n")

        # Final summary
        if verbose:
            print("="*70)
            print("TEST SUMMARY")
            print("="*70)
            print("✓ Connection: SUCCESS")
            print(f"✓ API Version: {version.api_version}")
            print(f"✓ Server Version: {version.server_version}")
            print(f"✓ Available Domains: {len(results['domains'])}")
            if results['sample_user']:
                print("✓ Sample Query: SUCCESS")
            print("="*70 + "\n")
            print("🎉 BloodHound credentials are working correctly!\n")

        return True, results

    except Exception as e:
        results['error'] = f"Test failed: {str(e)}"
        if verbose:
            print(f"\n✗ Test failed with error: {str(e)}\n")
        return False, results


def get_bloodhound_client(logger=None) -> Optional[Client]:
    """
    Get a BloodHound client if connection is available.

    This function attempts to create and test a BloodHound client connection.
    Used for checking BloodHound availability at startup.

    Args:
        logger: Optional logger instance for debug output

    Returns:
        Client instance if connection successful, None otherwise
    """
    try:
        # Create credentials and client
        credentials = Credentials(
            token_id=BHE_CONFIG["TOKEN_ID"],
            token_key=BHE_CONFIG["TOKEN_KEY"]
        )
        client = Client(
            scheme=BHE_CONFIG["SCHEME"],
            host=BHE_CONFIG["DOMAIN"],
            port=BHE_CONFIG["PORT"],
            credentials=credentials
        )

        # Test connection by getting version. get_version suppresses its own
        # exceptions and returns None on failure, so an explicit None check is
        # required -- otherwise an unreachable host is reported as "connected".
        version = client.get_version(logger=logger)
        if version is None:
            if logger:
                logger.debug("BloodHound connection check failed: no version returned")
            return None

        if logger:
            logger.debug(f"BloodHound connection successful: {version.server_version}")

        return client

    except Exception as e:
        # Connection failed - this is normal if BloodHound isn't configured
        if logger:
            logger.debug(f"BloodHound connection not available: {str(e)}")
        return None