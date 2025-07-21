#!/usr/bin/env python3
# coding: utf-8
#
# Simple python script using Splunk lookup-editor https://splunkbase.splunk.com/app/1724 rest endpoint to upload 
# lookups (wiki https://lukemurphey.net/projects/splunk-lookup-editor/wiki/REST_endpoints)
#
# Downloaded from https://github.com/mthcht/lookup-editor_scripts and modified
# Original author: mthcht (contact on Twitter)
# Modified by: Becky Burwell, April 26, 2023
# Modified by: Darren Fuller, June 05, 2025
#
########################################################################################################
# Usage: splunk_rest_upload_lookups.py --src-host HOST \
#                                      --src-port PORT \
#                                      --dst-host HOST \
#                                      --dst-port PORT \
#                                      --src-app APP \
#                                      --dst-app APP \
#                                      --lookup-name NAME_OR_ALL
#
# Example: splunk_rest_upload_lookups.py --src-host srchost.customer.net \
#                                        --src-port 8089 \
#                                        --dst-host customername.splunkcloud.com \
#                                        --dst-port 8089 \
#                                        --src-app search \
#                                        --dst-app search \
#                                        --lookup-name all
########################################################################################################

import json
import requests
import logging
import sys
import getpass
import argparse
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning # type: ignore

# Disable warning for insecure requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Setup logging
logging.basicConfig(level=logging.INFO,format='%(asctime)s.%(msecs)03dZ splunk_rest_upload_lookups: %(levelname)s: %(message)s', datefmt='%Y-%m-%dT%H:%M:%S')

def parse_arguments():
    """Parse and validate command line arguments"""
    parser = argparse.ArgumentParser(description='Transfer Splunk lookups between instances')
    
    # Source arguments
    parser.add_argument('--src-host', required=True, help='Source Splunk host')
    parser.add_argument('--src-port', required=True, type=int, help='Source Splunk port')
    parser.add_argument('--src-authtype', choices=['password', 'token'], default='password', help='Source authentication type')
    parser.add_argument('--src-username', help='Source username (required for password auth)')
    parser.add_argument('--src-password', help='Source password (required for password auth)')
    parser.add_argument('--src-token', help='Source token (required for token auth)')
    parser.add_argument('--src-app', required=True, help='Source Splunk app')
    
    # Destination arguments
    parser.add_argument('--dst-host', required=True, help='Destination Splunk host')
    parser.add_argument('--dst-port', required=True, type=int, help='Destination Splunk port')
    parser.add_argument('--dst-authtype', choices=['password', 'token'], default='password', help='Destination authentication type')
    parser.add_argument('--dst-username', help='Destination username (required for password auth)')
    parser.add_argument('--dst-password', help='Destination password (required for password auth)')
    parser.add_argument('--dst-token', help='Destination token (required for token auth)')
    parser.add_argument('--dst-app', help='Destination Splunk app (defaults to source app if not specified)')
    
    # Lookup specification
    parser.add_argument('--lookup-name', required=True, help='Lookup name or "all" for all lookups')
    
    # Transfer options
    parser.add_argument('--overwrite-existing', action='store_true', 
                       help='Overwrite existing lookups (default: skip existing)')
    
    # Debug options
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose HTTP logging')
    
    return parser.parse_args()


def validate_auth_args(args):
    """Validate and prompt for missing authentication arguments"""
    try:
        # Validate source authentication
        if args.src_authtype == 'password':
            if not args.src_username:
                args.src_username = input('Source username: ')
            if not args.src_password:
                args.src_password = getpass.getpass('Source password: ')
        elif args.src_authtype == 'token':
            if not args.src_token:
                args.src_token = getpass.getpass('Source token: ')
        
        # Validate destination authentication
        if args.dst_authtype == 'password':
            if not args.dst_username:
                args.dst_username = input('Destination username: ')
            if not args.dst_password:
                args.dst_password = getpass.getpass('Destination password: ')
        elif args.dst_authtype == 'token':
            if not args.dst_token:
                args.dst_token = getpass.getpass('Destination token: ')
        
        # Set default destination app to source app if not specified
        if not args.dst_app:
            args.dst_app = args.src_app
            
    except KeyboardInterrupt:
        logging.error("Authentication input cancelled by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error during authentication validation: {e}")
        sys.exit(1)


def make_request_with_retry(method, url, max_retries=5, **kwargs):
    """
    Make HTTP request with retry logic and exponential backoff
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: Request URL
        max_retries: Maximum number of retry attempts
        **kwargs: Additional request parameters
        
    Returns:
        requests.Response object
        
    Raises:
        Exception: If all retry attempts fail
    """
    for attempt in range(max_retries):
        try:
            response = requests.request(method, url, verify=False, timeout=60, **kwargs)
            return response
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            if attempt == max_retries - 1:
                logging.error(f"All {max_retries} retry attempts failed for {method} {url}")
                raise e
            delay = 2 ** attempt  # Exponential backoff: 1, 2, 4, 8, 16 seconds
            logging.warning(f"Request failed (attempt {attempt + 1}/{max_retries}), retrying in {delay} seconds: {e}")
            time.sleep(delay)


def get_auth_headers_or_params(authtype, username=None, password=None, token=None):
    """
    Get authentication headers or parameters based on auth type
    
    Args:
        authtype: 'password' or 'token'
        username: Username for password auth
        password: Password for password auth
        token: Token for token auth
        
    Returns:
        dict: Authentication parameters for requests
    """
    if authtype == 'password':
        if not username or not password:
            raise ValueError("Username and password required for password authentication")
        return {'auth': (username, password)}
    elif authtype == 'token':
        if not token:
            raise ValueError("Token required for token authentication")
        return {'headers': {'Authorization': f'Bearer {token}'}}
    else:
        raise ValueError(f"Unsupported auth type: {authtype}")


def get_lookup_metadata(host, port, authtype, app, lookup_name=None, **auth_args):
    """
    Get lookup metadata from Splunk instance (combined function for list and single lookup)
    
    Args:
        host: Splunk host
        port: Splunk port
        authtype: Authentication type
        app: Splunk app
        lookup_name: Specific lookup name (None for all lookups)
        **auth_args: Authentication arguments
        
    Returns:
        list: List of lookup info dictionaries with 'name', 'owner', and 'acl' keys
    """
    url = f"https://{host}:{port}/servicesNS/-/{app}/data/lookup-table-files"
    
    try:
        auth_params = get_auth_headers_or_params(authtype, **auth_args)
    except ValueError as e:
        logging.error(f"Authentication error: {e}")
        return []
    
    params = {
              "output_mode": "json", 
              "count": 0
             }
    
    # Add search parameter if looking for specific lookup
    if lookup_name:
        params["search"] = lookup_name
    
    try:
        response = make_request_with_retry('GET', url, params=params, **auth_params)
        
        if response.status_code != 200:
            logging.error(f"Failed to get lookup metadata: status={response.status_code}, reason={response.reason}")
            if response.status_code == 401:
                logging.error("Authentication failed - check credentials")
            elif response.status_code == 403:
                logging.error("Access denied - check user permissions")
            return []
            
        data = response.json()
        
        if 'entry' not in data:
            if lookup_name:
                logging.error(f"Lookup '{lookup_name}' not found")
            else:
                logging.warning("No lookups found in response")
            return []
            
        lookup_info = []
        for entry in data['entry']:
            if 'name' not in entry:
                continue
                         
            # Filter by app namespace to ensure only app-specific lookups
            acl = entry.get('acl', {})
            if acl.get('app') != app:
                continue
                
            # If searching for specific lookup, ensure exact match
            if lookup_name and entry['name'] != lookup_name:
                continue
            
            # Handle "no owner" case - normalize to "nobody"
            owner = acl.get('owner', 'nobody')
            if owner == 'no owner' or owner == '' or owner is None:
                owner = 'nobody'
                
            lookup_info.append({
                'name': entry['name'],
                'owner': owner,
                'acl': acl  # Include full ACL for permissions replication
            })
        
        if lookup_name and not lookup_info:
            logging.error(f"Lookup '{lookup_name}' not found in app '{app}'")
            
        return lookup_info
        
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error getting lookup metadata: {e}")
        return []
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON response getting lookup metadata: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error getting lookup metadata: {e}")
        return []


def get_lookup_contents(host, port, authtype, app, lookup_name, owner, **auth_args):
    """
    Get contents of a specific lookup from Splunk instance
    
    Args:
        host: Splunk host
        port: Splunk port
        authtype: Authentication type
        app: Splunk app
        lookup_name: Lookup file name
        owner: Lookup owner
        **auth_args: Authentication arguments
        
    Returns:
        dict or None: Lookup contents as JSON, None if failed, "EMPTY" if lookup is empty
    """
    url = f"https://{host}:{port}/services/data/lookup_edit/lookup_data"
    
    try:
        auth_params = get_auth_headers_or_params(authtype, **auth_args)
    except ValueError as e:
        logging.error(f"Authentication error: {e}")
        return None
    
    data = {
        "output_mode": "json",
        "namespace": app,
        "owner": owner,
        "lookup_file": lookup_name
    }
    
    logging.debug(f"Getting lookup contents from {url} with data: {data}")
    
    try:
        response = make_request_with_retry('POST', url, data=data, **auth_params)
        
        if response.status_code == 200:
            result = response.json()
            
            # Check if lookup is empty (only headers or completely empty)
            if not result or (isinstance(result, list) and len(result) <= 1):
                logging.info(f"Lookup '{lookup_name}' is empty, skipping transfer")
                return "EMPTY"
            
            logging.debug(f"Successfully retrieved lookup contents: {len(str(result))} characters")
            return result
        else:
            logging.error(f"Failed to get lookup contents for {lookup_name}: status={response.status_code}, "
                          f"reason={response.reason}")
            if response.text:
                logging.debug(f"Response text: {response.text}")
            if response.status_code == 404:
                logging.error(f"Lookup file '{lookup_name}' not found or not accessible")
            elif response.status_code == 401:
                logging.error("Authentication failed - check credentials")
            elif response.status_code == 403:
                logging.error("Access denied - check user permissions for lookup access")
            return None
            
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error getting lookup contents for {lookup_name}: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON response getting lookup contents for {lookup_name}: {e}")
        if hasattr(response, 'text'):
            logging.debug(f"Response text: {response.text}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error getting lookup contents for {lookup_name}: {e}")
        return None


def check_app_exists(host, port, authtype, app, **auth_args):
    """
    Check if app exists on Splunk instance
    
    Args:
        host: Splunk host
        port: Splunk port
        authtype: Authentication type
        app: Splunk app name
        **auth_args: Authentication arguments
        
    Returns:
        bool: True if app exists, False otherwise
    """
    url = f"https://{host}:{port}/servicesNS/-/-/apps/local/{app}"
    
    try:
        auth_params = get_auth_headers_or_params(authtype, **auth_args)
    except ValueError as e:
        logging.error(f"Authentication error: {e}")
        return False
    
    params = {"output_mode": "json"}
    
    try:
        response = make_request_with_retry('GET', url, params=params, **auth_params)
        
        if response.status_code == 200:
            logging.debug(f"App '{app}' exists on {host}:{port}")
            return True
        elif response.status_code == 404:
            logging.warning(f"App '{app}' does not exist on {host}:{port}")
            return False
        else:
            logging.error(f"Failed to check app existence: status={response.status_code}, reason={response.reason}")
            return False
            
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error checking app existence: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error checking app existence: {e}")
        return False


def check_lookup_exists(host, port, authtype, app, lookup_name, owner, **auth_args):
    """
    Check if a lookup file already exists on destination
    
    Args:
        host: Splunk host
        port: Splunk port
        authtype: Authentication type
        app: Splunk app
        lookup_name: Lookup file name
        owner: Lookup owner
        **auth_args: Authentication arguments
        
    Returns:
        bool: True if lookup exists, False otherwise
    """
    check_url = f"https://{host}:{port}/servicesNS/{owner}/{app}/data/lookup-table-files"
    
    try:
        auth_params = get_auth_headers_or_params(authtype, **auth_args)
    except ValueError as e:
        logging.error(f"Authentication error: {e}")
        return False
    
    params = {"output_mode": "json", "search": lookup_name}
    
    try:
        response = make_request_with_retry('GET', check_url, params=params, **auth_params)
        
        if response.status_code == 200:
            data = response.json()
            if 'entry' in data and len(data['entry']) > 0:
                logging.debug(f"Lookup file '{lookup_name}' already exists")
                return True
        
        return False
            
    except requests.exceptions.RequestException as e:
        logging.debug(f"Network error checking lookup existence: {e}")
        return False
    except Exception as e:
        logging.debug(f"Error checking lookup existence: {e}")
        return False


def create_lookup_file(host, port, authtype, app, lookup_name, owner, **auth_args):
    """
    Create a dummy lookup file on destination if it doesn't exist
    
    Args:
        host: Splunk host
        port: Splunk port
        authtype: Authentication type
        app: Splunk app
        lookup_name: Lookup file name
        owner: Lookup owner (should match source owner)
        **auth_args: Authentication arguments
        
    Returns:
        bool: True if successful or already exists, False otherwise
    """
    # Use the correct namespace with owner to check if file exists
    check_url = f"https://{host}:{port}/servicesNS/{owner}/{app}/data/lookup-table-files"
    
    try:
        auth_params = get_auth_headers_or_params(authtype, **auth_args)
    except ValueError as e:
        logging.error(f"Authentication error: {e}")
        return False
    
    # First check if the lookup file already exists
    params = {"output_mode": "json", "search": lookup_name}
    
    try:
        response = make_request_with_retry('GET', check_url, params=params, **auth_params)
        
        if response.status_code == 200:
            data = response.json()
            if 'entry' in data and len(data['entry']) > 0:
                logging.debug(f"Lookup file '{lookup_name}' already exists with owner '{owner}'")
                return True
        
        # Create a dummy lookup using the lookup_edit API instead of raw file creation
        create_url = f"https://{host}:{port}/services/data/lookup_edit/lookup_contents"
        
        # Create dummy CSV content
        dummy_content = [
            ["temp_field"],
            ["temp_value"]
        ]
        
        data = {
            "output_mode": "json",
            "namespace": app,
            "owner": owner,
            "lookup_file": lookup_name,
            "contents": json.dumps(dummy_content)
        }
        
        logging.debug(f"Creating dummy lookup file '{lookup_name}' on {host}:{port} with owner '{owner}'")
        response = make_request_with_retry('POST', create_url, data=data, **auth_params)
        
        if response.status_code in [200, 201]:
            logging.info(f"Successfully created dummy lookup file '{lookup_name}' with owner '{owner}'")
            return True
        else:
            logging.debug(f"Failed to create dummy lookup file '{lookup_name}': status={response.status_code}")
            if response.text:
                logging.debug(f"Response: {response.text}")
            # Don't fail here - the upload might still work without pre-creating the file
            return True
            
    except requests.exceptions.RequestException as e:
        logging.debug(f"Network error creating lookup file (continuing anyway): {e}")
        return True  # Don't fail the entire process
    except Exception as e:
        logging.debug(f"Unexpected error creating lookup file (continuing anyway): {e}")
        return True  # Don't fail the entire process


def set_lookup_permissions(host, port, authtype, app, lookup_name, owner, acl, **auth_args):
    """
    Set permissions on a lookup file to match source ACL
    
    Args:
        host: Splunk host
        port: Splunk port
        authtype: Authentication type
        app: Splunk app
        lookup_name: Lookup file name
        owner: Lookup owner
        acl: ACL dictionary from source lookup
        **auth_args: Authentication arguments
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Use the correct namespace with owner for ACL endpoint
    url = f"https://{host}:{port}/servicesNS/{owner}/{app}/data/lookup-table-files/{lookup_name}/acl"
    
    try:
        auth_params = get_auth_headers_or_params(authtype, **auth_args)
    except ValueError as e:
        logging.error(f"Authentication error: {e}")
        return False
    
    # Extract relevant ACL settings
    sharing = acl.get('sharing', 'user')  # user, app, global
    perms_read = acl.get('perms', {}).get('read', [])
    perms_write = acl.get('perms', {}).get('write', [])
    
    # Build ACL data
    acl_data = {
        "output_mode": "json",
        "owner": owner, 
        "sharing": sharing,
    }
    
    # Add read permissions if they exist
    if perms_read:
        if isinstance(perms_read, list):
            acl_data["perms.read"] = ",".join(perms_read)
        else:
            acl_data["perms.read"] = str(perms_read)
    
    # Add write permissions if they exist
    if perms_write:
        if isinstance(perms_write, list):
            acl_data["perms.write"] = ",".join(perms_write)
        else:
            acl_data["perms.write"] = str(perms_write)
    
    logging.debug(f"Setting permissions for '{lookup_name}': sharing={sharing}, read={perms_read}, write={perms_write}")
    
    try:
        response = make_request_with_retry('POST', url, data=acl_data, **auth_params)
        
        if response.status_code in [200, 201]:
            logging.info(f"Successfully set permissions for lookup '{lookup_name}' (sharing: {sharing})")
            return True
        else:
            logging.warning(f"Failed to set permissions for lookup '{lookup_name}': status={response.status_code}")
            if response.text:
                logging.debug(f"ACL Response: {response.text}")
            # Don't fail the entire transfer for permission issues
            return True
            
    except requests.exceptions.RequestException as e:
        logging.warning(f"Network error setting permissions for '{lookup_name}': {e}")
        return True  # Don't fail the entire process
    except Exception as e:
        logging.warning(f"Unexpected error setting permissions for '{lookup_name}': {e}")
        return True  # Don't fail the entire process


def upload_lookup(host, port, authtype, app, lookup_name, lookup_content, owner, acl, overwrite_existing, **auth_args):
    """
    Upload lookup to destination Splunk instance
    
    Args:
        host: Splunk host
        port: Splunk port
        authtype: Authentication type
        app: Splunk app
        lookup_name: Lookup file name
        lookup_content: Lookup content as JSON
        owner: Lookup owner (from source)
        acl: ACL dictionary from source lookup
        overwrite_existing: Whether to overwrite existing lookups
        **auth_args: Authentication arguments
        
    Returns:
        tuple: (success: bool, reason: str)
    """
    # Check if destination app exists
    if not check_app_exists(host, port, authtype, app, **auth_args):
        logging.error(f"Destination app '{app}' does not exist on {host}:{port}")
        return False, "Destination app does not exist"
    
    # Check if lookup already exists
    if check_lookup_exists(host, port, authtype, app, lookup_name, owner, **auth_args):
        if not overwrite_existing:
            logging.info(f"Lookup '{lookup_name}' already exists, skipping (use --overwrite-existing to overwrite)")
            return True, "Skipped - already exists"
        else:
            logging.info(f"Lookup '{lookup_name}' already exists, overwriting...")
    
    # Try to create the lookup file if it doesn't exist, with proper owner
    create_lookup_file(host, port, authtype, app, lookup_name, owner, **auth_args)
    
    url = f"https://{host}:{port}/services/data/lookup_edit/lookup_contents"
    
    try:
        auth_params = get_auth_headers_or_params(authtype, **auth_args)
    except ValueError as e:
        logging.error(f"Authentication error: {e}")
        return False, "Authentication error"
    
    data = {
        "output_mode": "json",
        "namespace": app,
        "owner": owner,  # Specify the owner explicitly
        "lookup_file": lookup_name,
        "contents": json.dumps(lookup_content)
    }
    
    logging.debug(f"Uploading lookup to {url}")
    logging.debug(f"Upload data keys: {list(data.keys())}")
    logging.debug(f"Lookup owner: {owner}")
    logging.debug(f"Lookup content size: {len(data['contents'])} characters")
    logging.debug(f"Lookup content preview: {data['contents'][:200]}...")
    
    try:
        response = make_request_with_retry('POST', url, data=data, **auth_params)
        
        logging.debug(f"Upload response status: {response.status_code}")
        if response.text:
            logging.debug(f"Upload response text: {response.text}")
        
        if response.status_code == 200:
            logging.info(f"[SUCCESS] Lookup '{lookup_name}' uploaded to app '{app}' with owner '{owner}'")
            
            # Set permissions to match source
            set_lookup_permissions(host, port, authtype, app, lookup_name, owner, acl, **auth_args)
            
            return True, "Successfully uploaded"
        else:
            error_msg = f"Upload failed: status={response.status_code}, reason={response.reason}"
            logging.error(f"[FAILED] Upload of lookup '{lookup_name}': {error_msg}")
            if response.text:
                logging.error(f"Server response: {response.text}")
            if response.status_code == 401:
                error_msg = "Authentication failed"
            elif response.status_code == 403:
                error_msg = "Access denied"
            elif response.status_code == 400:
                error_msg = "Bad request - check lookup content format"
            elif response.status_code == 500:
                error_msg = "Internal server error - check Splunk logs"
            return False, error_msg
            
    except requests.exceptions.RequestException as e:
        error_msg = f"Network error: {e}"
        logging.error(f"Network error uploading lookup {lookup_name}: {e}")
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        logging.error(f"Unexpected error uploading lookup {lookup_name}: {e}")
        return False, error_msg


def main():
    """Main function to orchestrate the lookup transfer process"""
    try:
        print("Parsing arguments...")
        # Parse and validate arguments
        args = parse_arguments()
        print(f"Arguments parsed successfully: debug={getattr(args, 'debug', False)}")
        
        # Set logging level based on debug flag
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug("Debug logging enabled")
        
        # Enable verbose HTTP logging if requested
        if args.verbose:
            import http.client as http_client
            http_client.HTTPConnection.debuglevel = 1
            logging.getLogger("urllib3.connectionpool").setLevel(logging.DEBUG)
            logging.getLogger("requests.packages.urllib3").setLevel(logging.DEBUG)
        
        print("Validating authentication arguments...")
        validate_auth_args(args)
        print("Authentication validation complete")
        
        # Prepare auth arguments for source and destination
        src_auth_args = {}
        dst_auth_args = {}
        
        if args.src_authtype == 'password':
            src_auth_args = {'username': args.src_username, 'password': args.src_password}
        else:
            src_auth_args = {'token': args.src_token}
        
        if args.dst_authtype == 'password':
            dst_auth_args = {'username': args.dst_username, 'password': args.dst_password}
        else:
            dst_auth_args = {'token': args.dst_token}
        
        # Determine which lookups to transfer
        if args.lookup_name.lower() == 'all':
            logging.info(f"Getting list of all CSV lookups from {args.src_host}:{args.src_port} app '{args.src_app}'")
            lookup_info_list = get_lookup_metadata(args.src_host, args.src_port, args.src_authtype, args.src_app, 
                                                   **src_auth_args)
        else:
            # Check if single lookup name ends with .csv
            if not args.lookup_name.lower().endswith('.csv'):
                logging.error(f"Lookup name '{args.lookup_name}' does not end with .csv - only CSV files are supported")
                sys.exit(1)
            logging.info(f"Getting info for lookup '{args.lookup_name}' from {args.src_host}:{args.src_port} "
                         f"app '{args.src_app}'")
            lookup_info_list = get_lookup_metadata(args.src_host, args.src_port, args.src_authtype, args.src_app, 
                                                   args.lookup_name, **src_auth_args)
        
        if not lookup_info_list:
            logging.error("No CSV lookups found or failed to get lookup metadata")
            sys.exit(1)
            
        logging.info(f"Found {len(lookup_info_list)} CSV lookup(s) to transfer")
        
        # Transfer each lookup
        successful_transfers = 0
        failed_transfers = 0
        skipped_transfers = 0
        failed_lookups = [] 
        skipped_lookups = []
        successful_lookups = []
        
        for lookup_info in lookup_info_list:
            lookup_name = lookup_info['name']
            owner = lookup_info['owner']
            acl = lookup_info['acl']
            
            # Check if lookup name ends with .csv
            if not lookup_name.lower().endswith('.csv'):
                logging.info(f"Skipping non-CSV file: {lookup_name}")
                skipped_transfers += 1
                skipped_lookups.append({
                    'name': lookup_name,
                    'reason': 'Non-CSV file (only CSV files supported)'
                })
                continue
            
            sharing = acl.get('sharing', 'user')
            logging.info(f"Processing lookup: {lookup_name} (owner: {owner}, sharing: {sharing})")
            
            # Get lookup contents from source
            lookup_content = get_lookup_contents(args.src_host, args.src_port, args.src_authtype, 
                                               args.src_app, lookup_name, owner, **src_auth_args)
            
            if lookup_content is None:
                logging.error(f"Failed to get contents for lookup: {lookup_name}")
                failed_transfers += 1
                failed_lookups.append({
                    'name': lookup_name,
                    'reason': 'Failed to get source contents'
                })
                continue
            elif lookup_content == "EMPTY":
                logging.info(f"Skipping empty lookup: {lookup_name}")
                skipped_transfers += 1
                skipped_lookups.append({
                    'name': lookup_name,
                    'reason': 'Empty lookup file'
                })
                continue
            
            # Upload to destination with the same owner and permissions
            success, reason = upload_lookup(args.dst_host, args.dst_port, args.dst_authtype,
                                          args.dst_app, lookup_name, lookup_content, owner, acl, 
                                          args.overwrite_existing, **dst_auth_args)
            
            if success:
                if reason == "Skipped - already exists":
                    skipped_transfers += 1
                    skipped_lookups.append({
                        'name': lookup_name,
                        'reason': reason
                    })
                else:
                    successful_transfers += 1
                    successful_lookups.append({
                        'name': lookup_name,
                        'owner': owner,
                        'acl': acl
                    })
            else:
                failed_transfers += 1
                failed_lookups.append({
                    'name': lookup_name,
                    'reason': reason
                })
        
        # Final summary
        total_lookups = len(lookup_info_list)
        logging.info("=" * 60)
        logging.info("TRANSFER SUMMARY")
        logging.info("=" * 60)
        logging.info(f"Total lookups processed: {total_lookups}")
        logging.info(f"Successfully transferred: {successful_transfers}")
        logging.info(f"Skipped (already exist/empty): {skipped_transfers}")
        logging.info(f"Failed: {failed_transfers}")

        if successful_lookups: 
            logging.info("=" * 60)
            logging.info("SUCCESSFUL LOOKUP TRANSFERS")
            logging.info("=" * 60)
            for lookup in successful_lookups:
                logging.info(f"  {lookup['name']} (owner: {lookup['owner']}, "
                             f"sharing: {lookup['acl'].get('sharing', 'user')})")

        if skipped_lookups:
            logging.info("=" * 60)
            logging.info("SKIPPED LOOKUPS")
            logging.info("=" * 60)
            for skipped_lookup in skipped_lookups:
                logging.info(f"  {skipped_lookup['name']}: {skipped_lookup['reason']}")
                
        if failed_lookups:
            logging.error("=" * 60)
            logging.error("FAILED LOOKUPS")
            logging.error("=" * 60)
            for failed_lookup in failed_lookups:
                logging.error(f"  {failed_lookup['name']}: {failed_lookup['reason']}")
        
        if failed_transfers > 0:
            logging.warning(f"{failed_transfers} lookup(s) failed to transfer")
            sys.exit(1)
        
        logging.info("Transfer completed successfully")
        
    except KeyboardInterrupt:
        logging.error("Script interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error in main: {e}")
        import traceback
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    try:
        print("Starting script...")
        main()
    except Exception as e:
        print(f"Script failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

