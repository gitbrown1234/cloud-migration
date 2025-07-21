import os, sys
import time
import json
import requests
import xml.etree.ElementTree as ET
import re
import logging # Explicitly import logging
from requests.exceptions import ConnectionError, Timeout
from requests.packages.urllib3.exceptions import InsecureRequestWarning # type: ignore

# Disable warning for insecure requests globally for requests module
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Add the lib directory to the sys.path for splunklib
# This assumes the script is placed in $SPLUNK_HOME/etc/apps/<your_app>/bin/
# and splunklib is in $SPLUNK_HOME/etc/apps/<your_app>/lib/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators


@Configuration()
class LookupMigratorCommand(GeneratingCommand):
    """
    The lookupmigrator command transfers Splunk lookups between instances.

    Example:
    ``| lookupmigrator src_host="localhost" src_port=8089 src_username="admin" src_password="password" src_app="search" dst_host="your-splunk-cloud.com" dst_port=8089 dst_token="YOUR_CLOUD_TOKEN" lookup_name="all" enable_overwrite_existing=true``

    Or for a specific lookup:
    ``| lookupmigrator src_host="localhost" src_port=8089 src_username="admin" src_password="password" src_app="search" dst_host="your-splunk-cloud.com" dst_port=8089 dst_token="YOUR_CLOUD_TOKEN" lookup_name="my_lookup.csv"``
    """

    # Source arguments
    src_host = Option(require=True, validate=validators.String())
    src_port = Option(require=True, validate=validators.Integer())
    src_authtype = Option(require=False, validate=validators.Set('password', 'token'), default='password')
    src_username = Option(require=False, validate=validators.String(), default="")
    src_password = Option(require=False, validate=validators.String(), default="")
    src_token = Option(require=False, validate=validators.String(), default="")
    src_app = Option(require=True, validate=validators.String())

    # Destination arguments
    dst_host = Option(require=True, validate=validators.String())
    dst_port = Option(require=True, validate=validators.Integer())
    dst_authtype = Option(require=False, validate=validators.Set('password', 'token'), default='password')
    dst_username = Option(require=False, validate=validators.String(), default="")
    dst_password = Option(require=False, validate=validators.String(), default="")
    dst_token = Option(require=False, validate=validators.String(), default="")
    dst_app = Option(require=False, validate=validators.String(), default="") # Defaults to src_app if not specified

    # Lookup specification
    lookup_name = Option(require=True, validate=validators.String()) # "all" or specific lookup.csv

    # Transfer options
    enable_overwrite_existing = Option(require=False, validate=validators.Boolean(), default=False)

    # Debug options
    enable_debug = Option(require=False, validate=validators.Boolean(), default=False)
    enable_verbose_http = Option(require=False, validate=validators.Boolean(), default=False)

    # Class attributes (constants from original script)
    SUPPORTED_FIELDS = [
        "capabilities", "cumulativeRTSrchJobsQuota", "cumulativeSrchJobsQuota", "defaultApp",
        "imported_roles", "rtSrchJobsQuota", "srchDiskQuota", "srchFilter",
        "srchIndexesAllowed", "srchIndexesDefault", "srchJobsQuota", "srchTimeWin"
    ]
    NAMESPACES = {
        "atom": "http://www.w3.org/2005/Atom",
        "s": "http://dev.splunk.com/ns/rest"
    }

    def generate(self):
        """
        Main generator method for the Splunk custom command.
        It orchestrates the lookup transfer process.
        """
        # Set logging level based on debug flag
        if self.enable_debug:
            self.logger.setLevel(logging.DEBUG)
            yield self._create_event("INFO", "Debug logging enabled.")
        else:
            self.logger.setLevel(logging.INFO)

        # Enable verbose HTTP logging if requested (requires http.client import)
        if self.enable_verbose_http:
            try:
                import http.client as http_client
                http_client.HTTPConnection.debuglevel = 1
                logging.getLogger("urllib3.connectionpool").setLevel(logging.DEBUG)
                logging.getLogger("requests.packages.urllib3").setLevel(logging.DEBUG)
                yield self._create_event("INFO", "Verbose HTTP logging enabled.")
            except ImportError:
                yield self._create_event("WARNING", "Could not enable verbose HTTP logging: http.client not available.")

        # Set default destination app to source app if not specified
        if not self.dst_app:
            self.dst_app = self.src_app

        # Prepare auth arguments for source and destination
        src_auth_args = {}
        dst_auth_args = {}

        # Validate and prepare source authentication
        if self.src_authtype == 'password':
            if not self.src_username or not self.src_password:
                yield self._create_event("ERROR", "Source username and password are required for password authentication.")
                return
            src_auth_args = {'username': self.src_username, 'password': self.src_password}
        elif self.src_authtype == 'token':
            if not self.src_token:
                yield self._create_event("ERROR", "Source token is required for token authentication.")
                return
            src_auth_args = {'token': self.src_token}

        # Validate and prepare destination authentication
        if self.dst_authtype == 'password':
            if not self.dst_username or not self.dst_password:
                yield self._create_event("ERROR", "Destination username and password are required for password authentication.")
                return
            dst_auth_args = {'username': self.dst_username, 'password': self.dst_password}
        elif self.dst_authtype == 'token':
            if not self.dst_token:
                yield self._create_event("ERROR", "Destination token is required for token authentication.")
                return
            dst_auth_args = {'token': self.dst_token}

        # Determine which lookups to transfer
        lookup_info_list = []
        if self.lookup_name.lower() == 'all':
            yield self._create_event("INFO", f"Getting list of all CSV lookups from {self.src_host}:{self.src_port} app '{self.src_app}'")
            get_metadata_generator = self._get_lookup_metadata(self.src_host, self.src_port, self.src_authtype, self.src_app, **src_auth_args)
            for event in get_metadata_generator:
                if event.get("log_level") == "LOOKUP_METADATA_FETCHED":
                    lookup_info_list = event.get("message")
                yield event
        else:
            # Check if single lookup name ends with .csv
            if not self.lookup_name.lower().endswith('.csv'):
                yield self._create_event("ERROR", f"Lookup name '{self.lookup_name}' does not end with .csv - only CSV files are supported.")
                return
            yield self._create_event("INFO", f"Getting info for lookup '{self.lookup_name}' from {self.src_host}:{self.src_port} app '{self.src_app}'")
            get_metadata_generator = self._get_lookup_metadata(self.src_host, self.src_port, self.src_authtype, self.src_app, lookup_name=self.lookup_name, **src_auth_args)
            for event in get_metadata_generator:
                if event.get("log_level") == "LOOKUP_METADATA_FETCHED":
                    lookup_info_list = event.get("message")
                yield event

        if not lookup_info_list:
            yield self._create_event("ERROR", "No CSV lookups found or failed to get lookup metadata.")
            return

        yield self._create_event("INFO", f"Found {len(lookup_info_list)} CSV lookup(s) to transfer.")

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

            # Check if lookup name ends with .csv (redundant if lookup_name is specified, but good for 'all')
            if not lookup_name.lower().endswith('.csv'):
                yield self._create_event("INFO", f"Skipping non-CSV file: {lookup_name}")
                skipped_transfers += 1
                skipped_lookups.append({'name': lookup_name, 'reason': 'Non-CSV file (only CSV files supported)'})
                continue

            sharing = acl.get('sharing', 'user')
            yield self._create_event("INFO", f"Processing lookup: {lookup_name} (owner: {owner}, sharing: {sharing})")

            # Get lookup contents from source
            lookup_content = None
            get_contents_generator = self._get_lookup_contents(self.src_host, self.src_port, self.src_authtype,
                                                               self.src_app, lookup_name, owner, **src_auth_args)
            for event in get_contents_generator:
                if event.get("log_level") == "LOOKUP_CONTENTS_FETCHED":
                    lookup_content = event.get("message")
                yield event

            if lookup_content is None:
                yield self._create_event("ERROR", f"Failed to get contents for lookup: {lookup_name}")
                failed_transfers += 1
                failed_lookups.append({'name': lookup_name, 'reason': 'Failed to get source contents'})
                continue
            elif lookup_content == "EMPTY":
                yield self._create_event("INFO", f"Skipping empty lookup: {lookup_name}")
                skipped_transfers += 1
                skipped_lookups.append({'name': lookup_name, 'reason': 'Empty lookup file'})
                continue

            # Upload to destination with the same owner and permissions
            upload_result_success = False
            upload_result_reason = ""
            upload_generator = self._upload_lookup(self.dst_host, self.dst_port, self.dst_authtype,
                                                   self.dst_app, lookup_name, lookup_content, owner, acl,
                                                   self.enable_overwrite_existing, **dst_auth_args)
            for event in upload_generator:
                if event.get("log_level") == "LOOKUP_UPLOAD_RESULT":
                    upload_result_success = event.get("success")
                    upload_result_reason = event.get("reason")
                yield event

            if upload_result_success:
                if upload_result_reason == "Skipped - already exists":
                    skipped_transfers += 1
                    skipped_lookups.append({'name': lookup_name, 'reason': upload_result_reason})
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
                    'reason': upload_result_reason
                })

        # Final summary
        total_lookups = len(lookup_info_list)
        yield self._create_event("INFO", "=" * 60)
        yield self._create_event("INFO", "TRANSFER SUMMARY")
        yield self._create_event("INFO", "=" * 60)
        yield self._create_event("INFO", f"Total lookups processed: {total_lookups}")
        yield self._create_event("INFO", f"Successfully transferred: {successful_transfers}")
        yield self._create_event("INFO", f"Skipped (already exist/empty): {skipped_transfers}")
        yield self._create_event("INFO", f"Failed: {failed_transfers}")

        if successful_lookups:
            yield self._create_event("INFO", "=" * 60)
            yield self._create_event("INFO", "SUCCESSFUL LOOKUP TRANSFERS")
            yield self._create_event("INFO", "=" * 60)
            for lookup in successful_lookups:
                yield self._create_event("INFO", f"  {lookup['name']} (owner: {lookup['owner']}, sharing: {lookup['acl'].get('sharing', 'user')})",
                                         lookup_name=lookup['name'], owner=lookup['owner'], sharing=lookup['acl'].get('sharing', 'user'))

        if skipped_lookups:
            yield self._create_event("INFO", "=" * 60)
            yield self._create_event("INFO", "SKIPPED LOOKUPS")
            yield self._create_event("INFO", "=" * 60)
            for skipped_lookup in skipped_lookups:
                yield self._create_event("INFO", f"  {skipped_lookup['name']}: {skipped_lookup['reason']}",
                                         lookup_name=skipped_lookup['name'], reason=skipped_lookup['reason'])

        if failed_lookups:
            yield self._create_event("ERROR", "=" * 60)
            yield self._create_event("ERROR", "FAILED LOOKUPS")
            yield self._create_event("ERROR", "=" * 60)
            for failed_lookup in failed_lookups:
                yield self._create_event("ERROR", f"  {failed_lookup['name']}: {failed_lookup['reason']}",
                                         lookup_name=failed_lookup['name'], reason=failed_lookup['reason'])

        if failed_transfers > 0:
            yield self._create_event("WARNING", f"{failed_transfers} lookup(s) failed to transfer.")
        else:
            yield self._create_event("INFO", "Transfer completed successfully.")
            # lookupmigrator.py - Block 2 of 5

    def _create_event(self, log_level, message, **kwargs):
        """
        Helper method to create a consistent event dictionary for yielding.
        """
        event = {
            '_time': time.time(),
            'log_level': log_level,
            'message': message,
            '_raw': message
        }
        event.update(kwargs)
        return event

    def _make_request_with_retry(self, method, url, max_retries=5, **kwargs):
        """
        Make HTTP request with retry logic and exponential backoff
        Yields events for retries or errors.
        """
        for attempt in range(max_retries):
            try:
                response = requests.request(method, url, verify=False, timeout=60, **kwargs)
                return response
            except (ConnectionError, Timeout) as e:
                yield self._create_event("WARNING", f"Request failed (attempt {attempt + 1}/{max_retries}), retrying in {2 ** attempt} seconds: {e}",
                                         url=url, method=method, attempt=attempt+1, max_retries=max_retries, error=str(e))
                if attempt == max_retries - 1:
                    yield self._create_event("ERROR", f"All {max_retries} retry attempts failed for {method} {url}",
                                             url=url, method=method, error=str(e))
                    raise e # Re-raise after yielding error
                time.sleep(2 ** attempt) # Exponential backoff
            except Exception as e:
                yield self._create_event("ERROR", f"Unexpected error during request {method} {url}: {e}",
                                         url=url, method=method, error=str(e))
                raise e # Re-raise after yielding error

    def _get_auth_headers_or_params(self, authtype, username=None, password=None, token=None):
        """
        Get authentication headers or parameters based on auth type
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
        # lookupmigrator.py - Block 3 of 5

    def _get_lookup_metadata(self, host, port, authtype, app, lookup_name=None, **auth_args):
        """
        Get lookup metadata from Splunk instance (combined function for list and single lookup)
        Yields events and returns list of lookup info dictionaries.
        """
        url = f"https://{host}:{port}/servicesNS/-/{app}/data/lookup-table-files"
        lookup_info = [] # Initialize here to ensure it's always returned

        try:
            auth_params = self._get_auth_headers_or_params(authtype, **auth_args)
        except ValueError as e:
            yield self._create_event("ERROR", f"Authentication error getting lookup metadata: {e}", host=host, app=app, error=str(e))
            yield self._create_event("LOOKUP_METADATA_FETCHED", [], status="exception")
            return # End generator

        params = {
                  "output_mode": "json",
                  "count": 0
                 }

        # Add search parameter if looking for specific lookup
        if lookup_name:
            params["search"] = lookup_name

        try:
            response = yield from self._make_request_with_retry('GET', url, params=params, **auth_params)

            if response.status_code != 200:
                yield self._create_event("ERROR", f"Failed to get lookup metadata: status={response.status_code}, reason={response.reason}",
                                         host=host, app=app, status_code=response.status_code, reason=response.reason)
                if response.status_code == 401:
                    yield self._create_event("ERROR", "Authentication failed - check credentials for lookup metadata access.")
                elif response.status_code == 403:
                    yield self._create_event("ERROR", "Access denied - check user permissions for lookup metadata access.")
                yield self._create_event("LOOKUP_METADATA_FETCHED", [], status="failed")
                return # End generator

            data = response.json()

            if 'entry' not in data:
                if lookup_name:
                    yield self._create_event("ERROR", f"Lookup '{lookup_name}' not found.")
                else:
                    yield self._create_event("WARNING", "No lookups found in response.")
                yield self._create_event("LOOKUP_METADATA_FETCHED", [], status="not_found")
                return # End generator

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
                yield self._create_event("ERROR", f"Lookup '{lookup_name}' not found in app '{app}'.")

            yield self._create_event("LOOKUP_METADATA_FETCHED", lookup_info, status="success")
            return # End generator

        except requests.exceptions.RequestException as e:
            yield self._create_event("ERROR", f"Network error getting lookup metadata: {e}", host=host, app=app, error=str(e))
            yield self._create_event("LOOKUP_METADATA_FETCHED", [], status="exception")
            return # End generator
        except json.JSONDecodeError as e:
            yield self._create_event("ERROR", f"Invalid JSON response getting lookup metadata: {e}", host=host, app=app, error=str(e), response_text=response.text)
            yield self._create_event("LOOKUP_METADATA_FETCHED", [], status="exception")
            return # End generator
        except Exception as e:
            yield self._create_event("ERROR", f"Unexpected error getting lookup metadata: {e}", host=host, app=app, error=str(e))
            yield self._create_event("LOOKUP_METADATA_FETCHED", [], status="exception")
            return # End generator

    def _get_lookup_contents(self, host, port, authtype, app, lookup_name, owner, **auth_args):
        """
        Get contents of a specific lookup from Splunk instance
        Yields events and returns lookup contents as JSON, None if failed, "EMPTY" if lookup is empty.
        """
        url = f"https://{host}:{port}/services/data/lookup_edit/lookup_data"
        lookup_content_result = None # Default return value

        try:
            auth_params = self._get_auth_headers_or_params(authtype, **auth_args)
        except ValueError as e:
            yield self._create_event("ERROR", f"Authentication error getting lookup contents: {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_CONTENTS_FETCHED", None, status="exception")
            return # End generator

        data = {
            "output_mode": "json",
            "namespace": app,
            "owner": owner,
            "lookup_file": lookup_name
        }

        self.logger.debug(f"Getting lookup contents from {url} with data: {data}")

        try:
            response = yield from self._make_request_with_retry('POST', url, data=data, **auth_params)

            if response.status_code == 200:
                result = response.json()

                # Check if lookup is empty (only headers or completely empty)
                if not result or (isinstance(result, list) and len(result) <= 1):
                    yield self._create_event("INFO", f"Lookup '{lookup_name}' is empty, skipping transfer.")
                    lookup_content_result = "EMPTY"
                else:
                    self.logger.debug(f"Successfully retrieved lookup contents: {len(str(result))} characters")
                    lookup_content_result = result

                yield self._create_event("LOOKUP_CONTENTS_FETCHED", lookup_content_result, lookup_name=lookup_name, status="success")
                return # End generator
            else:
                yield self._create_event("ERROR", f"Failed to get lookup contents for {lookup_name}: status={response.status_code}, reason={response.reason}",
                                         lookup_name=lookup_name, status_code=response.status_code, reason=response.reason)
                if response.text:
                    self.logger.debug(f"Response text: {response.text}")
                if response.status_code == 404:
                    yield self._create_event("ERROR", f"Lookup file '{lookup_name}' not found or not accessible.")
                elif response.status_code == 401:
                    yield self._create_event("ERROR", "Authentication failed - check credentials for lookup contents access.")
                elif response.status_code == 403:
                    yield self._create_event("ERROR", "Access denied - check user permissions for lookup contents access.")
                yield self._create_event("LOOKUP_CONTENTS_FETCHED", None, lookup_name=lookup_name, status="failed")
                return # End generator

        except requests.exceptions.RequestException as e:
            yield self._create_event("ERROR", f"Network error getting lookup contents for {lookup_name}: {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_CONTENTS_FETCHED", None, lookup_name=lookup_name, status="exception")
            return # End generator
        except json.JSONDecodeError as e:
            yield self._create_event("ERROR", f"Invalid JSON response getting lookup contents for {lookup_name}: {e}", lookup_name=lookup_name, error=str(e), response_text=response.text)
            yield self._create_event("LOOKUP_CONTENTS_FETCHED", None, lookup_name=lookup_name, status="exception")
            return # End generator
        except Exception as e:
            yield self._create_event("ERROR", f"Unexpected error getting lookup contents for {lookup_name}: {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_CONTENTS_FETCHED", None, lookup_name=lookup_name, status="exception")
            return # End generator

    def _check_app_exists(self, host, port, authtype, app, **auth_args):
        """
        Check if app exists on Splunk instance
        Yields events and returns True if app exists, False otherwise.
        """
        url = f"https://{host}:{port}/servicesNS/-/-/apps/local/{app}"
        app_exists = False # Default return value

        try:
            auth_params = self._get_auth_headers_or_params(authtype, **auth_args)
        except ValueError as e:
            yield self._create_event("ERROR", f"Authentication error checking app existence: {e}", app=app, error=str(e))
            yield self._create_event("APP_EXISTS_CHECKED", False, status="exception")
            return # End generator

        params = {"output_mode": "json"}

        try:
            response = yield from self._make_request_with_retry('GET', url, params=params, **auth_params)

            if response.status_code == 200:
                self.logger.debug(f"App '{app}' exists on {host}:{port}")
                app_exists = True
            elif response.status_code == 404:
                yield self._create_event("WARNING", f"App '{app}' does not exist on {host}:{port}.")
                app_exists = False
            else:
                yield self._create_event("ERROR", f"Failed to check app existence: status={response.status_code}, reason={response.reason}",
                                         app=app, status_code=response.status_code, reason=response.reason)
                app_exists = False

            yield self._create_event("APP_EXISTS_CHECKED", app_exists, app=app, status="success" if app_exists else "not_found")
            return # End generator

        except requests.exceptions.RequestException as e:
            yield self._create_event("ERROR", f"Network error checking app existence: {e}", app=app, error=str(e))
            yield self._create_event("APP_EXISTS_CHECKED", False, status="exception")
            return # End generator
        except Exception as e:
            yield self._create_event("ERROR", f"Unexpected error checking app existence: {e}", app=app, error=str(e))
            yield self._create_event("APP_EXISTS_CHECKED", False, status="exception")
            return # End generator# lookupmigrator.py - Block 4 of 5

    def _check_lookup_exists(self, host, port, authtype, app, lookup_name, owner, **auth_args):
        """
        Check if a lookup file already exists on destination
        Yields events and returns True if lookup exists, False otherwise.
        """
        check_url = f"https://{host}:{port}/servicesNS/{owner}/{app}/data/lookup-table-files"
        lookup_exists = False # Default return value

        try:
            auth_params = self._get_auth_headers_or_params(authtype, **auth_args)
        except ValueError as e:
            yield self._create_event("ERROR", f"Authentication error checking lookup existence: {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_EXISTS_CHECKED", False, status="exception")
            return # End generator

        params = {"output_mode": "json", "search": lookup_name}

        try:
            response = yield from self._make_request_with_retry('GET', check_url, params=params, **auth_params)

            if response.status_code == 200:
                data = response.json()
                if 'entry' in data and len(data['entry']) > 0:
                    self.logger.debug(f"Lookup file '{lookup_name}' already exists.")
                    lookup_exists = True

            yield self._create_event("LOOKUP_EXISTS_CHECKED", lookup_exists, lookup_name=lookup_name, status="success" if lookup_exists else "not_found")
            return # End generator

        except requests.exceptions.RequestException as e:
            yield self._create_event("DEBUG", f"Network error checking lookup existence: {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_EXISTS_CHECKED", False, status="exception")
            return # End generator
        except Exception as e:
            yield self._create_event("DEBUG", f"Error checking lookup existence: {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_EXISTS_CHECKED", False, status="exception")
            return # End generator

    def _create_lookup_file(self, host, port, authtype, app, lookup_name, owner, **auth_args):
        """
        Create a dummy lookup file on destination if it doesn't exist
        Yields events and returns True if successful or already exists, False otherwise.
        """
        # Use the correct namespace with owner to check if file exists
        check_url = f"https://{host}:{port}/servicesNS/{owner}/{app}/data/lookup-table-files"
        creation_success = False # Default return value

        try:
            auth_params = self._get_auth_headers_or_params(authtype, **auth_args)
        except ValueError as e:
            yield self._create_event("ERROR", f"Authentication error creating lookup file: {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_FILE_CREATED", False, status="exception")
            return # End generator

        # First check if the lookup file already exists
        params = {"output_mode": "json", "search": lookup_name}

        try:
            response = yield from self._make_request_with_retry('GET', check_url, params=params, **auth_params)

            if response.status_code == 200:
                data = response.json()
                if 'entry' in data and len(data['entry']) > 0:
                    self.logger.debug(f"Lookup file '{lookup_name}' already exists with owner '{owner}'.")
                    yield self._create_event("LOOKUP_FILE_CREATED", True, lookup_name=lookup_name, status="already_exists")
                    return # End generator

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

            self.logger.debug(f"Creating dummy lookup file '{lookup_name}' on {host}:{port} with owner '{owner}'.")
            response = yield from self._make_request_with_retry('POST', create_url, data=data, **auth_params)

            if response.status_code in [200, 201]:
                yield self._create_event("INFO", f"Successfully created dummy lookup file '{lookup_name}' with owner '{owner}'.")
                creation_success = True
            else:
                self.logger.debug(f"Failed to create dummy lookup file '{lookup_name}': status={response.status_code}.")
                if response.text:
                    self.logger.debug(f"Response: {response.text}")
                # Don't fail here - the upload might still work without pre-creating the file
                creation_success = True # Original script returned True here, so maintaining behavior

            yield self._create_event("LOOKUP_FILE_CREATED", creation_success, lookup_name=lookup_name, status="success" if creation_success else "failed")
            return # End generator

        except requests.exceptions.RequestException as e:
            yield self._create_event("DEBUG", f"Network error creating lookup file (continuing anyway): {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_FILE_CREATED", True, status="exception_continuing") # Original script returned True
            return # End generator
        except Exception as e:
            yield self._create_event("DEBUG", f"Unexpected error creating lookup file (continuing anyway): {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_FILE_CREATED", True, status="exception_continuing") # Original script returned True
            return # End generator

    def _set_lookup_permissions(self, host, port, authtype, app, lookup_name, owner, acl, **auth_args):
        """
        Set permissions on a lookup file to match source ACL
        Yields events and returns True if successful, False otherwise.
        """
        url = f"https://{host}:{port}/servicesNS/{owner}/{app}/data/lookup-table-files/{lookup_name}/acl"
        permissions_set_success = False # Default return value

        try:
            auth_params = self._get_auth_headers_or_params(authtype, **auth_args)
        except ValueError as e:
            yield self._create_event("ERROR", f"Authentication error setting lookup permissions: {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_PERMISSIONS_SET", False, status="exception")
            return # End generator

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

        self.logger.debug(f"Setting permissions for '{lookup_name}': sharing={sharing}, read={perms_read}, write={perms_write}")

        try:
            response = yield from self._make_request_with_retry('POST', url, data=acl_data, **auth_params)

            if response.status_code in [200, 201]:
                yield self._create_event("INFO", f"Successfully set permissions for lookup '{lookup_name}' (sharing: {sharing}).")
                permissions_set_success = True
            else:
                yield self._create_event("WARNING", f"Failed to set permissions for lookup '{lookup_name}': status={response.status_code}.",
                                         lookup_name=lookup_name, status_code=response.status_code, response_text=response.text)
                if response.text:
                    self.logger.debug(f"ACL Response: {response.text}")
                permissions_set_success = True # Original script returned True here, so maintaining behavior

            yield self._create_event("LOOKUP_PERMISSIONS_SET", permissions_set_success, lookup_name=lookup_name, status="success" if permissions_set_success else "failed")
            return # End generator

        except requests.exceptions.RequestException as e:
            yield self._create_event("WARNING", f"Network error setting permissions for '{lookup_name}': {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_PERMISSIONS_SET", True, status="exception_continuing") # Original script returned True
            return # End generator
        except Exception as e:
            yield self._create_event("WARNING", f"Unexpected error setting permissions for '{lookup_name}': {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_PERMISSIONS_SET", True, status="exception_continuing") # Original script returned True
            return # End generator

    def _upload_lookup(self, host, port, authtype, app, lookup_name, lookup_content, owner, acl, overwrite_existing, **auth_args):
        """
        Upload lookup to destination Splunk instance
        Yields events and returns tuple: (success: bool, reason: str)
        """
        upload_success = False
        upload_reason = "Unknown error"

        # Check if destination app exists
        app_exists = False
        for event in self._check_app_exists(host, port, authtype, app, **auth_args):
            if event.get("log_level") == "APP_EXISTS_CHECKED":
                app_exists = event.get("message")
            yield event
        
        if not app_exists:
            upload_reason = "Destination app does not exist"
            yield self._create_event("LOOKUP_UPLOAD_RESULT", False, reason=upload_reason, lookup_name=lookup_name, success=False)
            return # End generator

        # Check if lookup already exists
        lookup_already_exists = False
        for event in self._check_lookup_exists(host, port, authtype, app, lookup_name, owner, **auth_args):
            if event.get("log_level") == "LOOKUP_EXISTS_CHECKED":
                lookup_already_exists = event.get("message")
            yield event
        
        if lookup_already_exists:
            if not overwrite_existing:
                upload_reason = "Skipped - already exists"
                yield self._create_event("INFO", f"Lookup '{lookup_name}' already exists, skipping (use --enable_overwrite_existing to overwrite).")
                yield self._create_event("LOOKUP_UPLOAD_RESULT", True, reason=upload_reason, lookup_name=lookup_name, success=True)
                return # End generator
            else:
                yield self._create_event("INFO", f"Lookup '{lookup_name}' already exists, overwriting...")
        
        # Try to create the lookup file if it doesn't exist, with proper owner
        create_file_success = False
        for event in self._create_lookup_file(host, port, authtype, app, lookup_name, owner, **auth_args):
            if event.get("log_level") == "LOOKUP_FILE_CREATED":
                create_file_success = event.get("message")
            yield event
        
        # Original script continued even if create_lookup_file returned False,
        # so we'll proceed with upload attempt regardless of create_file_success for now.
        # If this causes issues, we might need to add a 'continue' here.
        
        url = f"https://{host}:{port}/services/data/lookup_edit/lookup_contents"
        
        try:
            auth_params = self._get_auth_headers_or_params(authtype, **auth_args)
        except ValueError as e:
            upload_reason = "Authentication error"
            yield self._create_event("ERROR", f"Authentication error uploading lookup: {e}", lookup_name=lookup_name, error=str(e))
            yield self._create_event("LOOKUP_UPLOAD_RESULT", False, reason=upload_reason, lookup_name=lookup_name, success=False)
            return # End generator
        
        data = {
            "output_mode": "json",
            "namespace": app,
            "owner": owner,  # Specify the owner explicitly
            "lookup_file": lookup_name,
            "contents": json.dumps(lookup_content)
        }
        
        self.logger.debug(f"Uploading lookup to {url}")
        self.logger.debug(f"Upload data keys: {list(data.keys())}")
        self.logger.debug(f"Lookup owner: {owner}")
        self.logger.debug(f"Lookup content size: {len(data['contents'])} characters")
        self.logger.debug(f"Lookup content preview: {data['contents'][:200]}...")
        
        try:
            response = yield from self._make_request_with_retry('POST', url, data=data, **auth_params)
            
            self.logger.debug(f"Upload response status: {response.status_code}")
            if response.text:
                self.logger.debug(f"Upload response text: {response.text}")
            
            if response.status_code == 200:
                yield self._create_event("INFO", f"[SUCCESS] Lookup '{lookup_name}' uploaded to app '{app}' with owner '{owner}'.",
                                         lookup_name=lookup_name, app=app, owner=owner, status_code=response.status_code)
                
                # Set permissions to match source
                permissions_set_success = False
                for event in self._set_lookup_permissions(host, port, authtype, app, lookup_name, owner, acl, **auth_args):
                    if event.get("log_level") == "LOOKUP_PERMISSIONS_SET":
                        permissions_set_success = event.get("message")
                    yield event
                
                upload_success = True
                upload_reason = "Successfully uploaded"
            else:
                upload_reason = f"Upload failed: status={response.status_code}, reason={response.reason}"
                yield self._create_event("ERROR", f"[FAILED] Upload of lookup '{lookup_name}': {upload_reason}",
                                         lookup_name=lookup_name, status_code=response.status_code, reason=response.reason)
                if response.text:
                    yield self._create_event("ERROR", f"Server response: {response.text}")
                if response.status_code == 401:
                    upload_reason = "Authentication failed"
                elif response.status_code == 403:
                    upload_reason = "Access denied"
                elif response.status_code == 400:
                    upload_reason = "Bad request - check lookup content format"
                elif response.status_code == 500:
                    upload_reason = "Internal server error - check Splunk logs"
                upload_success = False
                
        except requests.exceptions.RequestException as e:
            upload_reason = f"Network error: {e}"
            yield self._create_event("ERROR", f"Network error uploading lookup {lookup_name}: {e}", lookup_name=lookup_name, error=str(e))
            upload_success = False
        except Exception as e:
            upload_reason = f"Unexpected error: {e}"
            yield self._create_event("ERROR", f"Unexpected error uploading lookup {lookup_name}: {e}", lookup_name=lookup_name, error=str(e))
            upload_success = False
        
        yield self._create_event("LOOKUP_UPLOAD_RESULT", upload_success, reason=upload_reason, lookup_name=lookup_name, success=upload_success)
        return # End generator# lookupmigrator.py - Block 5 of 5

# This is the entry point for the Splunk search command
dispatch(LookupMigratorCommand, sys.argv, sys.stdin, sys.stdout, __name__)