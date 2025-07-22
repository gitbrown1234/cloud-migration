import os, sys
import time
import json
import requests
import xml.etree.ElementTree as ET
import urllib.parse
from datetime import datetime, timedelta # Keep if needed for other date parsing, though not used in current _count_only
import re
from requests.exceptions import ConnectionError, Timeout
import urllib3
import logging # Import logging for logger.setLevel

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add the lib directory to the sys.path for splunklib
# This assumes the script is placed in $SPLUNK_HOME/etc/apps/<your_app>/bin/
# and splunklib is in $SPLUNK_HOME/etc/apps/<your_app>/lib/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators


@Configuration()
class MigrationValidatorCommand(GeneratingCommand):
    """
    The migrationvalidator command compares counts and lists of Splunk knowledge objects,
    KVStore collections, lookups, or roles between a source and destination instance.

    Example (Knowledge Objects):
    ``| migrationvalidator type="ko" srcHost="src_splunk_host" destHost="dest_splunk_host" srcToken="YOUR_SRC_TOKEN" destToken="YOUR_DEST_TOKEN" srcApp="search"``

    Example (Roles - no srcApp needed):
    ``| migrationvalidator type="roles" srcHost="src_splunk_host" destHost="dest_splunk_host" srcToken="YOUR_SRC_TOKEN" destToken="YOUR_DEST_TOKEN"``

    Example (KVStore):
    ``| migrationvalidator type="kvstore" srcHost="src_splunk_host" destHost="dest_splunk_host" srcToken="YOUR_SRC_TOKEN" destToken="YOUR_DEST_TOKEN" srcApp="my_app"``

    Example (Lookups):
    ``| migrationvalidator type="lookups" srcHost="src_splunk_host" destHost="dest_splunk_host" srcToken="YOUR_SRC_TOKEN" destToken="YOUR_DEST_TOKEN" srcApp="my_app"``
    """

    srcHost = Option(require=True)
    destHost = Option(require=True)
    srcToken = Option(require=True)
    destToken = Option(require=True)
    srcApp = Option(require=False, default="") # Now optional
    type = Option(require=True, validate=validators.Set('ko', 'kvstore', 'lookups', 'roles'))

    # XML Namespaces for parsing Splunk REST responses
    NAMESPACES = {
        "atom": "http://www.w3.org/2005/Atom",
        "s": "http://dev.splunk.com/ns/rest"
    }

    def generate(self):
        """
        Main generator method for the Splunk custom command.
        Dispatches to specific validation logic based on 'type'.
        """
        self.logger.setLevel(logging.INFO) # Default to INFO

        validation_type = self.type
        src_host = self.srcHost
        dest_host = self.destHost
        src_token = self.srcToken
        dest_token = self.destToken
        src_app = self.srcApp
        
        # Construct full URLs from hostnames, assuming HTTPS and default management port 8089
        self.srcURL = f"https://{src_host}:8089"
        self.destURL = f"https://{dest_host}:8089"

        yield self._create_event("INFO", f"Starting validation for type: {validation_type}")

        if validation_type == 'ko':
            if not src_app:
                yield self._create_event("ERROR", "srcApp is required for 'ko' validation type.")
                return
            # Call the wrapper for KO validation
            yield from self._validate_ko_wrapper(self.srcURL, self.destURL, src_token, dest_token, src_app)
        elif validation_type == 'kvstore':
            if not src_app:
                yield self._create_event("ERROR", "srcApp is required for 'kvstore' validation type.")
                return
            yield from self._validate_kvstore(self.srcURL, self.destURL, src_token, dest_token, src_app)
        elif validation_type == 'lookups':
            if not src_app:
                yield self._create_event("ERROR", "srcApp is required for 'lookups' validation type.")
                return
            yield from self._validate_lookups(self.srcURL, self.destURL, src_token, dest_token, src_app)
        elif validation_type == 'roles':
            # srcApp is not required for roles as they are global
            yield from self._validate_roles(self.srcURL, self.destURL, src_token, dest_token)
        else:
            yield self._create_event("ERROR", f"Unsupported validation type: {validation_type}")

        yield self._create_event("INFO", f"Validation for type '{validation_type}' completed.")

    def _create_event(self, log_level, message, **kwargs):
        """
        Helper method to create a consistent event dictionary for yielding.
        Accepts kwargs for structured fields.
        """
        event = {
            '_time': time.time(),
            'log_level': log_level,
            'message': message,
            '_raw': message
        }
        event.update(kwargs) # This will add structured fields for kvstore, lookups, roles
        return event

    def _make_request(self, url, token, method='get', data=None):
        """
        Centralized function to make HTTP requests with token authentication.
        Uses Bearer token as per previous working version.
        """
        headers = {'Authorization': f'Bearer {token}'}
        if method.lower() == 'post' and data:
            # For POST requests, ensure Content-Type is set if data is provided
            # Splunk REST API typically expects application/x-www-form-urlencoded for form data
            # or application/json if sending JSON payload.
            # For this script, data is typically a dict for form data, so default to that.
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

        max_retries = 5
        base_delay = 1  # seconds

        for attempt in range(max_retries):
            try:
                if method.lower() == 'get':
                    response = requests.get(url, headers=headers, verify=False, timeout=30)
                elif method.lower() == 'post':
                    response = requests.post(url, headers=headers, data=data, verify=False, timeout=30)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                return response
            except (ConnectionError, Timeout) as e:
                yield self._create_event("WARNING", f"Request to {url} failed (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    yield self._create_event("INFO", f"Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    yield self._create_event("ERROR", f"Max retries exceeded for {url}.")
                    raise
            except requests.exceptions.RequestException as e:
                yield self._create_event("ERROR", f"An unexpected error occurred during request to {url}: {e}")
                raise

    def _get_local_name(self, full_name):
        """Extracts the local name from a namespaced XML tag or attribute name string."""
        if '}' in full_name:
            return full_name.split('}', 1)[1]
        return full_name

    # --- KO Validation specific functions (from previous working version) ---

    def _validate_ko_wrapper(self, src_url, dest_url, src_token, dest_token, src_app):
        """
        Wrapper function to handle KO validation using the existing _run_queries_count_only
        and _macros_count_only logic, preserving their output format.
        """
        # Set default destApp if not provided (for internal use by _run_queries_count_only)
        dest_app = src_app

        self.logger.info(f"Starting knowledge object validation from {src_url} (app: {src_app}) to {dest_url} (app: {dest_app})")

        # Determine source app list (for wildcarded app names)
        src_app_list = []
        if src_app.find("*") != -1:
            url = f"{src_url}/services/apps/local?search=disabled%3D0&f=title&count=0&output_mode=json"
            app_pattern = re.compile(src_app.replace('*', '.*')) # Convert wildcard to regex
            try:
                res = yield from self._make_request(
                    url, token=src_token, method='get'
                )
                if res.status_code == requests.codes.ok:
                    resDict = json.loads(res.text)
                    for entry in resDict['entry']:
                        if app_pattern.search(entry['name']):
                            self.logger.info(f"Adding app {entry['name']} to the list of source apps.")
                            src_app_list.append(entry['name'])
                else:
                    yield self._create_event("ERROR", f"Failed to retrieve source app list from {url}. Status: {res.status_code}, Response: {res.text}")
                    return
            except Exception as e:
                yield self._create_event("ERROR", f"Error retrieving source app list: {e}")
                return
        else:
            src_app_list.append(src_app)

        if not src_app_list:
            yield self._create_event("ERROR", f"No source applications found matching '{src_app}'. Exiting.")
            return

        # Check destination app existence
        self.logger.info(f"Checking if destination app '{dest_app}' exists on {dest_url}")
        try:
            res_dest_app = yield from self._make_request(
                f"{dest_url}/services/apps/local/{dest_app}",
                token=dest_token, method='get'
            )
            if res_dest_app.status_code == 404:
                yield self._create_event("WARNING", f"Destination app '{dest_app}' does not exist on {dest_url}. Destination counts might be zero.")
            elif res_dest_app.status_code != requests.codes.ok:
                yield self._create_event("ERROR", f"Failed to check destination app '{dest_app}': status={res_dest_app.status_code}, response={res_dest_app.text}")
            else:
                yield self._create_event("INFO", f"Destination app '{dest_app}' exists on {dest_url}.")
        except Exception as e:
            yield self._create_event("ERROR", f"Error checking destination app '{dest_app}': {e}")

        # Define all knowledge object types and their endpoints
        ko_types_to_validate = {
            "dashboards": "/data/ui/views",
            "savedsearches": "/saved/searches",
            "calcfields": "/data/props/calcfields",
            "fieldaliases": "/data/props/fieldaliases",
            "fieldextractions": "/data/props/extractions",
            "fieldtransformations": "/data/transforms/extractions",
            "workflowactions": "/data/ui/workflow-actions",
            "sourcetyperenaming": "/data/props/sourcetype-rename",
            "sourcetypes": "/configs/conf-props",
            "tags": "/configs/conf-tags",
            "eventtypes": "/saved/eventtypes",
            "navmenu": "/data/ui/nav",
            "datamodels": "/datamodel/model",
            "collections": "/storage/collections/config",
            "viewstates": "/configs/conf-viewstates",
            "times": "/configs/conf-times",
            "panels": "/data/ui/panels",
            "lookupdefinitions": "/data/transforms/lookups",
            "automaticlookups": "/data/props/lookups"
        }

        for current_src_app in src_app_list:
            yield self._create_event("INFO", f"Starting validation for knowledge objects from source app: {current_src_app}")

            # Handle macros separately due to their unique endpoint structure
            yield from self._macros_count_only(current_src_app, dest_app, "macros", src_url, dest_url, src_token, dest_token)

            for obj_type, endpoint in ko_types_to_validate.items():
                if obj_type != "macros": # Macros handled above
                    yield from self._run_queries_count_only(
                        current_src_app, dest_app, endpoint, obj_type, src_url, dest_url, src_token, dest_token
                    )

        yield self._create_event("INFO", "Knowledge object validation process completed.")

    def _run_queries_count_only(self, src_app, dest_app, endpoint, obj_type, src_url, dest_url, src_token, dest_token):
        """
        Generic function to query Splunk REST API and count objects for source and destination.
        All filtering logic is removed; it counts objects that belong to the app context.
        """
        source_ko_count = 0
        dest_ko_count = 0

        # --- Source Count ---
        url = f"{src_url}/servicesNS/-/{src_app}{endpoint}?count=-1"
        self.logger.debug(f"Counting {obj_type} on source: {url} in app {src_app}")

        res = yield from self._make_request(
            url, token=src_token, method='get'
        )
        if res.status_code != requests.codes.ok:
            yield self._create_event("ERROR", f"Failed to retrieve {obj_type} from source {url}. Status: {res.status_code}, Response: {res.text}")
        else:
            root = ET.fromstring(res.text)
            for child in root:
                if child.tag.endswith("entry"):
                    keep = True
                    found_acl_app = None

                    # Extract app from eai:acl to ensure it belongs to the current app context
                    for innerChild in child:
                        if innerChild.tag.endswith("content"):
                            if len(innerChild) == 0: continue
                            content_dict_element = innerChild[0]
                            for property_element in content_dict_element:
                                property_name = self._get_local_name(property_element.attrib.get('name', ''))
                                if property_name == 'eai:acl':
                                    if len(property_element) == 0: continue
                                    acl_dict_element = property_element[0]
                                    for acl_prop_element in acl_dict_element:
                                        acl_prop_name = self._get_local_name(acl_prop_element.attrib.get('name', ''))
                                        if acl_prop_name == 'app':
                                            found_acl_app = acl_prop_element.text
                                            break
                                    break

                    if found_acl_app and src_app != found_acl_app:
                        keep = False
                    elif not found_acl_app:
                        keep = False
                        self.logger.warning(f"No 'app' attribute found in eai:acl for {obj_type} on source. SKIPPING for safety.")

                    if keep:
                        source_ko_count += 1

        # --- Destination Count ---
        dest_url = f"{dest_url}/servicesNS/-/{dest_app}{endpoint}?count=-1"
        self.logger.debug(f"Counting {obj_type} on destination: {dest_url} in app {dest_app}")

        res_dest = yield from self._make_request(
            dest_url, token=dest_token, method='get'
        )
        if res_dest.status_code != requests.codes.ok:
            yield self._create_event("ERROR", f"Failed to retrieve {obj_type} from destination {dest_url}. Status: {res_dest.status_code}, Response: {res_dest.text}")
        else:
            root_dest = ET.fromstring(res_dest.text)
            for child in root_dest:
                if child.tag.endswith("entry"):
                    keep = True
                    found_acl_app = None

                    # Extract app from eai:acl to ensure it belongs to the current app context
                    for innerChild in child:
                        if innerChild.tag.endswith("content"):
                            if len(innerChild) == 0: continue
                            content_dict_element = innerChild[0]
                            for property_element in content_dict_element:
                                property_name = self._get_local_name(property_element.attrib.get('name', ''))
                                if property_name == 'eai:acl':
                                    if len(property_element) == 0: continue
                                    acl_dict_element = property_element[0]
                                    for acl_prop_element in acl_dict_element:
                                        acl_prop_name = self._get_local_name(acl_prop_element.attrib.get('name', ''))
                                        if acl_prop_name == 'app':
                                            found_acl_app = acl_prop_element.text
                                            break
                                    break

                    if found_acl_app and dest_app != found_acl_app:
                        keep = False
                    elif not found_acl_app:
                        keep = False
                        self.logger.warning(f"No 'app' attribute found in eai:acl for {obj_type} on destination. SKIPPING for safety.")

                    if keep:
                        dest_ko_count += 1

        # Yield the event with counts embedded in the message (preserving previous KO output format)
        yield self._create_event("INFO", f"Validation counts for {obj_type}: Source App '{src_app}' has {source_ko_count} objects, Destination App '{dest_app}' has {dest_ko_count} objects.")

    def _macros_count_only(self, src_app, dest_app, obj_type, src_url, dest_url, src_token, dest_token):
        """
        Handles macro specific counting logic for source and destination.
        All filtering logic is removed; it counts objects that belong to the app context.
        """
        source_ko_count = 0
        dest_ko_count = 0

        # --- Source Count ---
        url = f"{src_url}/servicesNS/-/{src_app}/configs/conf-macros?count=-1"
        self.logger.debug(f"Counting {obj_type} on source: {url} in app {src_app}")

        res = yield from self._make_request(
            url, token=src_token, method='get'
        )
        if res.status_code != requests.codes.ok:
            yield self._create_event("ERROR", f"Failed to retrieve {obj_type} from source {url}. Status: {res.status_code}, Response: {res.text}")
        else:
            root = ET.fromstring(res.text)
            for child in root:
                if child.tag.endswith("entry"):
                    keep = True
                    found_acl_app = None

                    # Extract app from eai:acl
                    for innerChild in child:
                        if innerChild.tag.endswith("content"):
                            if len(innerChild) == 0: continue
                            content_dict_element = innerChild[0]
                            for property_element in content_dict_element:
                                property_name = self._get_local_name(property_element.attrib.get('name', ''))
                                if property_name == 'eai:acl':
                                    if len(property_element) == 0: continue
                                    acl_dict_element = property_element[0]
                                    for acl_prop_element in acl_dict_element:
                                        acl_prop_name = self._get_local_name(acl_prop_element.attrib.get('name', ''))
                                        if acl_prop_name == 'app':
                                            found_acl_app = acl_prop_element.text
                                            break
                                    break

                    if found_acl_app and src_app != found_acl_app:
                        keep = False
                    elif not found_acl_app:
                        keep = False
                        self.logger.warning(f"No 'app' attribute found in eai:acl for {obj_type} on source. SKIPPING for safety.")

                    if keep:
                        source_ko_count += 1

        # --- Destination Count ---
        dest_url = f"{dest_url}/servicesNS/-/{dest_app}/configs/conf-macros?count=-1"
        self.logger.debug(f"Counting {obj_type} on destination: {dest_url} in app {dest_app}")

        res_dest = yield from self._make_request(
            dest_url, token=dest_token, method='get'
        )
        if res_dest.status_code != requests.codes.ok:
            yield self._create_event("ERROR", f"Failed to retrieve {obj_type} from destination {dest_url}. Status: {res_dest.status_code}, Response: {res_dest.text}")
        else:
            root_dest = ET.fromstring(res_dest.text)
            for child in root_dest:
                if child.tag.endswith("entry"):
                    keep = True
                    found_acl_app = None

                    # Extract app from eai:acl
                    for innerChild in child:
                        if innerChild.tag.endswith("content"):
                            if len(innerChild) == 0: continue
                            content_dict_element = innerChild[0]
                            for property_element in content_dict_element:
                                property_name = self._get_local_name(property_element.attrib.get('name', ''))
                                if property_name == 'eai:acl':
                                    if len(property_element) == 0: continue
                                    acl_dict_element = property_element[0]
                                    for acl_prop_element in acl_dict_element:
                                        acl_prop_name = self._get_local_name(acl_prop_element.attrib.get('name', ''))
                                        if acl_prop_name == 'app':
                                            found_acl_app = acl_prop_element.text
                                            break
                                    break

                    if found_acl_app and dest_app != found_acl_app:
                        keep = False
                    elif not found_acl_app:
                        keep = False
                        self.logger.warning(f"No 'app' attribute found in eai:acl for {obj_type} on destination. SKIPPING for safety.")

                    if keep:
                        dest_ko_count += 1

        # Yield the event with counts embedded in the message (preserving previous KO output format)
        yield self._create_event("INFO", f"Validation counts for {obj_type}: Source App '{src_app}' has {source_ko_count} objects, Destination App '{dest_app}' has {dest_ko_count} objects.")

    # --- New Validation Types (KVStore, Lookups, Roles) ---

    def _fetch_names_from_endpoint(self, host, token, app, endpoint_path):
        """
        Generic fetcher for lists of names from a Splunk REST endpoint.
        Handles Atom feed XML responses. Filters by acl:app.
        """
        url = f"{host}/servicesNS/-/{app}{endpoint_path}?count=-1"
        names = []
        try:
            response = yield from self._make_request(url, token, method='get')
            if response.status_code == 200:
                root = ET.fromstring(response.text)
                
                for entry in root.findall("atom:entry", namespaces=self.NAMESPACES):
                    entry_name_element = entry.find("atom:title", namespaces=self.NAMESPACES)
                    entry_name = entry_name_element.text if entry_name_element is not None else "UNKNOWN_NAME"

                    entry_app_context = "UNKNOWN_APP"
                    
                    content_element = entry.find("atom:content", namespaces=self.NAMESPACES)
                    if content_element is not None:
                        eai_acl_dict_key = content_element.find("s:dict/s:key[@name='eai:acl']", namespaces=self.NAMESPACES)
                        if eai_acl_dict_key is not None and len(eai_acl_dict_key) > 0:
                            actual_acl_dict = eai_acl_dict_key[0]
                            app_key_element = actual_acl_dict.find("s:key[@name='app']", namespaces=self.NAMESPACES)
                            if app_key_element is not None:
                                entry_app_context = app_key_element.text
                        else:
                            eai_acl_element = content_element.find("s:eai:acl", namespaces=self.NAMESPACES)
                            if eai_acl_element is not None:
                                if "app" in eai_acl_element.attrib:
                                    entry_app_context = eai_acl_element.attrib.get("app")
                                elif f"{self.NAMESPACES['s']}app" in eai_acl_element.attrib:
                                    entry_app_context = eai_acl_element.attrib.get(f"{self.NAMESPACES['s']}app")
                                else:
                                    app_key_element = eai_acl_element.find("s:key[@name='app']", namespaces=self.NAMESPACES)
                                    if app_key_element is not None:
                                        entry_app_context = app_key_element.text

                    # Only include names that belong to the specified app context
                    if entry_app_context == app:
                        names.append(entry_name)
                        self.logger.debug(f"FETCH_NAMES_DEBUG: Included '{entry_name}' (App: '{entry_app_context}') for target app '{app}'")
                    else:
                        self.logger.debug(f"FETCH_NAMES_DEBUG: Skipped '{entry_name}' (App: '{entry_app_context}') because its app context '{entry_app_context}' does not match target app '{app}'")

                yield self._create_event("INFO", f"Successfully fetched {len(names)} names for '{endpoint_path.split('/')[-1]}' from app '{app}'.",
                                         host=host, app=app, endpoint=endpoint_path, count=len(names))
            else:
                yield self._create_event("ERROR", f"Failed to fetch names from {url}. Status: {response.status_code}, Response: {response.text}",
                                         host=host, app=app, endpoint=endpoint_path, status_code=response.status_code, response_text=response.text)
        except Exception as e:
            yield self._create_event("ERROR", f"Error fetching names from {url}: {e}", host=host, app=app, endpoint=endpoint_path, error=str(e))
        return names

    def _fetch_roles_names(self, host, token):
        """
        Fetches names of all roles from a Splunk instance. Roles are global, so no app needed.
        """
        url = f"{host}/services/authorization/roles?count=-1"
        names = []
        try:
            response = yield from self._make_request(url, token, method='get')
            if response.status_code == 200:
                root = ET.fromstring(response.text)
                for entry_title in root.findall("atom:entry/atom:title", namespaces=self.NAMESPACES):
                    if entry_title.text and entry_title.text != "splunk-system-role": # Exclude system role
                        names.append(entry_title.text)
                yield self._create_event("INFO", f"Fetched {len(names)} role names from {host}", host=host, count=len(names))
            else:
                yield self._create_event("ERROR", f"Failed to fetch role names from {host}. Status: {response.status_code}, Response: {response.text}",
                                         host=host, status_code=response.status_code, response_text=response.text)
        except Exception as e:
            yield self._create_event("ERROR", f"Error fetching role names from {host}: {e}", host=host, error=str(e))
        return names

    def _validate_kvstore(self, src_url, dest_url, src_token, dest_token, src_app):
        """
        Validates KVStore collections by comparing names.
        """
        yield self._create_event("INFO", f"Validating KVStore Collections in app '{src_app}'...")

        # Fetch from Source
        yield self._create_event("INFO", f"Fetching KVStore collections from source: {src_url} (app: {src_app})...")
        src_kv_names = yield from self._fetch_names_from_endpoint(
            src_url, src_token, src_app, "/storage/collections/config"
        )
        src_kv_set = set(src_kv_names)
        yield self._create_event("INFO", f"Source KVStore Collection Count: {len(src_kv_set)}", source_count=len(src_kv_set))

        # Fetch from Destination
        yield self._create_event("INFO", f"Fetching KVStore collections from destination: {dest_url} (app: {src_app})...")
        dest_kv_names = yield from self._fetch_names_from_endpoint(
            dest_url, dest_token, src_app, "/storage/collections/config"
        )
        dest_kv_set = set(dest_kv_names)
        yield self._create_event("INFO", f"Destination KVStore Collection Count: {len(dest_kv_set)}", dest_count=len(dest_kv_set))

        # Compare and Report
        yield self._create_event("INFO", "\n--- KVStore Validation Summary ---", summary_type="kvstore")
        yield self._create_event("INFO", f"KVStore Collections (App: {src_app}):", ko_type="kvstore", app=src_app)
        yield self._create_event("INFO", f"  Source Count: {len(src_kv_set)}", location="source", count=len(src_kv_set))
        yield self._create_event("INFO", f"  Destination Count: {len(dest_kv_set)}", location="destination", count=len(dest_kv_set))

        if len(src_kv_set) == len(dest_kv_set):
            yield self._create_event("INFO", "  Counts match for KVStore Collections.", status="counts_match")
        else:
            yield self._create_event("WARNING", "  Counts MISMATCH for KVStore Collections.", status="counts_mismatch")

        missing_at_dest = src_kv_set - dest_kv_set
        extra_at_dest = dest_kv_set - src_kv_set

        if missing_at_dest:
            yield self._create_event("WARNING", f"  KVStore collections missing at destination: {', '.join(missing_at_dest)}",
                                     status="missing_at_dest", items=list(missing_at_dest))
        if extra_at_dest:
            yield self._create_event("WARNING", f"  KVStore collections extra at destination: {', '.join(extra_at_dest)}",
                                     status="extra_at_dest", items=list(extra_at_dest))
        if not missing_at_dest and not extra_at_dest:
            yield self._create_event("INFO", "  All KVStore collection names match.", status="names_match")

    def _validate_lookups(self, src_url, dest_url, src_token, dest_token, src_app):
        """
        Validates Lookups by comparing names.
        """
        yield self._create_event("INFO", f"Validating Lookups in app '{src_app}'...")

        # Fetch from Source
        yield self._create_event("INFO", f"Fetching lookups from source: {src_url} (app: {src_app})...")
        src_lookup_names = yield from self._fetch_names_from_endpoint(
            src_url, src_token, src_app, "/data/lookup-table-files"
        )
        src_lookup_set = set(src_lookup_names)
        yield self._create_event("INFO", f"Source Lookup Count: {len(src_lookup_set)}", source_count=len(src_lookup_set))

        # Fetch from Destination
        yield self._create_event("INFO", f"Fetching lookups from destination: {dest_url} (app: {src_app})...")
        dest_lookup_names = yield from self._fetch_names_from_endpoint(
            dest_url, dest_token, src_app, "/data/lookup-table-files"
        )
        dest_lookup_set = set(dest_lookup_names)
        yield self._create_event("INFO", f"Destination Lookup Count: {len(dest_lookup_set)}", dest_count=len(dest_lookup_set))

        # Compare and Report
        yield self._create_event("INFO", "\n--- Lookup Validation Summary ---", summary_type="lookups")
        yield self._create_event("INFO", f"Lookups (App: {src_app}):", ko_type="lookups", app=src_app)
        yield self._create_event("INFO", f"  Source Count: {len(src_lookup_set)}", location="source", count=len(src_lookup_set))
        yield self._create_event("INFO", f"  Destination Count: {len(dest_lookup_set)}", location="destination", count=len(dest_lookup_set))

        if len(src_lookup_set) == len(dest_lookup_set):
            yield self._create_event("INFO", "  Counts match for Lookups.", status="counts_match")
        else:
            yield self._create_event("WARNING", "  Counts MISMATCH for Lookups.", status="counts_mismatch")

        missing_at_dest = src_lookup_set - dest_lookup_set
        extra_at_dest = dest_lookup_set - src_lookup_set

        if missing_at_dest:
            yield self._create_event("WARNING", f"  Lookups missing at destination: {', '.join(missing_at_dest)}",
                                     status="missing_at_dest", items=list(missing_at_dest))
        if extra_at_dest:
            yield self._create_event("WARNING", f"  Lookups extra at destination: {', '.join(extra_at_dest)}",
                                     status="extra_at_dest", items=list(extra_at_dest))
        if not missing_at_dest and not extra_at_dest:
            yield self._create_event("INFO", "  All Lookup names match.", status="names_match")

    def _validate_roles(self, src_url, dest_url, src_token, dest_token):
        """
        Validates Roles by comparing names. Roles are global.
        """
        yield self._create_event("INFO", "Validating Roles (Global)...")

        # Fetch from Source
        yield self._create_event("INFO", f"Fetching roles from source: {src_url}...")
        src_role_names = yield from self._fetch_roles_names(src_url, src_token)
        src_role_set = set(src_role_names)
        yield self._create_event("INFO", f"Source Role Count: {len(src_role_set)}", source_count=len(src_role_set))

        # Fetch from Destination
        yield self._create_event("INFO", f"Fetching roles from destination: {dest_url}...")
        dest_role_names = yield from self._fetch_roles_names(dest_url, dest_token)
        dest_role_set = set(dest_role_names)
        yield self._create_event("INFO", f"Destination Role Count: {len(dest_role_set)}", dest_count=len(dest_role_set))

        # Compare and Report
        yield self._create_event("INFO", "\n--- Role Validation Summary ---", summary_type="roles")
        yield self._create_event("INFO", f"Roles (Global):", ko_type="roles")
        yield self._create_event("INFO", f"  Source Count: {len(src_role_set)}", location="source", count=len(src_role_set))
        yield self._create_event("INFO", f"  Destination Count: {len(dest_role_set)}", location="destination", count=len(dest_role_set))

        if len(src_role_set) == len(dest_role_set):
            yield self._create_event("INFO", "  Counts match for Roles.", status="counts_match")
        else:
            yield self._create_event("WARNING", "  Counts MISMATCH for Roles.", status="counts_mismatch")

        missing_at_dest = src_role_set - dest_role_set
        extra_at_dest = dest_role_set - src_role_set

        if missing_at_dest:
            yield self._create_event("WARNING", f"  Roles missing at destination: {', '.join(missing_at_dest)}",
                                     status="missing_at_dest", items=list(missing_at_dest))
        if extra_at_dest:
            yield self._create_event("WARNING", f"  Roles extra at destination: {', '.join(extra_at_dest)}",
                                     status="extra_at_dest", items=list(extra_at_dest))
        if not missing_at_dest and not extra_at_dest:
            yield self._create_event("INFO", "  All Role names match.", status="names_match")


# This is the entry point for the Splunk search command
dispatch(MigrationValidatorCommand, sys.argv, sys.stdin, sys.stdout, __name__)