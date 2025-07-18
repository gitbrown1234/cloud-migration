import os, sys
import time
import json
import requests
import xml.etree.ElementTree as ET
import urllib.parse
from datetime import datetime, timedelta
import re
import random
import string
from requests.exceptions import ConnectionError, Timeout
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add the lib directory to the sys.path for splunklib
# This assumes the script is placed in $SPLUNK_HOME/etc/apps/<your_app>/bin/
# and splunklib is in $SPLUNK_HOME/etc/apps/<your_app>/lib/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators


@Configuration()
class TransferKOCommand(GeneratingCommand):
    """
    The transferko command transfers Splunk knowledge objects between instances via REST API queries.
    It preserves ownership, sharing, and ACLs, and supports various migration filters.

    Example:
    ``| transferko srcURL="https://src_splunk:8089" destURL="https://dest_splunk:8089" srcUsername="admin" srcPassword="password" srcApp="search" destApp="my_new_app" all=true dry_run=true``
    """

    srcURL = Option(require=True)
    destURL = Option(require=True)
    srcUsername = Option(require=False)
    srcPassword = Option(require=False)
    srcApp = Option(require=True)
    destApp = Option(require=False)
    destUsername = Option(require=False)
    destPassword = Option(require=False)
    destOwner = Option(require=False)
    all = Option(require=False, validate=validators.Boolean(), default=False)
    enable_noPrivate = Option(require=False, validate=validators.Boolean(), default=False)
    enable_noDisabled = Option(require=False, validate=validators.Boolean(), default=False)
    enable_all = Option(require=False, validate=validators.Boolean(), default=False)
    enable_macros = Option(require=False, validate=validators.Boolean(), default=False)
    enable_tags = Option(require=False, validate=validators.Boolean(), default=False)
    enable_eventtypes = Option(require=False, validate=validators.Boolean(), default=False)
    enable_allFieldRelated = Option(require=False, validate=validators.Boolean(), default=False)
    enable_calcFields = Option(require=False, validate=validators.Boolean(), default=False)
    enable_fieldAlias = Option(require=False, validate=validators.Boolean(), default=False)
    enable_fieldExtraction = Option(require=False, validate=validators.Boolean(), default=False)
    enable_fieldTransforms = Option(require=False, validate=validators.Boolean(), default=False)
    enable_lookupDefinition = Option(require=False, validate=validators.Boolean(), default=False)
    enable_workflowActions = Option(require=False, validate=validators.Boolean(), default=False)
    enable_sourcetypeRenaming = Option(require=False, validate=validators.Boolean(), default=False)
    enable_sourcetypes = Option(require=False, validate=validators.Boolean(), default=False)
    enable_automaticLookup = Option(require=False, validate=validators.Boolean(), default=False)
    enable_datamodels = Option(require=False, validate=validators.Boolean(), default=False)
    enable_dashboards = Option(require=False, validate=validators.Boolean(), default=False)
    enable_savedsearches = Option(require=False, validate=validators.Boolean(), default=False)
    enable_navMenu = Option(require=False, validate=validators.Boolean(), default=False)
    enable_overrideMode = Option(require=False, validate=validators.Boolean(), default=False)
    enable_overrideAlwaysMode = Option(require=False, validate=validators.Boolean(), default=False)
    enable_collections = Option(require=False, validate=validators.Boolean(), default=False)
    enable_times = Option(require=False, validate=validators.Boolean(), default=False)
    enable_panels = Option(require=False, validate=validators.Boolean(), default=False)
    enable_debugMode = Option(require=False, validate=validators.Boolean(), default=False)
    enable_printPasswords = Option(require=False, validate=validators.Boolean(), default=False)
    includeEntities = Option(require=False)
    excludeEntities = Option(require=False)
    includeOwner = Option(require=False)
    excludeOwner = Option(require=False)
    enable_privateOnly = Option(require=False, validate=validators.Boolean(), default=False)
    enable_viewstates = Option(require=False, validate=validators.Boolean(), default=False)
    enable_ignoreViewstatesAttribute = Option(require=False, validate=validators.Boolean(), default=False)
    enable_disableAlertsOrReportsOnMigration = Option(require=False, validate=validators.Boolean(), default=False)
    nameFilter = Option(require=False, default="")
    sharingFilter = Option(require=False, validate=validators.Set("user", "app", "global"))
    srcAuthtype = Option(require=False, validate=validators.Set("password", "token"), default="password")
    destAuthtype = Option(require=False, validate=validators.Set("password", "token"), default="password")
    srcToken = Option(require=False)
    destToken = Option(require=False)
    enable_dry_run = Option(require=False, validate=validators.Boolean(), default=False)

    def generate(self):
        """
        Main generator method for the Splunk custom command.
        It orchestrates the knowledge object migration process.
        """
        # Set logger level based on debugMode
       # if self.debugMode:
       #     self.logger.setLevel(self.logger.debug)
       # else:
       #     self.logger.setLevel(self.logger.info)

        # Validate authentication parameters
        if self.srcAuthtype == 'token' and not self.srcToken:
            yield self._create_event("ERROR", "srcToken is required when srcAuthtype=token")
            return
        elif self.srcAuthtype == 'password' and (not self.srcUsername or not self.srcPassword):
            yield self._create_event("ERROR", "srcUsername and srcPassword are required when srcAuthtype=password")
            return

        if self.destAuthtype == 'token' and not self.destToken:
            yield self._create_event("ERROR", "destToken is required when destAuthtype=token")
            return
        elif self.destAuthtype == 'password' and (not self.destUsername or not self.destPassword):
            yield self._create_event("ERROR", "destUsername and destPassword are required when destAuthtype=password")
            return

        # Set default destApp if not provided
        if not self.destApp:
            self.destApp = self.srcApp

        # Process include/exclude entity and owner lists
        self.parsed_include_entities = set(x.strip() for x in self.includeEntities.split(',') if x.strip()) if self.includeEntities else None
        self.parsed_exclude_entities = set(x.strip() for x in self.excludeEntities.split(',') if x.strip()) if self.excludeEntities else None
        self.parsed_include_owner = set(x.strip() for x in self.includeOwner.split(',') if x.strip()) if self.includeOwner else None
        self.parsed_exclude_owner = set(x.strip() for x in self.excludeOwner.split(',') if x.strip()) if self.excludeOwner else None

        self.name_filter_regex = re.compile(self.nameFilter) if self.nameFilter else None

        # Initialize result dictionaries
        self.results = {
            "macros": {}, "tags": {}, "eventtypes": {}, "calcfields": {},
            "fieldaliases": {}, "fieldextractions": {}, "fieldtransformations": {},
            "lookupdefinitions": {}, "automaticlookups": {}, "times": {},
            "viewstates": {}, "panels": {}, "datamodels": {}, "dashboards": {},
            "savedsearches": {}, "workflowactions": {}, "sourcetyperenaming": {},
            "sourcetypes": {}, "navmenu": {}, "collections": {}
        }

        # If the all switch is provided, enable everything
# If the enable_all switch is provided, enable everything
        if self.all:
            self.enable_macros = True
            self.enable_tags = True
            self.enable_allFieldRelated = True
            self.enable_lookupDefinition = True
            self.enable_automaticLookup = True
            self.enable_datamodels = True
            self.enable_dashboards = True
            self.enable_savedsearches = True
            self.enable_navMenu = True
            self.enable_eventtypes = True
            self.enable_collections = True
            self.enable_times = True
            self.enable_panels = True
            self.enable_viewstates = True
            self.enable_sourcetypes = True

        # All field related switches on anything under Settings -> Fields
        if self.enable_allFieldRelated:
            self.enable_calcFields = True
            self.enable_fieldAlias = True
            self.enable_fieldExtraction = True
            self.enable_fieldTransforms = True
            self.enable_workflowActions = True
            self.enable_sourcetypeRenaming = True

        self.logger.info(f"Starting knowledge object transfer from {self.srcURL} (app: {self.srcApp}) to {self.destURL} (app: {self.destApp})")
        self.logger.debug(f"Command options: {self._without_keys(vars(self), ['srcPassword', 'destPassword', 'srcToken', 'destToken'])}")

        # Determine source app list (for wildcarded app names)
        src_app_list = []
        if self.srcApp.find("*") != -1:
            sys.exit()
            url = f"{self.srcURL}/services/apps/local?search=disabled%3D0&f=title&count=0&output_mode=json"
            app_pattern = re.compile(self.srcApp.replace('*', '.*')) # Convert wildcard to regex
            try:
                res = yield from self._make_request(
                    url, method='get', auth_type=self.srcAuthtype, username=self.srcUsername,
                    password=self.srcPassword, token=self.srcToken, verify=False
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
            src_app_list.append(self.srcApp)

        if not src_app_list:
            yield self._create_event("ERROR", f"No source applications found matching '{self.srcApp}'. Exiting.")
            return

        # Check and create destination app before starting transfers
        self.logger.info(f"Checking if destination app '{self.destApp}' exists on {self.destURL}")
        dest_parts = urllib.parse.urlparse(self.destURL)
        dest_host = dest_parts.hostname
        dest_port = dest_parts.port if dest_parts.port else '8089' # Default Splunk management port

        src_parts = urllib.parse.urlparse(self.srcURL)
        src_host = src_parts.hostname
        src_port = src_parts.port if src_parts.port else '8089'

        source_app_acl = None
        try:
            source_app_acl = yield from self._get_app_acl(
                src_host, src_port, self.srcAuthtype,
                self.srcUsername, self.srcPassword, self.srcToken, self.srcApp
            )
        except Exception as e:
            yield self._create_event("ERROR", f"Error getting source app ACL: {e}")
            return

        if source_app_acl:
            self.logger.info(
                f"Retrieved source app '{self.srcApp}' ACL - sharing: "
                f"{source_app_acl.get('sharing')}, owner: {source_app_acl.get('owner')}"
            )

        app_exists = yield from self._check_and_create_app(
            dest_host, dest_port, self.destAuthtype,
            self.destUsername, self.destPassword, self.destToken, self.destApp, source_app_acl
        )

        if not app_exists:
            yield self._create_event("ERROR", f"Cannot create or verify destination app '{self.destApp}' - exiting")
            return

        yield self._create_event("INFO", f"Destination app '{self.destApp}' is ready for knowledge object transfers")

        # Run the required functions based on the args
        for current_src_app in src_app_list:
            yield self._create_event("INFO", f"Processing knowledge objects from source app: {current_src_app}")

            if self.enable_macros:
                yield self._create_event("INFO", f"Begin macros transfer for app {current_src_app}")
                yield from self._macros(
                    current_src_app, self.destApp, self.destOwner, self.enable_noPrivate,
                    self.enable_noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.enable_privateOnly, self.enable_overrideMode,
                    self.enable_overrideAlwaysMode, self.results["macros"]
                )
                yield self._create_event("INFO", f"End macros transfer for app {current_src_app}")

            if self.enable_tags:
                yield self._create_event("INFO", f"Begin tags transfer for app {current_src_app}")
                yield from self._tags(
                    current_src_app, self.destApp, self.destOwner, self.enable_noPrivate,
                    self.enable_noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.enable_privateOnly, self.enable_overrideMode,
                    self.enable_overrideAlwaysMode, self.results["tags"]
                )
                yield self._create_event("INFO", f"End tags transfer for app {current_src_app}")

            if self.enable_eventtypes:
                yield self._create_event("INFO", f"Begin eventtypes transfer for app {current_src_app}")
                yield from self._eventtypes(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["eventtypes"]
                )
                yield self._create_event("INFO", f"End eventtypes transfer for app {current_src_app}")

            if self.enable_calcFields:
                yield self._create_event("INFO", f"Begin calcFields transfer for app {current_src_app}")
                yield from self._calcfields(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["calcfields"]
                )
                yield self._create_event("INFO", f"End calcFields transfer for app {current_src_app}")

            if self.enable_fieldAlias:
                yield self._create_event("INFO", f"Begin fieldAlias transfer for app {current_src_app}")
                yield from self._fieldaliases(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["fieldaliases"]
                )
                yield self._create_event("INFO", f"End fieldAlias transfer for app {current_src_app}")

            if self.enable_fieldTransforms:
                yield self._create_event("INFO", f"Begin fieldTransforms transfer for app {current_src_app}")
                yield from self._fieldtransformations(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["fieldtransformations"]
                )
                yield self._create_event("INFO", f"End fieldTransforms transfer for app {current_src_app}")

            if self.enable_fieldExtraction:
                yield self._create_event("INFO", f"Begin fieldExtraction transfer for app {current_src_app}")
                yield from self._fieldextractions(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["fieldextractions"]
                )
                yield self._create_event("INFO", f"End fieldExtraction transfer for app {current_src_app}")

            if self.enable_collections:
                yield self._create_event("INFO", f"Begin collections (kvstore definition) transfer for app {current_src_app}")
                yield from self._collections(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["collections"]
                )
                yield self._create_event("INFO", f"End collections (kvstore definition) transfer for app {current_src_app}")

            if self.enable_lookupDefinition:
                yield self._create_event("INFO", f"Begin lookupDefinitions transfer for app {current_src_app}")
                yield from self._lookupdefinitions(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["lookupdefinitions"]
                )
                yield self._create_event("INFO", f"End lookupDefinitions transfer for app {current_src_app}")

            if self.enable_automaticLookup:
                yield self._create_event("INFO", f"Begin automaticLookup transfer for app {current_src_app}")
                yield from self._automaticlookups(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["automaticlookups"]
                )
                yield self._create_event("INFO", f"End automaticLookup transfer for app {current_src_app}")

            if self.enable_times:
                yield self._create_event("INFO", f"Begin times (conf-times) transfer for app {current_src_app}")
                yield from self._times(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["times"]
                )
                yield self._create_event("INFO", f"End times (conf-times) transfer for app {current_src_app}")

            if self.enable_viewstates:
                yield self._create_event("INFO", f"Begin viewstates transfer for app {current_src_app}")
                yield from self._viewstates(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["viewstates"]
                )
                yield self._create_event("INFO", f"End viewstates transfer for app {current_src_app}")

            if self.enable_panels:
                yield self._create_event("INFO", f"Begin pre-built dashboard panels transfer for app {current_src_app}")
                yield from self._panels(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["panels"]
                )
                yield self._create_event("INFO", f"End pre-built dashboard panels transfer for app {current_src_app}")

            if self.enable_datamodels:
                yield self._create_event("INFO", f"Begin datamodels transfer for app {current_src_app}")
                yield from self._datamodels(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["datamodels"]
                )
                yield self._create_event("INFO", f"End datamodels transfer for app {current_src_app}")

            if self.enable_dashboards:
                yield self._create_event("INFO", f"Begin dashboards transfer for app {current_src_app}")
                yield from self._dashboards(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["dashboards"]
                )
                yield self._create_event("INFO", f"End dashboards transfer for app {current_src_app}")

            if self.enable_savedsearches:
                yield self._create_event("INFO", f"Begin savedsearches transfer for app {current_src_app}")
                yield from self._savedsearches(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.ignoreViewstatesAttribute,
                    self.disableAlertsOrReportsOnMigration, self.overrideMode,
                    self.overrideAlwaysMode, self.results["savedsearches"]
                )
                yield self._create_event("INFO", f"End savedsearches transfer for app {current_src_app}")

            if self.enable_workflowActions:
                yield from self._create_event("INFO", f"Begin workflowActions transfer for app {current_src_app}")
                yield from self._workflowactions(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["workflowactions"]
                )
                yield self._create_event("INFO", f"End workflowActions transfer for app {current_src_app}")

            if self.enable_sourcetypeRenaming:
                yield from self._create_event("INFO", f"Begin sourcetypeRenaming transfer for app {current_src_app}")
                yield from self._sourcetyperenaming(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["sourcetyperenaming"]
                )
                yield self._create_event("INFO", f"End sourcetypeRenaming transfer for app {current_src_app}")

            if self.enable_sourcetypes:
                yield from self._create_event("INFO", f"Begin sourcetypes transfer for app {current_src_app}")
                yield from self._sourcetypes(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["sourcetypes"]
                )
                yield self._create_event("INFO", f"End sourcetypes transfer for app {current_src_app}")

            if self.enable_navMenu:
                yield from self._create_event("INFO", f"Begin navMenu transfer for app {current_src_app}")
                yield from self._navmenu(
                    current_src_app, self.destApp, self.destOwner, self.noPrivate,
                    self.noDisabled, self.parsed_include_entities, self.parsed_exclude_entities, self.parsed_include_owner,
                    self.parsed_exclude_owner, self.privateOnly, self.overrideMode,
                    self.overrideAlwaysMode, self.results["navmenu"]
                )
                yield self._create_event("INFO", f"End navMenu transfer for app {current_src_app}")

        # Final Logging
        for ko_type, ko_results in self.results.items():
            if ko_results: # Only log if there were results for this type
                yield from self._log_stats(ko_results, ko_type, self.srcApp)
                yield from self._handle_failure_logging(ko_results, ko_type, self.srcApp)
                yield from self._log_deletion_script_in_logs(ko_results, self.enable_printPasswords, self.destUsername, self.destPassword)

        yield self._create_event("INFO", "Knowledge object transfer process completed.")
        yield self._create_event("INFO", "The undo command is: grep -o \"curl.*DELETE.*\" /tmp/transfer_knowledgeobj.log | grep -v \"curl\.\*DELETE\"")


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

    def _make_request(self, url, method='get', auth_type='password', username='', password='', token='', data=None, verify=False):
        """
        Centralized function to make HTTP requests with either token or password authentication.
        Yields events for retries or errors.
        """
        headers = {}
        auth = None
        max_retries = 5
        base_delay = 1  # seconds

        if auth_type == 'token':
            headers['Authorization'] = f'Bearer {token}'
        else:
            auth = (username, password)

        for attempt in range(max_retries):
            try:
                if method.lower() == 'get':
                    response = requests.get(url, auth=auth, headers=headers, verify=verify, timeout=30)
                elif method.lower() == 'post':
                    response = requests.post(url, auth=auth, headers=headers, verify=verify, data=data, timeout=30)
                elif method.lower() == 'delete':
                    response = requests.delete(url, auth=auth, headers=headers, verify=verify, timeout=30)
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
                    raise  # Re-raise the last exception after all retries fail
            except requests.exceptions.RequestException as e:
                yield self._create_event("ERROR", f"An unexpected error occurred during request to {url}: {e}")
                raise

    def _check_and_create_user(self, host, port, auth_type, username, password, token, user_to_check):
        """
        Check if a user exists on the destination system and create them if they don't
        """
        check_url = f"https://{host}:{port}/services/authentication/users/{user_to_check}"

        try:
            response = yield from self._make_request(check_url, method='get', auth_type=auth_type,
                                                  username=username, password=password, token=token, verify=False)

            if response.status_code == 200:
                self.logger.debug(f"User '{user_to_check}' already exists on destination")
                return True
            elif response.status_code == 404:
                yield self._create_event("INFO", f"User '{user_to_check}' does not exist on destination, creating...")

                random_password = ''.join(random.choices(string.ascii_letters + string.digits + '!@#$%^&*', k=16))

                create_url = f"https://{host}:{port}/services/authentication/users"
                create_data = {
                    'name': user_to_check,
                    'password': random_password,
                    'roles': 'user',
                    'force-change-pass': '1'
                }

                create_response = yield from self._make_request(create_url, method='post', auth_type=auth_type,
                                                             username=username, password=password, token=token,
                                                             data=create_data, verify=False)

                if create_response.status_code in [200, 201]:
                    yield self._create_event("INFO", f"Successfully created user '{user_to_check}' on destination with temporary password (forced change on first login).")
                    return True
                else:
                    yield self._create_event("ERROR", f"Failed to create user '{user_to_check}': status={create_response.status_code}, response={create_response.text}")
                    return False
            else:
                yield self._create_event("ERROR", f"Failed to check user '{user_to_check}': status={response.status_code}, response={response.text}")
                return False

        except Exception as e:
            yield self._create_event("ERROR", f"Error checking/creating user '{user_to_check}': {e}")
            return False

    def _get_app_acl(self, host, port, auth_type, username, password, token, app_name):
        """
        Get ACL information for an app
        """
        check_url = f"https://{host}:{port}/services/apps/local/{app_name}?output_mode=json"

        try:
            response = yield from self._make_request(check_url, method='get', auth_type=auth_type,
                                                  username=username, password=password, token=token, verify=False)

            if response.status_code == 200:
                data = response.json()
                if 'entry' in data and len(data['entry']) > 0:
                    acl = data['entry'][0].get('acl', {})
                    self.logger.debug(f"Retrieved ACL for app '{app_name}': sharing={acl.get('sharing')}, owner={acl.get('owner')}")
                    return acl

            yield self._create_event("WARNING", f"Could not retrieve ACL for app '{app_name}': status={response.status_code}, response={response.text}")
            return None

        except Exception as e:
            yield self._create_event("ERROR", f"Error getting ACL for app '{app_name}': {e}")
            return None

    def _set_app_acl(self, host, port, auth_type, username, password, token, app_name, acl_info):
        """
        Set ACL on an app to match source ACL
        """
        owner = acl_info.get('owner', 'nobody')

        if owner != 'nobody':
            user_exists = yield from self._check_and_create_user(host, port, auth_type, username, password, token, owner)
            if not user_exists:
                yield self._create_event("WARNING", f"Cannot create or verify owner '{owner}' for app '{app_name}' ACL - using 'nobody' instead")
                owner = 'nobody'

        acl_url = f"https://{host}:{port}/services/apps/local/{app_name}/acl"

        acl_data = {
            'output_mode': 'json',
            'owner': owner,
            'sharing': acl_info.get('sharing', 'app')
        }

        perms = acl_info.get('perms', {})
        if 'read' in perms and perms['read']:
            if isinstance(perms['read'], list):
                acl_data['perms.read'] = ','.join(perms['read'])
            else:
                acl_data['perms.read'] = str(perms['read'])

        if 'write' in perms and perms['write']:
            if isinstance(perms['write'], list):
                acl_data['perms.write'] = ','.join(perms['write'])
            else:
                acl_data['perms.write'] = str(perms['write'])

        try:
            response = yield from self._make_request(acl_url, method='post', auth_type=auth_type,
                                                  username=username, password=password, token=token,
                                                  data=acl_data, verify=False)

            if response.status_code in [200, 201]:
                yield self._create_event("INFO", f"Successfully set ACL on app '{app_name}' (sharing: {acl_data['sharing']}, owner: {acl_data['owner']})")
                return True
            else:
                yield self._create_event("WARNING", f"Failed to set ACL on app '{app_name}': status={response.status_code}, response={response.text}")
                return False

        except Exception as e:
            yield self._create_event("WARNING", f"Error setting ACL on app '{app_name}': {e}")
            return False

    def _check_and_create_app(self, host, port, auth_type, username, password, token, app_name, source_acl=None):
        """
        Check if an app exists on the destination system and create it if it doesn't
        """
        check_url = f"https://{host}:{port}/services/apps/local/{app_name}"

        try:
            response = yield from self._make_request(check_url, method='get', auth_type=auth_type,
                                                  username=username, password=password, token=token, verify=False)

            if response.status_code == 200:
                self.logger.debug(f"App '{app_name}' already exists on destination")
                return True
            elif response.status_code == 404:
                yield self._create_event("INFO", f"App '{app_name}' does not exist on destination, creating...")

                create_url = f"https://{host}:{port}/services/apps/local"
                create_data = {
                    'name': app_name,
                    'label': app_name,
                    'visible': '1',
                    'author': 'auto-created',
                    'description': f'Auto-created app during knowledge object transfer'
                }

                create_response = yield from self._make_request(create_url, method='post', auth_type=auth_type,
                                                             username=username, password=password, token=token,
                                                             data=create_data, verify=False)

                if create_response.status_code in [200, 201]:
                    yield self._create_event("INFO", f"Successfully created app '{app_name}' on destination.")
                    if source_acl:
                        yield from self._set_app_acl(host, port, auth_type, username, password, token, app_name, source_acl)
                    return True
                else:
                    yield self._create_event("ERROR", f"Failed to create app '{app_name}': status={create_response.status_code}, response={create_response.text}")
                    return False
            else:
                yield self._create_event("ERROR", f"Failed to check app '{app_name}': status={response.status_code}, response={response.text}")
                return False

        except Exception as e:
            yield self._create_event("ERROR", f"Error checking/creating app '{app_name}': {e}")
            return False

    def _determine_time(self, timestampStr, name, app, obj_type):
        """Converts Splunk REST API timestamp string to datetime object."""
        self.logger.debug(f"Attempting to convert {timestampStr} to timestamp for {name} name, in app {app} for type {obj_type}")
        try:
            ret = datetime.strptime(timestampStr[0:19], "%Y-%m-%dT%H:%M:%S")
            if len(timestampStr) > 19: # Handle timezone offset if present
                if timestampStr[19] == '+':
                    ret -= timedelta(hours=int(timestampStr[20:22]), minutes=int(timestampStr[24:]))
                elif timestampStr[19] == '-':
                    ret += timedelta(hours=int(timestampStr[20:22]), minutes=int(timestampStr[24:]))
            self.logger.debug(f"Converted time is {ret} for {name} name, in app {app} for type {obj_type}")
            return ret
        except ValueError as e:
            self.logger.warning(f"Could not parse timestamp '{timestampStr}' for {name} ({obj_type}): {e}. Returning current time.")
            return datetime.now()


    def _append_to_results(self, resultsDict, name, result):
        if name not in resultsDict:
            resultsDict[name] = []
        resultsDict[name].append(result)

    def _pop_last_result(self, resultsDict, name):
        if name in resultsDict:
            if len(resultsDict[name]) > 0:
                resultsDict[name].pop()

    def _run_queries(self, app, endpoint, obj_type, fieldIgnoreList, destApp, aliasAttributes={}, valueAliases={}, nameOverride="",
                   destOwner=None, noPrivate=False, noDisabled=False, override=None, includeEntities=None,
                   excludeEntities=None, includeOwner=None, excludeOwner=None, privateOnly=False,
                   disableAlertsOrReportsOnMigration=False, overrideAlways=None, actionResults=None):
        """
        Generic function to query source Splunk REST API, parse XML, and post to destination.
        """
        yield self._create_event("DEBUG", f"Inside _run_queries: Starting for type {obj_type} in app {app}")

        url = f"{self.srcURL}/servicesNS/-/{app}{endpoint}?count=-1"
        self.logger.debug(f"Running requests.get() on {url} with username {self.srcUsername} in app {app}")

        res = yield from self._make_request(
            url, method='get', auth_type=self.srcAuthtype, username=self.srcUsername,
            password=self.srcPassword, token=self.srcToken, verify=False
        )
        if res.status_code != requests.codes.ok:
            yield self._create_event("ERROR", f"URL {url} in app {app} status code {res.status_code} reason {res.reason}, response: '{res.text}'")
            return

        root = ET.fromstring(res.text)
        infoList = {}

        for child in root:
            # For debugging, printing the Element object directly
            try:
                with open("/tmp/test", "a") as f:
                    f.write(f"Processing child: {child}\n")
            except Exception as e:
                yield self._create_event("ERROR", f"Failed to write child to /tmp/test: {e}")

            if child.tag.endswith("entry"):
                info = {}
                # Initialize sharing and owner with default values
                info["sharing"] = "app" # Default to 'app' sharing if not found
                info["owner"] = "nobody" # Default owner if not found
                keep = True
                acl_info = {} # Reset acl_info for each entry

                for innerChild in child:
                    if innerChild.tag.endswith("title"):
                        title = innerChild.text
                        info["name"] = title
                        self.logger.debug(f"Found {obj_type} title/name: {title} in app {app}.")

                        if includeEntities and title not in includeEntities:
                            keep = False
                            break
                        if excludeEntities and title in excludeEntities:
                            keep = False
                            break
                        if self.name_filter_regex and not self.name_filter_regex.search(title):
                            keep = False
                            break
                        if 'name' in list(aliasAttributes.values()):
                            info["origName"] = title

                    elif innerChild.tag.endswith("updated"):
                        updatedStr = innerChild.text
                        info['updated'] = self._determine_time(updatedStr, info.get("name", "unknown"), app, obj_type)
                        self.logger.debug(f"name {info.get('name', 'unknown')}, type {obj_type} in app {app} was updated on {info['updated']}.")

                    elif innerChild.tag.endswith("content"):
                        # In _run_queries, <content> often contains a single <s:dict> child
                        # This 'content_dict_element' will be the <s:dict> element itself
                        if len(innerChild) == 0: # Handle empty content tags
                            continue
                        content_dict_element = innerChild[0] # Assuming <content> has a single child which is <s:dict>

                        # Debugging for content_dict_element (keep if needed)
                        try:
                            with open("/tmp/test", "a") as f:
                                f.write(f"  Processing content dict: {content_dict_element.tag}\n")
                                f.write(f"  Attributes: {content_dict_element.attrib}\n")
                        except Exception as e:
                            yield self._create_event("ERROR", f"Failed to write content dict to /tmp/test: {e}")

                        # Iterate over the children of the <s:dict> element.
                        # These children are the individual <s:key> elements representing properties.
                        for property_element in content_dict_element:
                            # property_element will be an <s:key> element
                            # Debugging for property_element (keep if needed)
                            try:
                                with open("/tmp/test", "a") as f:
                                    f.write(f"    Processing property element: {property_element.tag}\n")
                                    f.write(f"    Attributes: {property_element.attrib}\n")
                                    f.write(f"    Text: {property_element.text}\n")
                            except Exception as e:
                                yield self._create_event("ERROR", f"Failed to write property element to /tmp/test: {e}")

                            # Get the property name from the 'name' attribute of the <s:key> element
                            property_name = self._get_local_name(property_element.attrib.get('name', ''))
                            property_value = property_element.text # Get the text content of the <s:key> element

                            # Handle special case for eai:acl, which is a nested dict
                            if property_name == 'eai:acl':
                                # The value of eai:acl is another <s:dict> element, not simple text
                                # So, property_element[0] is the nested <s:dict> element
                                if len(property_element) == 0: # Handle empty eai:acl tags
                                    continue
                                acl_dict_element = property_element[0]
                                if 'perms' not in acl_info: # Initialize perms if not already
                                    acl_info['perms'] = {}

                                # Iterate over children of this nested <s:dict> (these are also <s:key> elements)
                                for acl_prop_element in acl_dict_element:
                                    acl_prop_name = self._get_local_name(acl_prop_element.attrib.get('name', ''))
                                    acl_prop_value = acl_prop_element.text

                                    if acl_prop_name == 'sharing':
                                        info["sharing"] = acl_prop_value # Overwrite default
                                        acl_info["sharing"] = acl_prop_value
                                        # Existing sharing checks (keep these)
                                        if noPrivate and info["sharing"] == "user":
                                            keep = False
                                            break
                                        elif privateOnly and info["sharing"] != "user":
                                            keep = False
                                            break
                                        if self.sharingFilter and not self.sharingFilter == info["sharing"]:
                                            keep = False
                                            break
                                    elif acl_prop_name == 'app':
                                        foundApp = acl_prop_value
                                        acl_info["app"] = foundApp
                                        # Existing app checks (keep these)
                                        if app != foundApp:
                                            keep = False
                                            break
                                    elif acl_prop_name == 'owner':
                                        info["owner"] = acl_prop_value # Overwrite default
                                        owner = acl_prop_value
                                        acl_info["owner"] = owner
                                        # Existing owner checks (keep these)
                                        if includeOwner and owner not in includeOwner:
                                            keep = False
                                            break
                                        if excludeOwner and owner in excludeOwner:
                                            keep = False
                                            break
                                    elif acl_prop_name == 'perms.read':
                                        # perms.read/write often contain an <s:list> as child, which has <s:item> children
                                        if len(acl_prop_element) > 0:
                                            read_perms_list_element = acl_prop_element[0] # This is the <s:list> element
                                            read_perms = [self._get_local_name(item.text) for item in read_perms_list_element if item.text is not None]
                                            acl_info['perms']['read'] = read_perms
                                    elif acl_prop_name == 'perms.write':
                                        if len(acl_prop_element) > 0:
                                            write_perms_list_element = acl_prop_element[0] # This is the <s:list> element
                                            write_perms = [self._get_local_name(item.text) for item in write_perms_list_element if item.text is not None]
                                            acl_info['perms']['write'] = write_perms

                                # If any 'keep' flag was set to False in ACL checks, break outer loop
                                if not keep: break # Break from acl_prop_element loop if keep is False

                            # Handle other regular properties (not eai:acl)
                            else:
                                # Apply fieldIgnoreList and valueAliases here
                                if property_name in fieldIgnoreList:
                                    continue # Skip this property

                                # Apply valueAliases
                                if property_value in valueAliases:
                                    property_value = valueAliases[property_value]

                                # Specific hacks from original script for collections/datamodels
                                if obj_type == "collections (kvstore definition)" and property_name.startswith("accelrated_fields"):
                                    property_name = "accelerated_fields" + property_name[17:]
                                elif property_name == "description" and obj_type=="datamodels" and "dataset.type" in info and info["dataset.type"] == "table":
                                    # This specific hack for datamodels assumes description is JSON, and modifies it.
                                    try:
                                        res_json = json.loads(property_value)
                                        if 'objects' in res_json and len(res_json['objects']) > 0 and 'fields' in res_json['objects'][0]:
                                            fields = res_json['objects'][0]['fields']
                                            res_json['objects'][0]['fields'] = [f for f in fields if f.get('fieldName') == "RootObject"]
                                        info[property_name] = json.dumps(res_json)
                                    except json.JSONDecodeError:
                                        info[property_name] = property_value # Fallback if not valid JSON
                                elif property_value is not None:
                                    info[property_name] = property_value
                                elif obj_type=="automatic lookup" and property_value is None:
                                    info[property_name] = ""

                            # Check for 'disabled' status (general check)
                            # This check applies to the property_name extracted from the <s:key> element
                            if property_name == "disabled" and noDisabled and property_value == "1":
                                yield self._create_event("DEBUG", f"{info.get('name', 'unknown')} of type {obj_type} is disabled and the noDisabled flag is true, excluding this in app {app}")
                                keep = False
                                break # Break from property_element loop

                        # If any 'keep' flag was set to False during content parsing, break outer loop
                        if not keep: break

                # If we reach here, 'keep' is True, proceed with processing the info
                if keep:
                    # Store the complete ACL information
                    info["acl_info"] = acl_info

                    if nameOverride != "":
                        info["origName"] = info["name"]
                        info["name"] = info[nameOverride]
                        if obj_type == "fieldextractions" and info["name"].startswith("EXTRACT-"):
                            info["name"] = info["name"][8:]
                        elif obj_type == "fieldextractions" and info["name"].startswith("REPORT-"):
                            info["name"] = info["name"][7:]
                        elif obj_type == "automatic lookup" and info["name"].startswith("LOOKUP-"):
                            info["name"] = info["name"][7:]
                        elif obj_type == "fieldaliases":
                            newName = info["name"]
                            newName = newName[newName.find("FIELDALIAS-") + 11:]
                            info["name"] = newName

                    # Some attributes are not used to create a new version so we remove them
                    for attribName in fieldIgnoreList:
                        if attribName in info:
                            del info[attribName]

                    # If we are migrating but leaving the old app enabled in a previous environment
                    # we may not want to leave the report and/or alert enabled
                    if disableAlertsOrReportsOnMigration and obj_type == "savedsearches":
                        if "disabled" in info and info["disabled"] == "0" and "alert_condition" in info:
                            info["disabled"] = 1
                            yield self._create_event("INFO", f"{obj_type} of type {info['name']} (alert) in app {app} with owner {info['owner']} was enabled but disableAlertsOrReportOnMigration set, setting to disabled.")
                        elif "is_scheduled" in info and "alert_condition" not in info and info["is_scheduled"] == "1":
                            info["is_scheduled"] = 0
                            yield self._create_event("INFO", f"{obj_type} of type {info['name']} (scheduled report) in app {app} with owner {info['owner']} was enabled but disableAlertsOrReportOnMigration set, setting to disabled.")

                    # Add this to the infoList
                    sharing = info["sharing"]
                    if sharing not in infoList:
                        infoList[sharing] = []

                    if obj_type == "fieldtransformations" and "FORMAT" in info and info["FORMAT"] == "nullQueue":
                        yield self._create_event("WARNING", f"Dropping the transfer of {info['name']} of type {obj_type} in app context {app} with owner {info['owner']} because nullQueue entries cannot be created via REST API (and they are not required in search heads).")
                    else:
                        infoList[sharing].append(info)
                        yield self._create_event("INFO", f"Recording {obj_type} info for {info['name']} in app context {app} with owner {info['owner']}.")

        dest_app_name = destApp
        for sharing_level in ["global", "app", "user"]:
            if sharing_level in infoList:
                yield self._create_event("INFO", f"Now running _run_queries_per_list with knowledge objects of type {obj_type} with {sharing_level} level sharing in app {dest_app_name}.")
                yield from self._run_queries_per_list(
                    infoList[sharing_level], destOwner, obj_type, override, dest_app_name, self.destURL,
                    endpoint, actionResults, overrideAlways, self.enable_dry_run
                )
        # No return statement here.

    def _run_queries_per_list(self, infoList, destOwner, obj_type, override, app, splunk_rest_dest, endpoint, 
                              actionResults, overrideAlways, dry_run):
        """
        Runs the required queries to create the knowledge object and then re-owns them to the correct user.
        """
        checked_users = set()

        for anInfo in infoList:
            sharing = anInfo["sharing"]
            owner = anInfo["owner"]
            acl_info = anInfo.get("acl_info", {})

            if destOwner:
                owner = destOwner

            if owner not in checked_users and owner != 'nobody':
                dest_parts = urllib.parse.urlparse(splunk_rest_dest)
                dest_host = dest_parts.hostname
                dest_port = dest_parts.port if dest_parts.port else '8089'

                user_exists = yield from self._check_and_create_user(
                    dest_host, dest_port, self.destAuthtype,
                    self.destUsername, self.destPassword, self.destToken, owner
                )
                if not user_exists:
                    yield self._create_event("ERROR", f"Cannot create or verify user '{owner}' on destination system.")
                    self._append_to_results(actionResults, 'creationFailure', f"User creation failed for {anInfo['name']}")
                    continue
                checked_users.add(owner)

            payload = anInfo.copy() # Use a copy to modify
            del payload["sharing"]
            del payload["owner"]
            if "acl_info" in payload:
                del payload["acl_info"]

            name = payload["name"]
            curUpdated = payload["updated"]
            del payload["updated"]

            objURL = None
            origName = None
            encoded_name = urllib.parse.quote(name.encode('utf-8'))
            encoded_name = encoded_name.replace("/", "%2F")

            if 'origName' in payload:
                origName = payload['origName']
                del payload['origName']
                objURL = f"{splunk_rest_dest}/servicesNS/-/{app}/{endpoint}/{urllib.parse.quote(origName.encode('utf-8')).replace('/', '%2F')}?output_mode=json"
            else:
                if obj_type == "datamodels":
                    objURL = f"{splunk_rest_dest}/servicesNS/{owner}/{app}/{endpoint}/{encoded_name}?output_mode=json"
                else:
                    objURL = f"{splunk_rest_dest}/servicesNS/-/{app}/{endpoint}/{encoded_name}?output_mode=json"
            self.logger.debug(f"{name} of type {obj_type} checking on URL {objURL} to see if it exists.")

            objExists = False
            updated_remote = None # Renamed to avoid conflict with 'updated' in payload
            
            try:
                res = yield from self._make_request(
                    objURL, method='get', auth_type=self.destAuthtype, username=self.destUsername,
                    password=self.destPassword, token=self.destToken, verify=False
                )
                if res.status_code == 404:
                    self.logger.debug(f"URL {objURL} is throwing a 404, assuming new object creation.")
                elif res.status_code != requests.codes.ok:
                    yield self._create_event("ERROR", f"URL {objURL} in app {app} status code {res.status_code} reason {res.reason}, response: '{res.text}'")
                else:
                    resDict = json.loads(res.text)
                    for entry in resDict['entry']:
                        sharingLevel = entry['acl']['sharing']
                        appContext = entry['acl']['app']
                        updatedStr = entry['updated']
                        remoteObjOwner = entry['acl']['owner']
                        updated_remote = self._determine_time(updatedStr, name, app, obj_type)

                        if (appContext == app and (sharing == 'app' or sharing == 'global') and
                                (sharingLevel == 'app' or sharingLevel == 'global')):
                            objExists = True
                        elif (appContext == app and sharing == 'user' and
                            sharingLevel == "user" and remoteObjOwner == owner):
                            objExists = True
                        elif (appContext == app and sharingLevel == "user" and
                            remoteObjOwner == owner and (sharing == "app" or sharing == "global")):
                            # This case means a private object exists, but we're trying to create an app/global one.
                            # We still consider it existing to avoid creating a duplicate.
                            objExists = True
                        if objExists:
                            self.logger.debug(f"name {name} of type {obj_type} in app context {app} found to exist on url {objURL} with sharing of {sharingLevel}, updated time of {updated_remote}.")
                            break # Found the object, no need to check other entries
            except Exception as e:
                yield self._create_event("ERROR", f"Error checking existence of {name} ({obj_type}): {e}")
                
            if obj_type == "times (conf-times)" and "is_sub_menu" not in payload:
                payload["is_sub_menu"] = "0"

            target_url = f"{splunk_rest_dest}/servicesNS/{owner}/{app}/{endpoint}"
            if sharing == 'app' or sharing == 'global':
                target_url = f"{splunk_rest_dest}/servicesNS/nobody/{app}/{endpoint}"
                self.logger.info(f"name {name} of type {obj_type} in app context {app}, sharing level is non-user so creating with nobody context updated url is {target_url}.")

            if objExists is False:
                if dry_run:
                    yield self._create_event("INFO", f"DRY RUN: Would create {name} of type {obj_type} on URL {target_url} with payload '{payload}'.")
                    self._append_to_results(actionResults, 'creationSkip', name) # Treat as skipped in dry run
                    continue

                self.logger.debug(f"Attempting to create {obj_type} with name {name} on URL {target_url} with payload '{payload}' in app {app}.")
                res = yield from self._make_request(
                    target_url, method='post', auth_type=self.destAuthtype, username=self.destUsername,
                    password=self.destPassword, token=self.destToken, data=payload, verify=False
                )
                if res.status_code not in [requests.codes.ok, 201]:
                    yield self._create_event("ERROR", f"{name} of type {obj_type} with URL {target_url} status code {res.status_code} reason {res.reason}, response '{res.text}', in app {app}, owner {owner}.")
                    self._append_to_results(actionResults, 'creationFailure', name)
                    continue
                else:
                    self.logger.debug(f"{name} of type {obj_type} in app {app} with URL {target_url} result is: '{res.text}' owner of {owner}.")

                deletionURL = None
                creationSuccessRes = False
                try:
                    root = ET.fromstring(res.text)
                    for child in root:
                        if child.tag.endswith("entry"):
                            for innerChild in child:
                                if innerChild.tag.endswith("link") and innerChild.attrib["rel"] == "list":
                                    deletionURL = f"{splunk_rest_dest}/{innerChild.attrib['href']}"
                                    self.logger.debug(f"{name} of type {obj_type} in app {app} recording deletion URL as {deletionURL}.")
                                    self._append_to_results(actionResults, 'creationSuccess', deletionURL)
                                    creationSuccessRes = True
                        elif child.tag.endswith("messages"):
                            for innerChild in child:
                                if (innerChild.tag.endswith("msg") and (innerChild.attrib["type"] == "ERROR" or "WARN" in innerChild.attrib)):
                                    yield self._create_event("WARNING", f"{name} of type {obj_type} in app {app} had a warn/error message of '{innerChild.text}' owner of {owner}.")
                                    self._append_to_results(actionResults, 'creationFailure', name)
                except ET.ParseError as e:
                    yield self._create_event("ERROR", f"Failed to parse XML response for {name} ({obj_type}) during creation: {e}. Response: {res.text}")
                    self._append_to_results(actionResults, 'creationFailure', name)
                    continue

                if not deletionURL:
                    yield self._create_event("WARNING", f"Could not determine deletion URL for {name} of type {obj_type} in app {app}. ACL change might fail.")
                    continue

                # Re-owning it to the previous owner
                acl_url = f"{deletionURL}/acl"
                acl_payload = {"owner": owner, "sharing": sharing}
                self.logger.info(f"Attempting to change ownership of {obj_type} with name {name} via URL {acl_url} to owner {owner} in app {app} with sharing {sharing}.")
                res = yield from self._make_request(
                    acl_url, method='post', auth_type=self.destAuthtype, username=self.destUsername,
                    password=self.destPassword, token=self.destToken, data=acl_payload, verify=False
                )

                if res.status_code not in [requests.codes.ok, 200, 201]:
                    yield self._create_event("ERROR", f"{name} of type {obj_type} in app {app} with URL {acl_url} status code {res.status_code} reason {res.reason}, response '{res.text}', owner of {owner}.")
                    self._append_to_results(actionResults, 'creationFailure', name)
                    if res.status_code == 409: # Conflict
                        if obj_type == "eventtypes":
                            yield self._create_event("WARNING", f"Received a 409 while changing the ACL permissions of {name} of type {obj_type} in app {app} with URL {acl_url}, however eventtypes throw this error and work anyway. Ignoring!")
                        else:
                            yield self._create_event("WARNING", f"Deleting the private object as it could not be re-owned {name} of type {obj_type} in app {app} with URL {deletionURL}.")
                            yield from self._make_request(
                                deletionURL, method='delete', auth_type=self.destAuthtype,
                                username=self.destUsername, password=self.destPassword,
                                token=self.destToken, verify=False
                            )
                            if creationSuccessRes:
                                self._pop_last_result(actionResults, 'creationSuccess')
                    continue
                else:
                    self.logger.debug(f"{name} of type {obj_type} in app {app}, ownership changed. Response: {res.text}. Will update deletion URL. Owner: {owner}, Sharing: {sharing}.")
                    try:
                        root = ET.fromstring(res.text)
                        for child in root:
                            if child.tag.endswith("entry"):
                                for innerChild in child:
                                    if innerChild.tag.endswith("link") and innerChild.attrib["rel"]=="list":
                                        deletionURL = f"{splunk_rest_dest}/{innerChild.attrib['href']}"
                                        self.logger.debug(f"{name} of type {obj_type} in app {app} recording new deletion URL: {deletionURL}. Owner: {owner}, Sharing: {sharing}.")
                                        self._pop_last_result(actionResults, 'creationSuccess')
                                        self._append_to_results(actionResults, 'creationSuccess', deletionURL)
                    except ET.ParseError as e:
                        yield self._create_event("ERROR", f"Failed to parse XML response for {name} ({obj_type}) during ACL update: {e}. Response: {res.text}")
                        self._append_to_results(actionResults, 'creationFailure', name)
                        continue

                if creationSuccessRes:
                    yield self._create_event("INFO", f"Created {name} of type {obj_type} in app {app}. Owner: {owner}, Sharing: {sharing}.")
                else:
                    yield self._create_event("WARNING", f"Attempted to create {name} of type {obj_type} in app {app} (Owner: {owner}, Sharing: {sharing}) but failed.")
            else: # Object exists already
                if override or overrideAlways:
                    if override and updated_remote and curUpdated <= updated_remote:
                        yield self._create_event("INFO", f"{name} of type {obj_type} in app {app} with URL {objURL}, owner {owner}, source object says time of {curUpdated}, destination object says time of {updated_remote}, skipping this entry.")
                        self._append_to_results(actionResults, 'creationSkip', objURL)
                        continue
                    else:
                        yield self._create_event("INFO", f"{name} of type {obj_type} in app {app} with URL {objURL}, owner {owner}, source object says time of {curUpdated}, destination object says time of {updated_remote}, will update this entry.")
                    
                    if dry_run:
                        yield self._create_event("INFO", f"DRY RUN: Would update {name} of type {obj_type} on URL {objURL} with payload '{payload}'.")
                        self._append_to_results(actionResults, 'creationSkip', name) # Treat as skipped in dry run
                        continue

                    update_url = objURL
                    url_name = origName if origName else encoded_name

                    if sharing == "user":
                        update_url = f"{splunk_rest_dest}/servicesNS/{owner}/{app}/{endpoint}/{url_name}"
                    else:
                        update_url = f"{splunk_rest_dest}/servicesNS/nobody/{app}/{endpoint}/{url_name}"

                    if 'type' in payload: del payload['type']
                    if 'stanza' in payload: del payload['stanza']
                    if 'name' in payload: del payload['name']
                    
                    self.logger.debug(f"Attempting to update {obj_type} with name {name} on URL {update_url} with payload '{payload}'.")
                    res = yield from self._make_request(
                        update_url, method='post', auth_type=self.destAuthtype, username=self.destUsername,
                        password=self.destPassword, token=self.destToken, data=payload, verify=False
                    )
                    if res.status_code not in [requests.codes.ok, 201]:
                        yield self._create_event("ERROR", f"{name} of type {obj_type} with URL {update_url} status code {res.status_code} reason {res.reason}, response '{res.text}', in app {app}, owner {owner}.")
                        self._append_to_results(actionResults, 'updateFailure', name)
                    else:
                        self.logger.debug(f"Post-update of {name} of type {obj_type} in app {app} with URL {update_url} result is: '{res.text}' owner of {owner}.")
                        self._append_to_results(actionResults, 'updateSuccess', name)

                    if sharing != "user":
                        acl_url = f"{update_url}/acl"
                        acl_payload = {"owner": owner, "sharing": sharing}
                        self.logger.info(f"App or Global sharing in use, attempting to change ownership of {obj_type} with name {name} via URL {acl_url} to owner {owner} in app {app} with sharing {sharing}.")
                        res = yield from self._make_request(
                            acl_url, method='post', auth_type=self.destAuthtype, username=self.destUsername,
                            password=self.destPassword, token=self.destToken, data=acl_payload, verify=False
                        )
                else:
                    self._append_to_results(actionResults, 'creationSkip', objURL)
                    yield self._create_event("INFO", f"{name} of type {obj_type} in app {app} owner of {owner}, object already exists and override is not set, nothing to do here.")

    def _get_local_name(self, full_name):
        if '}' in full_name:
            return full_name.split('}', 1)[1]
        return full_name

    def _macros(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities, excludeEntities, includeOwner,
               excludeOwner, privateOnly, override, overrideAlways, macroResults):
        """
        Handles macro specific migration logic.
        """
        yield self._create_event("DEBUG", f"Inside _macros: Starting processing for app {app}") # Forced initial yield
        yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Target app for this run is '{app}'") # DEBUG: Show target app

        macros_info = {}
        url = f"{self.srcURL}/servicesNS/-/{app}/configs/conf-macros?count=-1"
        self.logger.debug(f"Running requests.get() on {url} with username {self.srcUsername} in app {app} for type macro.")
        res = yield from self._make_request(
            url, method='get', auth_type=self.srcAuthtype, username=self.srcUsername,
            password=self.srcPassword, token=self.srcToken, verify=False
        )
        if res.status_code != requests.codes.ok:
            yield self._create_event("ERROR", f"Type macro in app {app}, URL {url} status code {res.status_code} reason {res.reason}, response '{res.text}'.")
            return

        root = ET.fromstring(res.text)

        for child in root:
            # For debugging, printing the Element object directly (keep if needed)
            try:
                with open("/tmp/test", "a") as f:
                    f.write(f"Processing child: {child}\n")
            except Exception as e:
                yield self._create_event("ERROR", f"Failed to write child to /tmp/test: {e}")

            if child.tag.endswith("entry"):
                macroInfo = {}
                # Initialize sharing and owner with default values
                macroInfo["sharing"] = "app" # Default to 'app' sharing if not found
                macroInfo["owner"] = "nobody" # Default owner if not found
                keep = True # Assume we want to keep it initially

                # Initialize found_acl_app for each new entry
                found_acl_app = None
                yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Initializing found_acl_app to {found_acl_app} for new entry.")

                # DEBUG: Log initial state for each entry
                yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Processing new entry. Initial keep={keep}. Target app: '{app}'")

                for innerChild in child:
                    if innerChild.tag.endswith("title"):
                        title = innerChild.text
                        macroInfo["name"] = title
                        self.logger.debug(f"Found macro title/name: {title} in app {app}.")

                        # --- Filtering based on title/regex ---
                        if includeEntities and title not in includeEntities:
                            keep = False
                            yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{title}' filtered by includeEntities. keep={keep}")
                        if excludeEntities and title in excludeEntities:
                            keep = False
                            yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{title}' filtered by excludeEntities. keep={keep}")
                        if self.name_filter_regex and not self.name_filter_regex.search(title):
                            keep = False
                            yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{title}' filtered by nameFilter regex. keep={keep}")

                        # If keep became False, skip to the next entry
                        if not keep:
                            yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo.get('name', 'UNKNOWN')}' skipped early due to title filter. Final keep={keep}")
                            break # Break from innerChild loop, will lead to 'continue' for main loop

                    elif innerChild.tag.endswith("updated"):
                        updatedStr = innerChild.text
                        macroInfo['updated'] = self._determine_time(updatedStr, macroInfo.get("name", "unknown"), app, "macro")

                    elif innerChild.tag.endswith("content"):
                        # In _macros, <content> often contains a single <s:dict> child
                        # This 'content_dict_element' will be the <s:dict> element itself
                        if len(innerChild) == 0: # Handle empty content tags
                            continue
                        content_dict_element = innerChild[0] # Assuming <content> has a single child which is <s:dict>

                        # Debugging for content_dict_element (keep if needed)
                        try:
                            with open("/tmp/test", "a") as f:
                                f.write(f"  Processing content dict: {content_dict_element.tag}\n")
                                f.write(f"  Attributes: {content_dict_element.attrib}\n")
                        except Exception as e:
                            yield self._create_event("ERROR", f"Failed to write content dict to /tmp/test: {e}")

                        # Iterate over the children of the <s:dict> element.
                        # These children are the individual <s:key> elements representing properties.
                        for property_element in content_dict_element:
                            # property_element will be an <s:key> element
                            # Debugging for property_element (keep if needed)
                            try:
                                with open("/tmp/test", "a") as f:
                                    f.write(f"    Processing property element: {property_element.tag}\n")
                                    f.write(f"    Attributes: {property_element.attrib}\n")
                                    f.write(f"    Text: {property_element.text}\n")
                            except Exception as e:
                                yield self._create_event("ERROR", f"Failed to write property element to /tmp/test: {e}")

                            # Get the property name from the 'name' attribute of the <s:key> element
                            property_name = self._get_local_name(property_element.attrib.get('name', ''))
                            property_value = property_element.text # Get the text content of the <s:key> element

                            # Handle special case for eai:acl, which is a nested dict
                            if property_name == 'eai:acl':
                                # The value of eai:acl is another <s:dict> element, not simple text
                                # So, property_element[0] is the nested <s:dict> element
                                if len(property_element) == 0: # Handle empty eai:acl tags
                                    continue
                                acl_dict_element = property_element[0]
                                if 'perms' not in macroInfo: # Initialize perms if not already
                                    macroInfo['perms'] = {}

                                # Iterate over children of this nested <s:dict> (these are also <s:key> elements)
                                for acl_prop_element in acl_dict_element:
                                    acl_prop_name = self._get_local_name(acl_prop_element.attrib.get('name', ''))
                                    acl_prop_value = acl_prop_element.text

                                    if acl_prop_name == 'sharing':
                                        macroInfo["sharing"] = acl_prop_value # Overwrite default
                                        # Existing sharing checks (keep these)
                                        if noPrivate and macroInfo["sharing"] == "user":
                                            keep = False
                                            yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo.get('name', 'UNKNOWN')}' filtered by noPrivate. keep={keep}")
                                            break
                                        elif privateOnly and macroInfo["sharing"] != "user":
                                            keep = False
                                            yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo.get('name', 'UNKNOWN')}' filtered by privateOnly. keep={keep}")
                                            break
                                        if self.sharingFilter and not self.sharingFilter == macroInfo["sharing"]:
                                            keep = False
                                            yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo.get('name', 'UNKNOWN')}' filtered by sharingFilter. keep={keep}")
                                            break
                                    elif acl_prop_name == 'app':
                                        found_acl_app = acl_prop_value # Store the found app from ACL
                                        yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo.get('name', 'UNKNOWN')}' - ACL 'app' attribute found: name='{acl_prop_name}', value='{acl_prop_value}', local_name='{acl_prop_name}', assigned_found_acl_app='{found_acl_app}'")
                                    elif acl_prop_name == 'owner':
                                        macroInfo["owner"] = acl_prop_value # Overwrite default
                                        owner = acl_prop_value
                                        # Existing owner checks (keep these)
                                        if includeOwner and owner not in includeOwner:
                                            keep = False
                                            yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo.get('name', 'UNKNOWN')}' filtered by includeOwner. keep={keep}")
                                            break
                                        if excludeOwner and owner in excludeOwner:
                                            keep = False
                                            yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo.get('name', 'UNKNOWN')}' filtered by excludeOwner. keep={keep}")
                                            break
                                    elif acl_prop_name == 'perms': # This is the <s:key name="perms">
                                        # It contains an <s:list> element as its child, which then has <s:item> children
                                        if len(acl_prop_element) > 0:
                                            perms_list_element = acl_prop_element[0] # This is the <s:list> element
                                            read_perms = []
                                            write_perms = []
                                            for perm_item in perms_list_element: # Iterate over <s:item> children
                                                perm_text = self._get_local_name(perm_item.text)
                                                if perm_text: # Ensure text is not None
                                                    if perm_text in ['read', 'write']: # Assuming simple 'read' or 'write' strings
                                                        if 'perms' not in macroInfo: macroInfo['perms'] = {}
                                                        if perm_text == 'read':
                                                            if 'read' not in macroInfo['perms']: macroInfo['perms']['read'] = []
                                                            macroInfo['perms']['read'].append(perm_text)
                                                        elif perm_text == 'write':
                                                            if 'write' not in macroInfo['perms']: macroInfo['perms']['write'] = []
                                                            macroInfo['perms']['write'].append(perm_text)
                                                    # If perms are roles, you might need to parse acl_prop_element.text.split(',')
                                            # The previous perms.read/write handling was specific to attributes.
                                            # This handles the nested <s:list><s:item> structure.
                                        # If needed, you can add more specific parsing for perms.read/perms.write if they are direct keys.
                                    # ... (rest of acl_prop_name handling) ...

                                # If keep became False inside ACL parsing, break from content_property_element loop
                                if not keep: break

                            # Handle other regular properties (not eai:acl)
                            else:
                                # Check for 'disabled' attribute on the property element itself
                                if property_name == "disabled" and noDisabled and property_value == "1":
                                    self.logger.debug(f"{macroInfo.get('name', 'UNKNOWN')} of type macro is disabled and the noDisabled flag is true, excluding this in app {app}")
                                    keep = False
                                    yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo.get('name', 'UNKNOWN')}' filtered by disabled status. keep={keep}")
                                    break

                                if property_value is not None:
                                    macroInfo[property_name] = property_value
                                elif property_element.attrib: # If it has attributes but no text
                                    macroInfo[property_name] = property_element.attrib

                        # If keep became False during content parsing, break from innerChild loop
                        if not keep: break

                # --- Final Filtering Check for this Entry ---
                # If 'keep' is already False from any of the above filters, skip this entry
                if not keep:
                    yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo.get('name', 'UNKNOWN')}' skipped by prior filter. Final keep={keep}")
                    continue # Skip to the next 'child' (next entry) in the main loop

                # --- CRITICAL APP FILTERING ---
                # This ensures found_acl_app is populated before the check
                if found_acl_app and app != found_acl_app:
                    # If the macro's reported app context is different from the target app for this run,
                    # then we should exclude it.
                    keep = False
                    yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo.get('name', 'UNKNOWN')}' (ACL app '{found_acl_app}') FILTERED OUT because it does not match target app '{app}'. Final keep={keep}")
                elif not found_acl_app:
                    # If eai:acl app was not found, it's a problem, default to skipping for safety.
                    keep = False
                    yield self._create_event("WARNING", f"MACRO_FILTER_DEBUG: No 'app' attribute found in eai:acl for macro '{macroInfo.get('name', 'UNKNOWN')}'. SKIPPING for safety. Final keep={keep}")

                # --- Final decision for this entry ---
                if not keep: # If keep is False after all checks for this entry
                    yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo.get('name', 'UNKNOWN')}' SKIPPED due to app/ACL filtering. Final keep={keep}")
                    continue # Skip to the next 'child' (next entry) in the main loop

                # If we reach here, 'keep' is True, proceed with processing the macro
                sharing = macroInfo["sharing"]
                if sharing not in macros_info:
                    macros_info[sharing] = []
                macros_info[sharing].append(macroInfo)
                yield self._create_event("INFO", f"Recording macro info for {macroInfo['name']} in app {app} with owner {macroInfo['owner']} sharing level of {macroInfo['sharing']}.")
                yield self._create_event("DEBUG", f"MACRO_FILTER_DEBUG: Macro '{macroInfo['name']}' SUCCESSFULLY ADDED to macros_info. Final keep={keep}")

        dest_app_name = destApp
        for sharing_level in ["global", "app", "user"]:
            if sharing_level in macros_info:
                yield self._create_event("INFO", f"Now running _macro_creation with knowledge objects of type macro with {sharing_level} level sharing in app {dest_app_name}.")
                yield from self._macro_creation(
                    macros_info[sharing_level], destOwner, dest_app_name, self.destURL,
                    macroResults, override, overrideAlways, self.enable_dry_run
                )
        # No return statement here.
    
    def _macro_creation(self, macros_list, destOwner, app, splunk_rest_dest, macroResults, override, overrideAlways, dry_run):
        """
        Runs the required queries to create the macro knowledge objects and then re-owns them to the correct user.
        """
        checked_users = set()

        for aMacro in macros_list:
            sharing = aMacro["sharing"]
            name = aMacro["name"]
            owner = aMacro["owner"]
            curUpdated = aMacro["updated"]
            del aMacro["updated"]

            if destOwner:
                owner = destOwner

            if owner not in checked_users and owner != 'nobody':
                dest_parts = urllib.parse.urlparse(splunk_rest_dest)
                dest_host = dest_parts.hostname
                dest_port = dest_parts.port if dest_parts.port else '8089'

                user_exists = yield from self._check_and_create_user(
                    dest_host, dest_port, self.destAuthtype,
                    self.destUsername, self.destPassword, self.destToken, owner
                )
                if not user_exists:
                    yield self._create_event("ERROR", f"Cannot create or verify user '{owner}' on destination system.")
                    self._append_to_results(macroResults, 'creationFailure', f"User creation failed for {name}")
                    continue
                checked_users.add(owner)

            url = f"{splunk_rest_dest}/servicesNS/{owner}/{app}/properties/macros"
            encoded_name = urllib.parse.quote(name.encode('utf-8'))
            encoded_name = encoded_name.replace("/", "%2F")
            objURL = f"{splunk_rest_dest}/servicesNS/-/{app}/configs/conf-macros/{encoded_name}?output_mode=json"
            
            objExists = False
            updated_remote = None
            try:
                res = yield from self._make_request(
                    objURL, method='get', auth_type=self.destAuthtype, username=self.destUsername,
                    password=self.destPassword, token=self.destToken, verify=False
                )
                if res.status_code == 404:
                    self.logger.debug(f"URL {objURL} is throwing a 404, assuming new object creation.")
                elif res.status_code != requests.codes.ok:
                    yield self._create_event("ERROR", f"URL {objURL} in app {app} status code {res.status_code} reason {res.reason}, response '{res.text}'.")
                else:
                    resDict = json.loads(res.text)
                    for entry in resDict['entry']:
                        sharingLevel = entry['acl']['sharing']
                        appContext = entry['acl']['app']
                        updatedStr = entry['updated']
                        updated_remote = self._determine_time(updatedStr, name, app, "macro")
                        remoteObjOwner = entry['acl']['owner']
                        if appContext == app and (sharing == 'app' or sharing == 'global') and (sharingLevel == 'app' or sharingLevel == 'global'):
                            objExists = True
                        elif appContext == app and sharing == 'user' and sharingLevel == "user" and remoteObjOwner == owner:
                            objExists = True
                        elif appContext == app and sharingLevel == "user" and remoteObjOwner == owner and (sharing == "app" or sharing == "global"):
                            objExists = True
                        if objExists:
                            self.logger.debug(f"name {name} of type macro in app context {app} found to exist on url {objURL} with sharing of {sharingLevel}, updated time of {updated_remote}.")
                            break
            except Exception as e:
                yield self._create_event("ERROR", f"Error checking existence of macro {name}: {e}")

            if objExists and not (override or overrideAlways):
                yield self._create_event("INFO", f"{name} of type macro in app {app} on URL {objURL} exists, however override/overrideAlways is not set so not changing this macro.")
                self._append_to_results(macroResults, 'creationSkip', objURL)
                continue
            elif objExists and override and updated_remote and not curUpdated > updated_remote:
                yield self._create_event("INFO", f"{name} of type macro in app {app} on URL {objURL} exists, override is set but the source copy has modification time of {curUpdated} destination has time of {updated_remote}, skipping.")
                self._append_to_results(macroResults, 'creationSkip', objURL)
                continue
            elif objExists and overrideAlways:
                yield self._create_event("INFO", f"{name} of type macro in app {app} on URL {objURL} exists, overrideAlways is set, will update this macro.")

            createOrUpdate = "create" if not objExists else "update"
            if objExists:
                macro_target_url = f"{url}/{encoded_name}"
            else:
                macro_target_url = url

            if dry_run:
                yield self._create_event("INFO", f"DRY RUN: Would {createOrUpdate} macro {name} on URL {macro_target_url}.")
                self._append_to_results(macroResults, 'creationSkip', name) # Treat as skipped in dry run
                continue

            yield self._create_event("INFO", f"Attempting to {createOrUpdate} macro {name} on URL {macro_target_url} in app {app}.")

            macroCreationSuccessRes = False
            if not objExists:
                payload = {"__stanza": name}
                res = yield from self._make_request(
                    macro_target_url, method='post', auth_type=self.destAuthtype,
                    username=self.destUsername, password=self.destPassword,
                    token=self.destToken, data=payload, verify=False
                )
                if res.status_code not in [requests.codes.ok, 201]:
                    yield self._create_event("ERROR", f"{name} of type macro in app {app} with URL {macro_target_url} status code {res.status_code} reason {res.reason}, response '{res.text}', owner {owner}.")
                    self._append_to_results(macroResults, 'creationFailure', name)
                else:
                    deletionURL = f"{splunk_rest_dest}/servicesNS/{owner}/{app}/configs/conf-macros/{name}"
                    self._append_to_results(macroResults, 'creationSuccess', deletionURL)
                    macroCreationSuccessRes = True
                self.logger.debug(f"{name} of type macro in app {app}, received response of: '{res.text}'.")

            # Modify macro properties
            payload_modify = aMacro.copy()
            del payload_modify["sharing"]
            del payload_modify["name"]
            del payload_modify["owner"]

            if createOrUpdate == "create":
                macro_target_url = f"{url}/{encoded_name}" # URL for modifying the newly created macro

            self.logger.debug(f"Attempting to modify macro {name} on URL {macro_target_url} with payload '{payload_modify}' in app {app}.")
            res = yield from self._make_request(
                macro_target_url, method='post', auth_type=self.destAuthtype, username=self.destUsername,
                password=self.destPassword, token=self.destToken, data=payload_modify, verify=False
            )
            if res.status_code not in [requests.codes.ok, 201]:
                yield self._create_event("ERROR", f"{name} of type macro in app {app} with URL {macro_target_url} status code {res.status_code} reason {res.reason}, response '{res.text}'.")
                if not objExists:
                    self._pop_last_result(macroResults, 'creationSuccess')
                    self._append_to_results(macroResults, 'creationFailure', name)
                else:
                    self._append_to_results(macroResults, 'updateFailure', name)
                macroCreationSuccessRes = False
            else:
                if not objExists: # If it was a new creation, re-own it
                    acl_url = f"{splunk_rest_dest}/servicesNS/{owner}/{app}/configs/conf-macros/{encoded_name}/acl"
                    acl_payload = {"owner": owner, "sharing": sharing}
                    self.logger.info(f"Attempting to change ownership of macro {name} via URL {acl_url} to owner {owner} in app {app} with sharing {sharing}.")
                    res = yield from self._make_request(
                        acl_url, method='post', auth_type=self.destAuthtype,
                        username=self.destUsername, password=self.destPassword,
                        token=self.destToken, data=acl_payload, verify=False
                    )
                    if res.status_code not in [requests.codes.ok, 200, 201]:
                        yield self._create_event("ERROR", f"{name} of type macro in app {app} with URL {acl_url} status code {res.status_code} reason {res.reason}, response '{res.text}', owner {owner} sharing level {sharing}.")
                        self._pop_last_result(macroResults, 'creationSuccess')
                        self._append_to_results(macroResults, 'creationFailure', name)
                        macroCreationSuccessRes = False
                    else:
                        macroCreationSuccessRes = True
                else: # If it was an update
                    macroCreationSuccessRes = True
                    self._append_to_results(macroResults, 'updateSuccess', name)

            if macroCreationSuccessRes:
                yield self._create_event("INFO", f"{createOrUpdate} {name} of type macro in app {app} owner is {owner} sharing level {sharing} was successful.")
            else:
                yield self._create_event("WARNING", f"{createOrUpdate} {name} of type macro in app {app} owner is {owner} sharing level {sharing} was not successful, a failure occurred.")

    # --- Knowledge Object Type Specific Migration Functions ---
    # These functions call the generic _run_queries or _macros with specific parameters.

    def _dashboards(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities, excludeEntities, includeOwner, excludeOwner, privateOnly, override, overrideAlways, actionResults):
        ignoreList = ["disabled", "eai:appName", "eai:digest", "eai:userName", "isDashboard", "isVisible", "label", "rootNode", "description", "version"]
        yield from self._run_queries(
            app, "/data/ui/views", "dashboard", ignoreList, destApp,
            destOwner=destOwner, noPrivate=noPrivate, noDisabled=noDisabled,
            includeEntities=includeEntities, excludeEntities=excludeEntities,
            includeOwner=includeOwner, excludeOwner=excludeOwner,
            privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _savedsearches(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                      excludeEntities, includeOwner, excludeOwner, privateOnly,
                      ignoreVSID, disableAlertsOrReportsOnMigration, override,
                      overrideAlways, actionResults):
        ignoreList = ["embed.enabled", "triggered_alert_count"]
        if ignoreVSID:
            ignoreList.append("vsid")
        yield from self._run_queries(
            app, "/saved/searches", "savedsearches", ignoreList, destApp,
            destOwner=destOwner, noPrivate=noPrivate, noDisabled=noDisabled,
            includeEntities=includeEntities, excludeEntities=excludeEntities,
            includeOwner=includeOwner, excludeOwner=excludeOwner,
            privateOnly=privateOnly,
            disableAlertsOrReportsOnMigration=disableAlertsOrReportsOnMigration,
            override=override, overrideAlways=overrideAlways,
            actionResults=actionResults
        )

    def _calcfields(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                   excludeEntities, includeOwner, excludeOwner, privateOnly,
                   override, overrideAlways, actionResults):
        ignoreList = ["attribute", "type"]
        aliasAttributes = {"field.name": "name"}
        yield from self._run_queries(
            app, "/data/props/calcfields", "calcfields", ignoreList, destApp,
            aliasAttributes, destOwner=destOwner, noPrivate=noPrivate,
            noDisabled=noDisabled, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _fieldaliases(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                     excludeEntities, includeOwner, excludeOwner, privateOnly,
                     override, overrideAlways, actionResults):
        ignoreList = ["attribute", "type", "value"]
        yield from self._run_queries(
            app, "/data/props/fieldaliases", "fieldaliases", ignoreList, destApp,
            nameOverride="name", destOwner=destOwner, noPrivate=noPrivate,
            noDisabled=noDisabled, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _fieldextractions(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                         excludeEntities, includeOwner, excludeOwner, privateOnly,
                         override, overrideAlways, actionResults):
        ignoreList = ["attribute"]
        yield from self._run_queries(
            app, "/data/props/extractions", "fieldextractions", ignoreList,
            destApp, {}, {"Inline": "EXTRACT", "Uses transform": "REPORT"},
            "attribute", destOwner=destOwner, noPrivate=noPrivate,
            noDisabled=noDisabled, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _fieldtransformations(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                             excludeEntities, includeOwner, excludeOwner, privateOnly,
                             override, overrideAlways, actionResults):
        ignoreList = [
            "attribute", "DEFAULT_VALUE", "DEPTH_LIMIT", "LOOKAHEAD", "MATCH_LIMIT",
            "WRITE_META", "eai:appName", "eai:userName", "DEST_KEY"
        ]
        yield from self._run_queries(
            app, "/data/transforms/extractions", "fieldtransformations",
            ignoreList, destApp, destOwner=destOwner, noPrivate=noPrivate,
            noDisabled=noDisabled, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _workflowactions(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                        excludeEntities, includeOwner, excludeOwner, privateOnly,
                        override, overrideAlways, actionResults):
        ignoreList = ["disabled", "eai:appName", "eai:userName"]
        yield from self._run_queries(
            app, "/data/ui/workflow-actions", "workflow-actions", ignoreList,
            destApp, destOwner=destOwner, noPrivate=noPrivate,
            noDisabled=noDisabled, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _sourcetyperenaming(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                           excludeEntities, includeOwner, excludeOwner, privateOnly,
                           override, overrideAlways, actionResults):
        ignoreList = ["attribute", "disabled", "eai:appName", "eai:userName", "stanza", "type"]
        yield from self._run_queries(
            app, "/data/props/sourcetype-rename", "sourcetype-rename", ignoreList,
            destApp, destOwner=destOwner, noPrivate=noPrivate,
            noDisabled=noDisabled, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _sourcetypes(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                    excludeEntities, includeOwner, excludeOwner, privateOnly,
                    override, overrideAlways, actionResults):
        ignoreList = ["disabled", "eai:appName", "eai:userName", "eai:type"]
        yield from self._run_queries(
            app, "/configs/conf-props", "sourcetypes", ignoreList,
            destApp, destOwner=destOwner, noPrivate=noPrivate,
            noDisabled=noDisabled, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _tags(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
             excludeEntities, includeOwner, excludeOwner, privateOnly, override,
             overrideAlways, actionResults):
        ignoreList = ["disabled", "eai:appName", "eai:userName"]
        yield from self._run_queries(
            app, "/configs/conf-tags", "tags", ignoreList, destApp,
            destOwner=destOwner, noPrivate=noPrivate, noDisabled=noDisabled,
            includeEntities=includeEntities, excludeEntities=excludeEntities,
            includeOwner=includeOwner, excludeOwner=excludeOwner,
            privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _eventtypes(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                   excludeEntities, includeOwner, excludeOwner, privateOnly,
                   override, overrideAlways, actionResults):
        ignoreList = ["disabled", "eai:appName", "eai:userName"]
        yield from self._run_queries(
            app, "/saved/eventtypes", "eventtypes", ignoreList, destApp,
            destOwner=destOwner, noPrivate=noPrivate, noDisabled=noDisabled,
            includeEntities=includeEntities, excludeEntities=excludeEntities,
            includeOwner=includeOwner, excludeOwner=excludeOwner,
            privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _navmenu(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                excludeEntities, includeOwner, excludeOwner, privateOnly, override,
                overrideAlways, actionResults):
        ignoreList = ["disabled", "eai:appName", "eai:userName", "eai:digest", "rootNode"]
        yield from self._run_queries(
            app, "/data/ui/nav", "navMenu", ignoreList, destApp,
            destOwner=destOwner, noPrivate=noPrivate, noDisabled=noDisabled,
            override=override, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _datamodels(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                   excludeEntities, includeOwner, excludeOwner, privateOnly, override,
                   overrideAlways, actionResults):
        ignoreList = [
            "disabled", "eai:appName", "eai:userName", "eai:digest", "eai:type",
            "acceleration.allowed"
        ]
        yield from self._run_queries(
            app, "/datamodel/model", "datamodels", ignoreList, destApp,
            destOwner=destOwner, noPrivate=noPrivate, noDisabled=noDisabled,
            includeEntities=includeEntities, excludeEntities=excludeEntities,
            includeOwner=includeOwner, excludeOwner=excludeOwner,
            privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _collections(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                    excludeEntities, includeOwner, excludeOwner, privateOnly, override,
                    overrideAlways, actionResults):
        ignoreList = ["eai:appName", "eai:userName", "type"]
        # nobody is the only username that can be used when working with collections
        yield from self._run_queries(
            app, "/storage/collections/config", "collections (kvstore definition)",
            ignoreList, destApp, destOwner="nobody", noPrivate=noPrivate,
            noDisabled=noDisabled, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _viewstates(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                   excludeEntities, includeOwner, excludeOwner, privateOnly, override,
                   overrideAlways, actionResults):
        ignoreList = ["eai:appName", "eai:userName"]
        yield from self._run_queries(
            app, "/configs/conf-viewstates", "viewstates", ignoreList, destApp,
            destOwner=destOwner, noPrivate=noPrivate, noDisabled=noDisabled,
            includeEntities=includeEntities, excludeEntities=excludeEntities,
            includeOwner=includeOwner, excludeOwner=excludeOwner,
            privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _times(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
              excludeEntities, includeOwner, excludeOwner, privateOnly, override,
              overrideAlways, actionResults):
        ignoreList = ["disabled", "eai:appName", "eai:userName", "header_label"]
        yield from self._run_queries(
            app, "/configs/conf-times", "times (conf-times)", ignoreList, destApp,
            destOwner=destOwner, noPrivate=noPrivate, noDisabled=noDisabled,
            includeEntities=includeEntities, excludeEntities=excludeEntities,
            includeOwner=includeOwner, excludeOwner=excludeOwner,
            privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _panels(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
               excludeEntities, includeOwner, excludeOwner, privateOnly, override,
               overrideAlways, actionResults):
        ignoreList = [
            "disabled", "eai:digest", "panel.title", "rootNode", "eai:appName",
            "eai:userName"
        ]
        yield from self._run_queries(
            app, "/data/ui/panels", "pre-built dashboard panels", ignoreList,
            destApp, destOwner=destOwner, noPrivate=noPrivate,
            noDisabled=noDisabled, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _lookupdefinitions(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                          excludeEntities, includeOwner, excludeOwner, privateOnly,
                          override, overrideAlways, actionResults):
        ignoreList = [
            "disabled", "eai:appName", "eai:userName", "CAN_OPTIMIZE", "CLEAN_KEYS",
            "DEPTH_LIMIT", "KEEP_EMPTY_VALS", "LOOKAHEAD", "MATCH_LIMIT", "MV_ADD",
            "SOURCE_KEY", "WRITE_META", "fields_array", "type"
        ]
        yield from self._run_queries(
            app, "/data/transforms/lookups", "lookup definition", ignoreList,
            destApp, destOwner=destOwner, noPrivate=noPrivate,
            noDisabled=noDisabled, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    def _automaticlookups(self, app, destApp, destOwner, noPrivate, noDisabled, includeEntities,
                         excludeEntities, includeOwner, excludeOwner, privateOnly,
                         override, overrideAlways, actionResults):
        ignoreList = ["attribute", "type", "value"]
        yield from self._run_queries(
            app, "/data/props/lookups", "automatic lookup", ignoreList, destApp,
            {}, {}, "attribute", destOwner=destOwner, noPrivate=noPrivate,
            noDisabled=noDisabled, includeEntities=includeEntities,
            excludeEntities=excludeEntities, includeOwner=includeOwner,
            excludeOwner=excludeOwner, privateOnly=privateOnly, override=override,
            overrideAlways=overrideAlways, actionResults=actionResults
        )

    # --- Logging Functions for Output ---
    def _log_deletion_script_in_logs(self, theDict, printPasswords, destUsername, destPassword):
        if not theDict or 'creationSuccess' not in theDict:
            return
        
        for item in theDict['creationSuccess']:
            # Escape parentheses for shell execution
            item_escaped = item.replace("(", "\\(").replace(")", "\\)")
            if printPasswords:
                yield self._create_event("INFO", f"curl -k -u {destUsername}:{destPassword} --request DELETE {item_escaped}", action="deletion_script")
            else:
                yield self._create_event("INFO", f"curl -k --request DELETE {item_escaped}", action="deletion_script")

    def _log_creation_failure(self, theDict, obj_type, app):
        if not theDict or 'creationFailure' not in theDict:
            return
        for item in theDict['creationFailure']:
            yield self._create_event("WARNING", f"In App {app}, {obj_type} '{item}' failed to create", type=obj_type, app=app, status="failed_creation")

    # ... (previous code of transferko.py) ...

    def _log_stats(self, resultsDict, obj_type, app):
        successList = resultsDict.get('creationSuccess', [])
        failureList = resultsDict.get('creationFailure', [])
        skippedList = resultsDict.get('creationSkip', [])
        updateSuccess = resultsDict.get('updateSuccess', [])
        updateFailure = resultsDict.get('updateFailure', [])

        if not resultsDict:
            return

        yield self._create_event(
            "INFO",
            f"App {app}, {len(successList)} {obj_type} successfully migrated, "
            f"{len(failureList)} {obj_type} failed to migrate, "
            f"{len(skippedList)} were skipped due to existing already, "
            f"{len(updateSuccess)} were updated, {len(updateFailure)} failed to update",
            app=app,
            object_type=obj_type,
            migrated_count=len(successList),
            failed_count=len(failureList),
            skipped_count=len(skippedList),
            updated_count=len(updateSuccess),
            update_failed_count=len(updateFailure)
        )

    def _handle_failure_logging(self, failureListDict, obj_type, app):
        if not failureListDict or 'creationFailure' not in failureListDict:
            return
        for item in failureListDict['creationFailure']:
            yield self._create_event("WARNING", f"In App {app}, {obj_type} '{item}' failed to create", type=obj_type, app=app, status="failed_creation", item_name=item)

    def _log_deletion(self, successListDict, printPasswords, destUsername, destPassword):
        # This method is effectively replaced by _log_deletion_script_in_logs which yields events.
        # Keeping it for completeness if original script calls it directly, but it should not be used.
        if not successListDict or 'creationSuccess' not in successListDict:
            return
        # The actual logging is done by _log_deletion_script_in_logs which is called in generate()
        # This function is just a placeholder to match the original script's structure.
        pass

    # Helper function as per https://stackoverflow.com/questions/31433989/return-copy-of-dictionary-excluding-specified-keys
    def _without_keys(self, d, keys):
        return {x: d[x] for x in d if x not in keys}

# This is the entry point for the Splunk search command
dispatch(TransferKOCommand, sys.argv, sys.stdin, sys.stdout, __name__)