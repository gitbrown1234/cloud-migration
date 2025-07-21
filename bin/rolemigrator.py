import os, sys
import time
import json
import requests
import xml.etree.ElementTree as ET
import re
import logging
from requests.exceptions import ConnectionError, Timeout

# Add the lib directory to the sys.path for splunklib
# This assumes the script is placed in $SPLUNK_HOME/etc/apps/<your_app>/bin/
# and splunklib is in $SPLUNK_HOME/etc/apps/<your_app>/lib/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators


@Configuration()
class RoleMigratorCommand(GeneratingCommand):
    """
    The rolemigrator command migrates Splunk roles between instances via REST API.

    Example:
    ``| rolemigrator srcHost="https://localhost:8089" destHost="https://your-splunk-cloud.com:8089" source_token="YOUR_SRC_TOKEN" destination_token="YOUR_DEST_TOKEN" enable_all=true enable_update_if_exists=true``

    Or for specific roles:
    ``| rolemigrator srcHost="https://localhost:8089" destHost="https://your-splunk-cloud.com:8089" source_token="YOUR_SRC_TOKEN" destination_token="YOUR_DEST_TOKEN" roles_to_migrate="user_role1,user_role2"``
    """

    srcHost = Option(require=True)
    destHost = Option(require=True)
    source_token = Option(require=True)
    destination_token = Option(require=True)

    enable_all = Option(require=False, validate=validators.Boolean(), default=False)
    roles_to_migrate = Option(require=False) # Comma-separated list of roles
    enable_update_if_exists = Option(require=False, validate=validators.Boolean(), default=False)

    # Class attributes (equivalent to global constants in original script)
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
        It orchestrates the role migration process.
        """
        # Set logger level (optional, can be controlled by Splunk's logging config)
        self.logger.setLevel(logging.INFO) # Default to INFO, can be DEBUG if needed for detailed internal logs

        # Validate mutually exclusive options (enable_all vs roles_to_migrate)
        if self.enable_all and self.roles_to_migrate:
            yield self._create_event("ERROR", "Cannot specify both 'enable_all' and 'roles_to_migrate'. Choose one.")
            return
        if not self.enable_all and not self.roles_to_migrate:
            yield self._create_event("ERROR", "Must specify either 'enable_all=true' or 'roles_to_migrate' (comma-separated list).")
            return

        roles_migrated = []
        roles_not_migrated = []
        roles_to_process = []

        if self.enable_all:
            yield self._create_event("INFO", "Attempting to fetch all roles from source Splunk...")
            fetched_roles_generator = self._fetch_roles(self.srcHost, self.source_token)
            
            # Consume the generator and extract roles
            for event in fetched_roles_generator:
                if event.get("log_level") == "ROLES_FETCHED":
                    roles_to_process = event.get("message") # The list of roles
                yield event # Re-yield all events from _fetch_roles
            
            if not roles_to_process:
                yield self._create_event("ERROR", "No roles found to process from source.")
                return
            yield self._create_event("INFO", f"Processing {len(roles_to_process)} roles...")

        elif self.roles_to_migrate:
            roles_to_process = [role.strip() for role in self.roles_to_migrate.split(",") if role.strip()]
            if not roles_to_process:
                yield self._create_event("ERROR", "No valid roles specified in 'roles_to_migrate'.")
                return
            yield self._create_event("INFO", f"Processing {len(roles_to_process)} specified roles...")

        for role in roles_to_process:
            if role == "splunk-system-role":
                yield self._create_event("INFO", f"Skipping system role: {role}")
                roles_not_migrated.append(role)
                continue

            yield self._create_event("INFO", f"\nProcessing role: {role}")
            role_details_xml = None
            
            # Fetch role details
            fetch_details_generator = self._fetch_role_details(self.srcHost, self.source_token, role)
            for event in fetch_details_generator:
                if event.get("log_level") == "ROLE_DETAILS_FETCHED":
                    role_details_xml = event.get("message")
                yield event # Re-yield all events from _fetch_role_details

            if role_details_xml:
                role_fields = {}
                # Extract role fields
                extract_fields_generator = self._extract_role_fields(role_details_xml)
                for event in extract_fields_generator:
                    if event.get("log_level") == "ROLE_FIELDS_EXTRACTED":
                        role_fields = event.get("message")
                    yield event # Re-yield all events from _extract_role_fields

                # Post or update role
                post_update_generator = self._post_or_update_role(
                    self.destHost, self.destination_token, role, role_fields, self.enable_update_if_exists
                )
                for event in post_update_generator:
                    if event.get("log_level") == "ROLE_MIGRATION_RESULT":
                        if event.get("status") == "success":
                            roles_migrated.append(role)
                        else:
                            roles_not_migrated.append(role)
                    yield event # Re-yield all events from _post_or_update_role
            else:
                yield self._create_event("ERROR", f"failed: Could not fetch details for role: {role}")
                roles_not_migrated.append(role)

        # Summary of migrated and not migrated roles
        yield self._create_event("INFO", "\n--- Migration Summary ---")
        yield self._create_event("INFO", "Roles Migrated:")
        for role in roles_migrated:
            yield self._create_event("INFO", f"- {role}", role_name=role, migration_status="migrated")

        yield self._create_event("INFO", "\nRoles Not Migrated:")
        for role in roles_not_migrated:
            yield self._create_event("INFO", f"- {role}", role_name=role, migration_status="not_migrated")

        yield self._create_event("INFO", "\nRole migration process completed.")

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

    def _parse_error_response(self, response_text):
        """Parse the Splunk error response to extract the problematic capability."""
        try:
            root = ET.fromstring(response_text)  # Parse the XML response
            # Find the error message in the <msg> element
            msg_element = root.find(".//msg")
            if msg_element is not None and msg_element.text and "capability=" in msg_element.text:
                # Extract the problematic capability using regex
                match = re.search(r"capability=([\w_]+)", msg_element.text)
                if match:
                    return match.group(1)  # Return the extracted capability
            return None
        except Exception as e:
            yield self._create_event("ERROR", f"Failed to parse error response: {e}", error_details=str(e))
            return None

    def _fetch_roles(self, source_host, source_token):
        """Fetch the list of roles from the Splunk Authorization API."""
        url = f"{source_host}/services/authorization/roles"

        try:
            self.logger.debug(f"Making GET request to {url}")
            headers = {"Authorization": f"Splunk {source_token}"}
            response = requests.get(
                url,
                headers=headers,
                verify=False  # Disable SSL verification for localhost
            )

            if response.status_code == 200:
                yield self._create_event("INFO", "successful: Fetched roles.", url=url, status_code=response.status_code)
                raw_xml = response.text  # Get the raw XML response
                
                # Extract and yield titles
                extracted_roles = []
                for event in self._extract_titles(raw_xml):
                    if event.get("log_level") == "ROLES_EXTRACTED":
                        extracted_roles = event.get("message")
                    yield event # Re-yield events from _extract_titles
                
                yield self._create_event("ROLES_FETCHED", extracted_roles, url=url, status="success")
                return # End generator
            else:
                yield self._create_event("ERROR", f"failed: Could not fetch roles. Status Code: {response.status_code}, Response: {response.text}",
                                         url=url, status_code=response.status_code, response_text=response.text)
                yield self._create_event("ROLES_FETCHED", [], url=url, status="failed")
                return # End generator
        except Exception as e:
            yield self._create_event("ERROR", f"failed: An error occurred while fetching roles: {e}", error_details=str(e), url=url)
            yield self._create_event("ROLES_FETCHED", [], url=url, status="exception")
            return # End generator

    def _extract_titles(self, xml_data):
        """Extract and return all <title> elements from the XML response, skipping the first one."""
        try:
            # Parse the XML data
            root = ET.fromstring(xml_data)
            # Extract all <title> elements
            titles = root.findall(".//atom:title", self.NAMESPACES)
            
            roles = []
            if len(titles) > 1: # Skip the first <title> element (the overarching dict key)
                roles = [title.text for title in titles[1:] if title.text is not None]
            
            yield self._create_event("INFO", "Found the following roles:")
            for role in roles:
                yield self._create_event("INFO", f"- {role}", role_name=role)
            
            yield self._create_event("ROLES_EXTRACTED", roles, status="success")
            return # End generator
        except Exception as e:
            yield self._create_event("ERROR", f"failed: An error occurred while parsing XML: {e}", error_details=str(e))
            yield self._create_event("ROLES_EXTRACTED", [], status="exception")
            return # End generator

    def _fetch_role_details(self, source_host, source_token, role):
        """Fetch details for a specific role from the Splunk Authorization API."""
        url = f"{source_host}/services/authorization/roles/{role}"

        try:
            self.logger.debug(f"Making GET request to {url}")
            headers = {"Authorization": f"Splunk {source_token}"}
            response = requests.get(
                url,
                headers=headers,
                verify=False  # Disable SSL verification for localhost
            )

            if response.status_code == 200:
                yield self._create_event("INFO", f"successful: Fetched details for role: {role}", role_name=role, url=url, status_code=response.status_code)
                yield self._create_event("ROLE_DETAILS_FETCHED", response.text, role_name=role, status="success")
                return # End generator
            else:
                yield self._create_event("ERROR", f"failed: Could not fetch details for role: {role}. Status Code: {response.status_code}, Response: {response.text}",
                                         role_name=role, url=url, status_code=response.status_code, response_text=response.text)
                yield self._create_event("ROLE_DETAILS_FETCHED", None, role_name=role, status="failed")
                return # End generator
        except Exception as e:
            yield self._create_event("ERROR", f"failed: An error occurred while fetching details for role: {e}", error_details=str(e), role_name=role, url=url)
            yield self._create_event("ROLE_DETAILS_FETCHED", None, role_name=role, status="exception")
            return # End generator

    def _extract_role_fields(self, xml_data):
        """Extract supported fields from the role details XML."""
        role_fields = {}
        try:
            # Parse the XML data
            root = ET.fromstring(xml_data)
            content = root.find(".//atom:content", self.NAMESPACES)
            if content is None:
                yield self._create_event("ERROR", "failed: No <content> element found in the role details.", xml_data=xml_data)
                yield self._create_event("ROLE_FIELDS_EXTRACTED", {}, status="failed")
                return # End generator

            self.logger.debug("Found <content> element. Inspecting <s:key> elements...")

            # Iterate over all <s:key> elements
            for key in content.findall(".//s:key", self.NAMESPACES):
                name = key.get("name")
                if name:
                    self.logger.debug(f"Found <s:key> with name='{name}'")
                    if name in self.SUPPORTED_FIELDS:
                        if key.find(".//s:list", self.NAMESPACES) is not None:
                            # If it's a list, extract all items
                            values = [item.text for item in key.findall(".//s:item", self.NAMESPACES) if item.text is not None]
                            self.logger.debug(f"Extracted list for '{name}': {values}")
                            role_fields[name] = values
                        else:
                            # Otherwise, extract the text directly
                            value = key.text
                            self.logger.debug(f"Extracted value for '{name}': {value}")
                            role_fields[name] = value
                    else:
                        self.logger.debug(f"Skipping unsupported field '{name}'")

            yield self._create_event("INFO", "Extracted the following role fields:")
            for field, value in role_fields.items():
                yield self._create_event("INFO", f"- {field}: {value}", field_name=field, field_value=value)
            
            yield self._create_event("ROLE_FIELDS_EXTRACTED", role_fields, status="success")
            return # End generator
        except Exception as e:
            yield self._create_event("ERROR", f"failed: An error occurred while extracting role fields: {e}", error_details=str(e), xml_data=xml_data)
            yield self._create_event("ROLE_FIELDS_EXTRACTED", {}, status="exception")
            return # End generator

    def _post_or_update_role(self, target_host, target_token, role, role_fields, enable_update_if_exists):
        """Post or update role details to the target Splunk API."""
        url = f"{target_host}/services/authorization/roles"
        update_url = f"{target_host}/services/authorization/roles/{role}"

        # Prepare the payload
        payload = []
        for field, value in role_fields.items():
            if isinstance(value, list):
                for item in value:
                    payload.append((field, item))
            else:
                payload.append((field, value))

        # Add the role name for creation
        payload_with_name = payload + [("name", role)]  # Include "name" for creation only

        removed_capabilities = []  # Keep track of removed capabilities
        success = False  # Track if the role was successfully created or updated

        while True:
            try:
                # Attempt to create the role
                self.logger.debug(f"Making POST request to {url}")
                headers = {"Authorization": f"Splunk {target_token}"}
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload_with_name,  # Pass the payload with "name" for creation
                    verify=False  # Disable SSL verification for localhost
                )

                if response.status_code == 201:
                    yield self._create_event("INFO", f"successful: Created role: {role}", role_name=role, status_code=response.status_code)
                    success = True
                    break  # Exit the loop on success
                elif "already exists" in response.text and enable_update_if_exists:
                    # If the role exists and updates are allowed, attempt an update
                    yield self._create_event("WARNING", f"Role '{role}' already exists. Preparing update request.", role_name=role)
                    response = requests.post(
                        update_url,
                        headers=headers,
                        data=payload,  # Send the payload without "name" for updates
                        verify=False
                    )
                    if response.status_code == 200:
                        yield self._create_event("INFO", f"successful: Updated role: {role}", role_name=role, status_code=response.status_code)
                        success = True
                        break  # Exit the loop on success
                    elif response.status_code == 400:
                        # Handle problematic capabilities during update
                        problematic_capability = None
                        for event in self._parse_error_response(response.text):
                            if event.get("log_level") == "PROBLEM_CAPABILITY_EXTRACTED":
                                problematic_capability = event.get("message")
                            yield event # Re-yield events from _parse_error_response
                        
                        if problematic_capability:
                            yield self._create_event("WARNING", f"Removing problematic capability: {problematic_capability}", role_name=role, capability=problematic_capability)
                            removed_capabilities.append(problematic_capability)
                            payload = [
                                (key, value)
                                for key, value in payload
                                if not (key == "capabilities" and value == problematic_capability)
                            ]
                        else:
                            yield self._create_event("ERROR", "failed: Could not extract problematic capability from error message.", role_name=role, response_text=response.text)
                            break
                    else:
                        yield self._create_event("ERROR", f"failed: Could not update role: {role}. Status Code: {response.status_code}, Response: {response.text}",
                                                 role_name=role, status_code=response.status_code, response_text=response.text)
                        break
                elif response.status_code == 400:
                    # Handle problematic capabilities during creation
                    problematic_capability = None
                    for event in self._parse_error_response(response.text):
                        if event.get("log_level") == "PROBLEM_CAPABILITY_EXTRACTED":
                            problematic_capability = event.get("message")
                        yield event # Re-yield events from _parse_error_response
                    
                    if problematic_capability:
                        yield self._create_event("WARNING", f"Removing problematic capability: {problematic_capability}", role_name=role, capability=problematic_capability)
                        removed_capabilities.append(problematic_capability)
                        payload_with_name = [
                            (key, value)
                            for key, value in payload_with_name
                            if not (key == "capabilities" and value == problematic_capability)
                        ]
                    else:
                        yield self._create_event("ERROR", "failed: Could not extract problematic capability from error message.", role_name=role, response_text=response.text)
                        break
                else:
                    yield self._create_event("ERROR", f"failed: Could not create or update role: {role}. Status Code: {response.status_code}, Response: {response.text}",
                                             role_name=role, status_code=response.status_code, response_text=response.text)
                    break
            except Exception as e:
                yield self._create_event("ERROR", f"failed: An error occurred while posting or updating role: {e}", error_details=str(e), role_name=role)
                break

        if success:
            yield self._create_event("INFO", f"successful: Role '{role}' added to migrated list.", role_name=role, migration_result="success")
            yield self._create_event("ROLE_MIGRATION_RESULT", True, role_name=role, status="success", removed_capabilities=removed_capabilities)
        else:
            yield self._create_event("ERROR", f"failed: Role '{role}' added to not migrated list.", role_name=role, migration_result="failed")
            yield self._create_event("ROLE_MIGRATION_RESULT", False, role_name=role, status="failed", removed_capabilities=removed_capabilities)

        if removed_capabilities:
            yield self._create_event("WARNING", f"The following capabilities were removed during processing: {removed_capabilities}", role_name=role, removed_capabilities_list=removed_capabilities)

# This is the entry point for the Splunk search command
dispatch(RoleMigratorCommand, sys.argv, sys.stdin, sys.stdout, __name__)