import requests
import xml.etree.ElementTree as ET
import argparse
import re
import logging
from getpass import getpass

# Configure logging
LOG_FILE = "/tmp/role-migration.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("%(message)s"))
logging.getLogger().addHandler(console_handler)

# Fields supported by the POST API
SUPPORTED_FIELDS = [
    "capabilities", "cumulativeRTSrchJobsQuota", "cumulativeSrchJobsQuota", "defaultApp",
    "imported_roles", "rtSrchJobsQuota", "srchDiskQuota", "srchFilter",
    "srchIndexesAllowed", "srchIndexesDefault", "srchJobsQuota", "srchTimeWin"
]

# Register XML namespaces for parsing responses
NAMESPACES = {
    "atom": "http://www.w3.org/2005/Atom",
    "s": "http://dev.splunk.com/ns/rest"
}


def parse_error_response(response_text):
    """Parse the Splunk error response to extract the problematic capability."""
    try:
        root = ET.fromstring(response_text)  # Parse the XML response
        # Find the error message in the <msg> element
        msg_element = root.find(".//msg")
        if msg_element is not None and "capability=" in msg_element.text:
            # Extract the problematic capability using regex
            match = re.search(r"capability=([\w_]+)", msg_element.text)
            if match:
                return match.group(1)  # Return the extracted capability
        return None
    except Exception as e:
        logging.error(f"Failed to parse error response: {e}")
        return None


def fetch_roles(source_host, source_token):
    """Fetch the list of roles from the Splunk Authorization API."""
    url = f"{source_host}/services/authorization/roles"

    try:
        logging.debug(f"Making GET request to {url}")
        headers = {"Authorization": f"Splunk {source_token}"}
        response = requests.get(
            url,
            headers=headers,
            verify=False  # Disable SSL verification for localhost
        )

        if response.status_code == 200:
            logging.info("successful: Fetched roles.")
            raw_xml = response.text  # Get the raw XML response
            return extract_titles(raw_xml)  # Extract and return <title> elements
        else:
            logging.error(f"failed: Could not fetch roles. Status Code: {response.status_code}, Response: {response.text}")
            return None
    except Exception as e:
        logging.error(f"failed: An error occurred while fetching roles: {e}")
        return None


def extract_titles(xml_data):
    """Extract and return all <title> elements from the XML response, skipping the first one."""
    try:
        # Parse the XML data
        root = ET.fromstring(xml_data)
        # Extract all <title> elements
        titles = root.findall(".//atom:title", NAMESPACES)
        # Skip the first <title> element (the overarching dict key)
        roles = [title.text for title in titles[1:]]  # Start from the second element
        logging.info("Found the following roles:")
        for role in roles:
            logging.info(f"- {role}")
        return roles
    except Exception as e:
        logging.error(f"failed: An error occurred while parsing XML: {e}")
        return []


def fetch_role_details(source_host, source_token, role):
    """Fetch details for a specific role from the Splunk Authorization API."""
    url = f"{source_host}/services/authorization/roles/{role}"

    try:
        logging.debug(f"Making GET request to {url}")
        headers = {"Authorization": f"Splunk {source_token}"}
        response = requests.get(
            url,
            headers=headers,
            verify=False  # Disable SSL verification for localhost
        )

        if response.status_code == 200:
            logging.info(f"successful: Fetched details for role: {role}")
            return response.text  # Return the raw XML response for the role
        else:
            logging.error(f"failed: Could not fetch details for role: {role}. Status Code: {response.status_code}, Response: {response.text}")
            return None
    except Exception as e:
        logging.error(f"failed: An error occurred while fetching details for role: {e}")
        return None


def extract_role_fields(xml_data):
    """Extract supported fields from the role details XML."""
    try:
        # Parse the XML data
        root = ET.fromstring(xml_data)
        content = root.find(".//atom:content", NAMESPACES)
        if content is None:
            logging.error("failed: No <content> element found in the role details.")
            return {}

        role_fields = {}
        logging.debug("Found <content> element. Inspecting <s:key> elements...")

        # Iterate over all <s:key> elements
        for key in content.findall(".//s:key", NAMESPACES):
            name = key.get("name")
            if name:
                logging.debug(f"Found <s:key> with name='{name}'")
                if name in SUPPORTED_FIELDS:
                    if key.find(".//s:list", NAMESPACES) is not None:
                        # If it's a list, extract all items
                        values = [item.text for item in key.findall(".//s:item", NAMESPACES)]
                        logging.debug(f"Extracted list for '{name}': {values}")
                        role_fields[name] = values
                    else:
                        # Otherwise, extract the text directly
                        value = key.text
                        logging.debug(f"Extracted value for '{name}': {value}")
                        role_fields[name] = value
                else:
                    logging.debug(f"Skipping unsupported field '{name}'")

        logging.info("\nExtracted the following role fields:")
        for field, value in role_fields.items():
            logging.info(f"- {field}: {value}")
        return role_fields
    except Exception as e:
        logging.error(f"failed: An error occurred while extracting role fields: {e}")
        return {}


def post_or_update_role(target_host, target_token, role, role_fields, update_if_exists, roles_migrated, roles_not_migrated):
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
            logging.debug(f"Making POST request to {url}")
            headers = {"Authorization": f"Splunk {target_token}"}
            response = requests.post(
                url,
                headers=headers,
                data=payload_with_name,  # Pass the payload with "name" for creation
                verify=False  # Disable SSL verification for localhost
            )

            if response.status_code == 201:
                logging.info(f"successful: Created role: {role}")
                success = True
                break  # Exit the loop on success
            elif "already exists" in response.text and update_if_exists:
                # If the role exists and updates are allowed, attempt an update
                logging.warning(f"Role '{role}' already exists. Preparing update request.")
                response = requests.post(
                    update_url,
                    headers=headers,
                    data=payload,  # Send the payload without "name" for updates
                    verify=False
                )
                if response.status_code == 200:
                    logging.info(f"successful: Updated role: {role}")
                    success = True
                    break  # Exit the loop on success
                elif response.status_code == 400:
                    # Handle problematic capabilities during update
                    problematic_capability = parse_error_response(response.text)
                    if problematic_capability:
                        logging.warning(f"Removing problematic capability: {problematic_capability}")
                        removed_capabilities.append(problematic_capability)
                        payload = [
                            (key, value)
                            for key, value in payload
                            if not (key == "capabilities" and value == problematic_capability)
                        ]
                    else:
                        logging.error("failed: Could not extract problematic capability from error message.")
                        break
                else:
                    logging.error(f"failed: Could not update role: {role}. Status Code: {response.status_code}, Response: {response.text}")
                    break
            elif response.status_code == 400:
                # Handle problematic capabilities during creation
                problematic_capability = parse_error_response(response.text)
                if problematic_capability:
                    logging.warning(f"Removing problematic capability: {problematic_capability}")
                    removed_capabilities.append(problematic_capability)
                    payload_with_name = [
                        (key, value)
                        for key, value in payload_with_name
                        if not (key == "capabilities" and value == problematic_capability)
                    ]
                else:
                    logging.error("failed: Could not extract problematic capability from error message.")
                    break
            else:
                logging.error(f"failed: Could not create or update role: {role}. Status Code: {response.status_code}, Response: {response.text}")
                break
        except Exception as e:
            logging.error(f"failed: An error occurred while posting or updating role: {e}")
            break

    if success:
        roles_migrated.append(role)
        logging.info(f"successful: Role '{role}' added to migrated list.")
    else:
        roles_not_migrated.append(role)
        logging.info(f"failed: Role '{role}' added to not migrated list.")

    if removed_capabilities:
        logging.warning(f"The following capabilities were removed during processing: {removed_capabilities}")


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Process Splunk roles.")
    parser.add_argument("--srcHost", required=True, help="Source Splunk host (e.g., https://localhost:8089).")
    parser.add_argument("--destHost", required=True, help="Target Splunk host (e.g., https://your-splunk-cloud.com:8089).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="Migrate all roles.")
    group.add_argument("--srcRole", type=str, help="Comma-separated list of roles to migrate.")
    parser.add_argument("--update-if-exists", action="store_true", help="Update the role if it already exists.")
    args = parser.parse_args()

    # Prompt for tokens
    source_token = getpass("Enter the source Splunk token: ").strip()
    destination_token = getpass("Enter the destination Splunk token: ").strip()

    roles_migrated = []
    roles_not_migrated = []

    if args.all:
        # Migrate all roles
        roles = fetch_roles(args.srcHost, source_token)
        if roles and len(roles) > 0:
            logging.info(f"Processing {len(roles)} roles...\n")
            for role in roles:
                if role == "splunk-system-role":
                    logging.info(f"Skipping system role: {role}")
                    continue

                logging.info(f"\nProcessing role: {role}")
                role_details_xml = fetch_role_details(args.srcHost, source_token, role)

                if role_details_xml:
                    role_fields = extract_role_fields(role_details_xml)
                    post_or_update_role(args.destHost, destination_token, role, role_fields, args.update_if_exists, roles_migrated, roles_not_migrated)
                else:
                    logging.error(f"failed: Could not fetch details for role: {role}")
                    roles_not_migrated.append(role)
        else:
            logging.error("failed: No roles found to process.")
    elif args.srcRole:
        # Migrate the specified roles (comma-separated list)
        roles = [role.strip() for role in args.srcRole.split(",") if role.strip()]
        logging.info(f"Processing {len(roles)} specified roles...\n")
        for role in roles:
            logging.info(f"\nProcessing role: {role}")
            role_details_xml = fetch_role_details(args.srcHost, source_token, role)

            if role_details_xml:
                role_fields = extract_role_fields(role_details_xml)
                post_or_update_role(args.destHost, destination_token, role, role_fields, args.update_if_exists, roles_migrated, roles_not_migrated)
            else:
                logging.error(f"failed: Could not fetch details for role: {role}")
                roles_not_migrated.append(role)

    # Summary of migrated and not migrated roles
    logging.info("\nRoles Migrated:")
    for role in roles_migrated:
        logging.info(f"- {role}")

    logging.info("\nRoles Not Migrated:")
    for role in roles_not_migrated:
        logging.info(f"- {role}")

    logging.info(f"\nMigration log saved to: {LOG_FILE}")