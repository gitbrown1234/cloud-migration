# Cloud Migrations Splunk App

## Overview

The **Cloud Migrations** Splunk App is designed to streamline and simplify the process of migrating various Splunk configurations and data between different Splunk instances, particularly useful for transitioning to or managing cloud environments. This app provides a set of powerful custom search commands that allow for granular control over the transfer of critical Splunk knowledge objects, KVStore data, user roles, and lookup files.

## Included Migration Tools (Custom Commands)

The Cloud Migrations app provides a suite of powerful tools, each implemented as a custom Splunk search command. While these commands can be executed directly via SPL, each tool is primarily designed to be used through its dedicated dashboard, which serves as the main interface for users to manage and execute migration tasks.

### `transferko` (Knowledge Object Migration)
*   **Purpose:** This tool facilitates the transfer of various Splunk knowledge objects from a source Splunk instance to a destination. This includes items like:
    *   Macros
    *   Dashboards (Views)
    *   Saved Searches (including Reports and Alerts)
    *   Event Types
    *   Data Models
    *   Field Extractions, Aliases, Transformations, Calculated Fields
    *   Workflow Actions
    *   Sourcetype Renaming and Definitions
    *   Tags
    *   Navigation Menus
    *   Pre-built Dashboard Panels
    *   Viewstates
*   **Dashboard Integration:** The `transferko` command is integrated into a dedicated dashboard, providing an intuitive interface to specify source/destination details, select object types, and manage override options. This dashboard is the primary spot for users to interact with the script.
*   **Key Features:**
    *   Preserves object ownership and sharing permissions (ACLs).
    *   Supports selective migration of specific object types or all.
    *   Options for overriding existing objects on the destination based on modification time or unconditionally.
    *   Supports token-based or username/password authentication.

### `kvstoremigrator` (KVStore Migration)
*   **Purpose:** This tool is designed to migrate KVStore collection data from local JSON backup files into a Splunk KVStore collection on a target instance.
*   **Dashboard Integration:** The `kvstoremigrator` command is accessible via its dedicated dashboard, allowing users to define Splunk host, token, file path, and dry run options for KVStore data transfer. This dashboard is the primary spot for users to interact with the script.
*   **Key Features:**
    *   Processes JSON files organized by app and collection name.
    *   Supports token-based authentication for secure data transfer.
    *   Includes a dry run mode to simulate the migration process without making actual changes.

### `rolemigrator` (Role Migration)
*   **Purpose:** This tool automates the transfer of Splunk user roles, including their assigned capabilities and search quotas, from a source Splunk instance to a destination.
*   **Dashboard Integration:** The `rolemigrator` command is used through its dedicated dashboard, which provides an interactive interface for specifying source/destination details, selecting roles, and managing update options. This dashboard is the primary spot for users to interact with the script.
*   **Key Features:**
    *   Migrates all roles or a specified comma-separated list of roles.
    *   Handles creation of roles on the destination.
    *   Option to update role configurations if the role already exists on the destination.
    *   Automatically handles problematic capabilities during migration, allowing the transfer to proceed.

### `lookupmigrator` (Lookup Migration)
*   **Purpose:** This tool facilitates the transfer of Splunk lookup files (CSV format) between Splunk instances.
*   **Dashboard Integration:** The `lookupmigrator` command is primarily managed via its dedicated dashboard, enabling users to define source/destination details, specify lookup names, and manage overwrite options. This dashboard is the primary spot for users to interact with the script.
*   **Key Features:**
    *   Supports migrating all lookups from a specified source app or individual lookup files.
    *   Option to overwrite existing lookups on the destination.
    *   Preserves lookup permissions (ACLs) and ownership.
    *   Handles creation of dummy lookup files if needed before content upload.

## Credits / Original Script Sources

This Splunk App leverages and adapts code from existing open-source projects. We extend our gratitude to the original authors for their contributions:

*   **Lookup Migration (`lookupmigrator`):** Adapted from [https://github.com/darrenfuller/splunk_rest_upload_lookups](https://github.com/darrenfuller/splunk_rest_upload_lookups)
*   **Knowledge Object Migration (`transferko`):** Adapted from [https://github.com/gjanders/Splunk/blob/master/bin/transfersplunkknowledgeobjects.py](https://github.com/gjanders/Splunk/blob/master/bin/transfersplunkknowledgeobjects.py)

## Support

For any issues or questions, please refer to the documentation or contact your Splunk administrator.
