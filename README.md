# Cloud Migrations Splunk App

## Overview

The **Cloud Migrations** Splunk App is designed to streamline and simplify the process of migrating various Splunk configurations and data between different Splunk instances, particularly useful for transitioning to or managing cloud environments. This app provides a set of powerful custom search commands that allow for granular control over the transfer of critical Splunk knowledge objects, KVStore data, user roles, and lookup files.

## Included Migration Tools (Custom Commands)

The app introduces the following custom search commands, accessible via Splunk Search Processing Language (SPL) or through dedicated dashboards:

### `transferko` (Knowledge Object Migration)
*   **Purpose:** Facilitates the transfer of various Splunk knowledge objects from a source Splunk instance to a destination. This includes items like:
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
*   **Key Features:**
    *   Preserves object ownership and sharing permissions (ACLs).
    *   Supports selective migration of specific object types or all.
    *   Options for overriding existing objects on the destination based on modification time or unconditionally.
    *   Supports token-based or username/password authentication.

### `kvstoremigrator` (KVStore Migration)
*   **Purpose:** Enables the migration of KVStore collection data from local JSON backup files into a Splunk KVStore collection on a target instance.
*   **Key Features:**
    *   Processes JSON files organized by app and collection name.
    *   Supports token-based authentication for secure data transfer.
    *   Includes a dry run mode to simulate the migration process without making actual changes.

### `rolemigrator` (Role Migration)
*   **Purpose:** Automates the transfer of Splunk user roles, including their assigned capabilities and search quotas, from a source Splunk instance to a destination.
*   **Key Features:**
    *   Migrates all roles or a specified comma-separated list of roles.
    *   Handles creation of roles on the destination.
    *   Option to update role configurations if the role already exists on the destination.
    *   Automatically handles problematic capabilities during migration, allowing the transfer to proceed.

### `lookupmigrator` (Lookup Migration)
*   **Purpose:** Facilitates the transfer of Splunk lookup files (CSV format) between Splunk instances.
*   **Key Features:**
    *   Supports migrating all lookups from a specified source app or individual lookup files.
    *   Option to overwrite existing lookups on the destination.
    *   Preserves lookup permissions (ACLs) and ownership.
    *   Handles creation of dummy lookup files if needed before content upload.

## Dashboards

The Cloud Migrations app includes dashboards to provide a user-friendly interface for managing and executing these migration commands.

### Migration Commands Overview
*   **Purpose:** This dashboard serves as the central entry point and comprehensive guide to the app's capabilities. It provides a high-level overview of each custom migration command, detailing its specific function and listing the key parameters users need to provide. This dashboard acts as a quick reference, helping users understand what each tool does and how to effectively utilize it for various migration scenarios.

### Command-Specific Dashboards (Assumed)
*   The app is designed to be complemented by dedicated dashboards (not explicitly provided in this README but implied by the command structure) that offer interactive forms and controls for executing each specific migration command (`transferko`, `kvstoremigrator`, `rolemigrator`, `lookupmigrator`). These dashboards would allow users to input parameters and initiate migration tasks directly from the Splunk UI.

## Credits / Original Script Sources

This Splunk App leverages and adapts code from existing open-source projects. We extend our gratitude to the original authors for their contributions:

*   **Lookup Migration (`lookupmigrator`):** Adapted from [https://github.com/darrenfuller/splunk_rest_upload_lookups](https://github.com/darrenfuller/splunk_rest_upload_lookups)
*   **Knowledge Object Migration (`transferko`):** Adapted from [https://github.com/gjanders/Splunk/blob/master/bin/transfersplunkknowledgeobjects.py](https://github.com/gjanders/Splunk/blob/master/bin/transfersplunkknowledgeobjects.py)

## Support

For any issues or questions, please refer to the documentation or contact your Splunk administrator.
