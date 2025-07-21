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
*   **Purpose:** This is a high-level informational dashboard that provides a centralized overview of all the custom migration commands included in the app. It describes each command's purpose and lists its key parameters, serving as a quick reference guide for users.

### Command-Specific Dashboards (Assumed)
*   The app is designed to be complemented by dedicated dashboards (not explicitly provided in this README but implied by the command structure) that offer interactive forms and controls for executing each specific migration command (`transferko`, `kvstoremigrator`, `rolemigrator`, `lookupmigrator`). These dashboards would allow users to input parameters and initiate migration tasks directly from the Splunk UI.

## Installation

1.  **Deploy the App:** Install the `Cloud Migrations` app to your Splunk instance(s) using standard Splunk app installation methods (e.g., via "Manage Apps" in Splunk Web, or by extracting the app package into `$SPLUNK_HOME/etc/apps/`).
2.  **Install Python Dependencies:** The custom commands rely on external Python libraries (`splunklib` and `requests`). These must be installed into the app's local library path:
    ```bash
    # Navigate to your Splunk app's bin directory (e.g., /opt/splunk/etc/apps/Cloud_Migrations/bin/)
    # Then install dependencies into the app's lib directory
    $SPLUNK_HOME/bin/splunk cmd python3 -m pip install --target=$SPLUNK_HOME/etc/apps/Cloud_Migrations/lib --upgrade splunklib requests
    ```
    *(Replace `$SPLUNK_HOME` with your actual Splunk installation path and `Cloud_Migrations` with your app's directory name if different.)*
3.  **Restart Splunk:** After installing the app and its dependencies, a full Splunk restart is required for the custom commands and dashboards to be recognized:
    ```bash
    $SPLUNK_HOME/bin/splunk restart
    ```

## Usage

*   **Via Dashboards:** Access the "Cloud Migrations" app from the Splunk home screen. Navigate to the "Migration Commands Overview" dashboard for information, and then to specific command dashboards to execute migration tasks.
*   **Via Search (SPL):** All commands can be executed directly from the Splunk Search bar using SPL. Refer to the `searchbnf.conf` files (located in the app's `default` directory) for detailed syntax and available options for each command. For example:
    ```splunk
    | transferko srcURL="..." destURL="..." srcApp="..." enable_all=true
    ```

## Support

For any issues or questions, please refer to the documentation or contact your Splunk administrator.
