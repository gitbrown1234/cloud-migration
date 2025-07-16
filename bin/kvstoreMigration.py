import os
import json
import requests

def log_message(message, log_file="/tmp/kvstore.log"):
    """Log a message to both the screen and a file."""
    print(message)  # Print to screen
    with open(log_file, "a") as file:  # Append to the log file
        file.write(message + "\n")


def post_json_data(json_file, splunk_host, auth_token, app_name, collection_name, log_file="/tmp/kvstore.log"):
    """Function to read a JSON file and post its data to Splunk."""
    endpoint = f'/servicesNS/nobody/{app_name}/storage/collections/data/{collection_name}'
    url = splunk_host + endpoint

    with open(json_file, 'r') as file:
        data_list = json.load(file)  # Load JSON data

    # Iterate over JSON entries
    for entry in data_list:
        payload = json.dumps(entry)  # Convert to JSON string
        log_message(f"DEBUG: Sending payload to {url}: {payload}", log_file)  # Log the payload for debugging

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Splunk {auth_token}'  # Add token-based authorization
        }

        response = requests.post(
            url,
            headers=headers,  # Pass the headers, including the token
            data=payload,  # Send the JSON string as the payload
            verify=False  # Disables SSL verification (equivalent to `-k` in curl)
        )

        # Handle the response
        if response.status_code == 201:
            log_message(f"Success: {payload}", log_file)
        else:
            log_message(f"Failed for {payload} - Status {response.status_code}: {response.text}", log_file)


def process_directory(base_path, splunk_host, auth_token, log_file="/tmp/kvstore.log"):
    """Recursively process directories and JSON files."""
    # List only directories in the base path
    directories = [d for d in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, d))]
    
    for directory in directories:
        dir_path = os.path.join(base_path, directory)
        log_message(f"\nFound app directory: {directory}", log_file)
        proceed = input(f"Do you want to migrate the KV store from this app ({directory})? (yes/no): ").strip().lower()

        if proceed in ['yes', 'y']:
            app_name = directory  # Use the directory name as the app name

            # Process subdirectories inside this directory
            subdirectories = [d for d in os.listdir(dir_path) if os.path.isdir(os.path.join(dir_path, d))]
            for subdirectory in subdirectories:
                sub_dir_path = os.path.join(dir_path, subdirectory)
                log_message(f"\nFound KV store subdirectory: {subdirectory}", log_file)
                sub_proceed = input(f"Do you want to migrate the {subdirectory} KV store? (yes/no): ").strip().lower()

                if sub_proceed in ['yes', 'y']:
                    collection_name = subdirectory  # Use the subdirectory name as the collection name

                    # Find all JSON files in this subdirectory
                    json_files = [f for f in os.listdir(sub_dir_path) if f.endswith('.json')]
                    for json_file in json_files:
                        json_file_path = os.path.join(sub_dir_path, json_file)
                        log_message(f"\nProcessing JSON file: {json_file}", log_file)

                        # Post the JSON file data
                        post_json_data(json_file_path, splunk_host, auth_token, app_name, collection_name, log_file)

                else:
                    log_message(f"Skipping KV store: {subdirectory}", log_file)
        else:
            log_message(f"Skipping app: {directory}", log_file)


if __name__ == "__main__":
    # Prompt user for Splunk URL and Auth Token
    splunk_host = input("Enter the Splunk URL (e.g., https://your-splunk-host:8089): ").strip()
    auth_token = input("Enter the Splunk Authorization Token: ").strip()

    # Prompt user for the base path
    base_path = input("Enter the base path to start processing directories (e.g., /opt/splunk/var/lib/splunk/kvstorebackup/test1/): ").strip()
    
    if os.path.exists(base_path) and os.path.isdir(base_path):
        # Clear the log file before starting (optional)
        with open("/tmp/kvstore.log", "w") as file:
            file.write("Starting KV store migration log...\n")

        # Start processing from the base path
        process_directory(base_path, splunk_host, auth_token)
    else:
        log_message("Invalid path. Please make sure the path exists and is a directory.")
