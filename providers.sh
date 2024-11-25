#!/bin/bash

# Define the URL of the JSON-Datei
json_url="https://api.pidmr.devel.argo.grnet.gr/v1/providers?size=100"

# Define the storing directory
providers_folder="/hs/svr_1/providers/"

# Check if the providers directory exists, if not make it
if [ ! -d "$providers_folder" ]; then
    mkdir -p "$providers_folder"
fi

# Check if the providers file already exists
if [ -f "${providers_folder}providers.json" ]; then
    curl -o "${providers_folder}fresh_providers.json" "$json_url"
    if cmp -s "providers/providers.json" "providers/fresh_providers.json"; then
        rm -r "${providers_folder}fresh_providers.json"
        echo "The files are identical."
    else
        if [ -f "${providers_folder}providers_backup.json" ]; then
          rm -r "${providers_folder}providers_backup.json"
        fi
        cp "${providers_folder}providers.json" "${providers_folder}providers_backup.json"
        rm -r "${providers_folder}providers.json"
        mv "${providers_folder}fresh_providers.json" "${providers_folder}providers.json"
        echo "The file are updated."
    fi
else
    if [ -f "${providers_folder}providers_backup.json" ]; then
      rm -r "${providers_folder}providers_backup.json"
    fi
    # Download the providers json file and store it in providers directory"
    curl -o "${providers_folder}providers.json" "$json_url"
    echo "The file is downloaded and successfully stored."
fi
