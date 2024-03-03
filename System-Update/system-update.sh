#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run with sudo."
   echo "Please switch the user to the root." 
   exit 1
fi

command="/path/to/your/script/update_system.sh"

(crontab -l ; echo "0 0 * * * $SCRIPT_PATH") | crontab -

echo "Your system will be updated every day in 00:00 AM"