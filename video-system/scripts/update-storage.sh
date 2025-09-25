#\!/bin/bash

# Update storage configuration file with provided values
# Usage: ./update-storage.sh total_disk_space used_disk_space reserved_value upload_limit_value reserved_value_flag

TOTAL_DISK=$1
USED_DISK=$2
RESERVED_VALUE=$3
UPLOAD_LIMIT=$4
RESERVED_FLAG=$5

CONFIG_FILE="/home/gus/video-system/docs/reserved_value.txt"

# Update each value in the file
sed -i "s/^total_disk_space = .*/total_disk_space = $TOTAL_DISK/" "$CONFIG_FILE"
sed -i "s/^used_disk_space = .*/used_disk_space = $USED_DISK/" "$CONFIG_FILE"
sed -i "s/^reserved_value = .*/reserved_value = $RESERVED_VALUE/" "$CONFIG_FILE"
sed -i "s/^upload_limit_value = .*/upload_limit_value = $UPLOAD_LIMIT/" "$CONFIG_FILE"
sed -i "s/^reserved_value_flag = .*/reserved_value_flag = $RESERVED_FLAG/" "$CONFIG_FILE"

echo "Storage config updated successfully"
