#!/bin/bash

# Check if argument is provided
if [ $# -eq 0 ]; then
    echo "Error: Missing required argument"
    echo "Usage: $0 <identifier> [--no-header]"
    echo "Example: $0 production"
    echo "Example: $0 staging --no-header"
    exit 1
fi

# Store the first argument
IDENTIFIER="$1"

# Check for --no-header flag
INCLUDE_HEADER=true
if [ "$2" == "--no-header" ]; then
    INCLUDE_HEADER=false
fi

# 1. Fetch all instances and filter them into a temporary file
# Filters for Name containing 'jboss' or 'brdg' (case-insensitive)
echo "Fetching instance data..."
aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].{Name: Tags[?Key==`Name`].Value | [0], Type: InstanceType}' \
    --output json | \
    jq -c '.[] | .[] | select(.Name != null and (.Name | test("jboss|brdg"; "i")))' > instances.json

# 2. Get unique instance types from the list to optimize API calls
unique_types=$(jq -r '.Type' instances.json | sort -u)

# 3. Create a lookup file (vCPU mapping)
echo "type,vcpus" > cpu_map.csv
for type in $unique_types; do
    vcpu=$(aws ec2 describe-instance-types --instance-types "$type" --query 'InstanceTypes[0].VCpuInfo.DefaultVCpus' --output text)
    echo "$type,$vcpu" >> cpu_map.csv
done

# 4. Generate the final CSV by joining the data
# With header: truncate file and write header
# Without header: append to existing file
if [ "$INCLUDE_HEADER" = true ]; then
    echo "Identifier,Name,InstanceType,vCPUs" > ec2_report.csv
fi

# Always append data rows
while read -r line; do
    name=$(echo "$line" | jq -r '.Name')
    type=$(echo "$line" | jq -r '.Type')
    # Look up vCPU from our map
    vcpu=$(grep "^$type," cpu_map.csv | cut -d',' -f2)
    echo "$IDENTIFIER,$name,$type,$vcpu" >> ec2_report.csv
done < instances.json

# Cleanup
# rm instances.json cpu_map.csv

if [ "$INCLUDE_HEADER" = true ]; then
    echo "Report generated: ec2_report.csv with identifier: $IDENTIFIER (with header, file overwritten)"
else
    echo "Report appended: ec2_report.csv with identifier: $IDENTIFIER (no header, data appended)"
fi
