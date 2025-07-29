#!/bin/bash
# Delete instances along with associated volumes and snapshots
# Requires bash. Parsing text to array will not work in zsh
# Be careful what you delete!

delete_amis() {
  local instance_id="$1"
  local ami_ids=$(aws ec2 describe-images --filters "Name=description,Values=*$instance_id*" --query 'Images[*].ImageId' --output text)

  if [ -z "$ami_ids" ]; then
      echo "No AMIs found for instance: $instance_id"
      return
  fi
  
  echo "Found AMI IDs: $ami_ids"
  
  for ami_id in $ami_ids; do
    delete_ami "$ami_id"
  done
}

delete_ami() {
    local ami_id="$1"
    echo "Deregistering: $ami_id"
    aws ec2 deregister-image --image-id "$ami_id"
    local snapshot_ids=$(aws ec2 describe-images --image-ids "$ami_id" --query 'Images[].BlockDeviceMappings[].Ebs.SnapshotId' --output text)
    if [ -z "$snapshot_ids" ]; then
        echo "No snapshots found for AMI: $ami_id"
    else
      echo "Deleting snapshots: $snapshot_ids"
      delete_snapshots "$snapshot_ids"
    fi
}

delete_snapshot() {
    local snapshot_id="$1"
    echo "Deleting: $snapshot_id"
    aws ec2 delete-snapshot --snapshot-id "$snapshot_id"
}

delete_volume() {
    local volume_id="$1"
    echo "Deleting: $volume_id"
    local snapshot_output=$(aws ec2 describe-snapshots --filters "Name=volume-id,Values=$volume_id" --query 'Snapshots[*].SnapshotId' --output text)
    echo "  snapshots: '$snapshot_output'"
    local snapshots=($snapshot_output)
    for id in "${snapshots[@]}"; do
        delete_snapshot "$id"
    done
    local output=$(aws ec2 delete-volume --volume-id "$volume_id" 2>&1)
    if [[ $? -ne 0 ]]; then
        if [[ "$output" == *"InvalidVolume.NotFound"* ]]; then
            echo "Volume already deleted: $volume_id"
        else
            echo "$output" >&2
        fi
    else
        echo "Volume deleted: $volume_id"
    fi
}

terminate_instance() {
    local instance_id=("$1")    
    local volume_output=$(aws ec2 describe-volumes --filters "Name=attachment.instance-id,Values=$instance_id" --query 'Volumes[*].VolumeId' --output text)
    echo "  volumes: '$volume_output'"

    local output=$(aws ec2 terminate-instances --instance-ids "$instance_id" 2>&1)
    echo "$output"
    if [[ $? -ne 0 ]]; then
        if [[ "$output" == *"InvalidInstanceID.NotFound"* ]]; then
            echo "Instance not found: $instance_id"
            return 0
        else
            echo "$output"
            return 1
        fi
    else
        echo "Waiting for instance $instance_id to be terminated..."
        aws ec2 wait instance-terminated --instance-ids "$instance_id"
        echo "Terminated $instance_id"
    fi

    local volumes=($volume_output)
    for id in "${volumes[@]}"; do
        delete_volume "$id";
    done
}


terminate_instances() {
    local instance_ids=("$@")
    echo "Terminating: ${instance_ids[*]}"
    
    for instance_id in "${instance_ids[@]}"; do
        terminate_instance "$instance_id"
    done
    echo "Finished"
}



