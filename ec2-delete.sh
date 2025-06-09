#!/bin/bash
# Delete instances along with associated volumes and snapshots

delete_snapshots() {
    local snapshots="$1"
    if [[ -n "$snapshots" ]]; then
        echo "Deleting snapshots: $snapshots"
        for snapshot_id in $snapshots; do
            echo "Deleting snapshot: $snapshot_id"
            aws ec2 delete-snapshot --snapshot-id "$snapshot_id"
        done
    fi
}

delete_volumes() {
    local volumes="$1"
    if [[ -n "$volumes" ]]; then
        for volume_id in $volumes; do
            echo "Waiting for volume $volume_id to become available..."
            aws ec2 wait volume-available --volume-ids "$volume_id"
            
            echo "Deleting volume: $volume_id"
            local snapshots=$(aws ec2 describe-snapshots --filters "Name=volume-id,Values=$volume_id" --query 'Snapshots[*].SnapshotId' --output text)
            delete_snapshots "$snapshots"
            aws ec2 delete-volume --volume-id "$volume_id"
        done
    else
        echo "No volumes to delete"
    fi
}

delete_amis() {
  local instance_id="$1"
  # Assumes there is a tag SourceInstance on the AMIs set to the instance ID
  local ami_ids=$(aws ec2 describe-images --filters "Name=tag:SourceInstance,Values=$instance_id" --query 'Images[*].ImageId' --output text)

  if [ -z "$ami_ids" ]; then
      echo "No AMIs found for instance: $instance_id"
      return
  fi
  
  echo "Found AMI IDs: $ami_ids"
  
  for ami_id in $ami_ids; do
    echo "Deregistering AMI: $ami_id"
    aws ec2 deregister-image --image-id "$ami_id"

    local snapshot_ids=$(aws ec2 describe-images --image-ids "$ami_id" --query 'Images[].BlockDeviceMappings[].Ebs.SnapshotId' --output text)
    if [ -z "$snapshot_ids" ]; then
        echo "No snapshots found for AMI: $ami_id"
    else
      echo "Deleting snapshots: $snapshot_ids"
      delete_snapshots "$snapshot_ids"
    fi
  done
}

process_instances() {
    local instance_ids=("$@")
    echo "Terminating instances: ${instance_ids[*]}"
    
    # Process each instance
    for instance_id in "${instance_ids[@]}"; do
        echo "Processing instance: $instance_id"
        local volumes=$(aws ec2 describe-volumes --filters "Name=attachment.instance-id,Values=$instance_id" --query 'Volumes[*].VolumeId' --output text)
        echo "  volumes: $volumes"
        aws ec2 terminate-instances --instance-ids "$instance_id"
        delete_amis "$instance_id"
        delete_volumes "$volumes"
    done

    # aws ec2 terminate-instances --instance-ids "${instance_ids[@]}"
}

if [ "$#" -eq 0 ]; then
  echo "Usage: $0 <instance_id_1> <instance_id_2> ..."
  exit 1
fi

process_instances "$@"

echo "Script finished."