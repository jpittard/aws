#!/bin/bash
# Empty a versioned bucket
export BUCKET_NAME="$1"

delete_batch() {
    local batch="$*"
    local json=$(echo "$batch" | xargs -n 2 | jq -R 'split(" ") | {Key: .[0], VersionId: .[1]}' | jq -s '.')
    
    aws s3api delete-objects \
        --bucket "$BUCKET_NAME" \
        --delete "{\"Objects\":$json,\"Quiet\":true}"
}

export -f delete_batch

aws s3api list-object-versions --bucket "$BUCKET_NAME" --output text \
    --query 'Versions[].[Key,VersionId]' | \
    tr '\t' ' ' | \
    xargs -n 1000 -P 10 bash -c 'delete_batch "$@"' _

aws s3api list-object-versions --bucket "$BUCKET_NAME" --output text \
    --query 'DeleteMarkers[].[Key,VersionId]' | \
    tr '\t' ' ' | \
    xargs -n 1000 -P 10 bash -c 'delete_batch "$@"' _
