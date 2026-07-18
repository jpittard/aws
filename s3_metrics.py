#!/usr/bin/env python3

import boto3
from datetime import datetime, timedelta, timezone
import csv

s3 = boto3.client("s3")
cloudwatch = boto3.client("cloudwatch")

# CloudWatch S3 Storage metrics are published once per day
end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(days=3)

# Output to CSV file
output_file = "s3_metrics.csv"

with open(output_file, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    # Write header
    writer.writerow(["Bucket", "CreatedDate", "Objects", "Bytes"])

    for bucket in s3.list_buckets()["Buckets"]:
        bucket_name = bucket["Name"]
        # Get bucket creation date
        creation_date = bucket["CreationDate"].strftime("%Y-%m-%d %H:%M:%S")

        try:
            # Total bytes
            size_resp = cloudwatch.get_metric_statistics(
                Namespace="AWS/S3",
                MetricName="BucketSizeBytes",
                Dimensions=[
                    {"Name": "BucketName", "Value": bucket_name},
                    {"Name": "StorageType", "Value": "StandardStorage"},
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=["Average"],
            )

            size_bytes = (
                sorted(
                    size_resp["Datapoints"],
                    key=lambda x: x["Timestamp"]
                )[-1]["Average"]
                if size_resp["Datapoints"]
                else 0
            )

            # Object count
            count_resp = cloudwatch.get_metric_statistics(
                Namespace="AWS/S3",
                MetricName="NumberOfObjects",
                Dimensions=[
                    {"Name": "BucketName", "Value": bucket_name},
                    {"Name": "StorageType", "Value": "AllStorageTypes"},
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=["Average"],
            )

            object_count = (
                sorted(
                    count_resp["Datapoints"],
                    key=lambda x: x["Timestamp"]
                )[-1]["Average"]
                if count_resp["Datapoints"]
                else 0
            )
            print(bucket_name, creation_date, int(object_count), int(size_bytes))
            writer.writerow([bucket_name, creation_date, int(object_count), int(size_bytes)])

        except Exception as e:
            writer.writerow([bucket_name, creation_date, "ERROR", str(e)])

print(f"Metrics saved to {output_file}")
