# Lifecycle rule to delete all objects from bucket

aws s3api put-bucket-lifecycle-configuration \
  --lifecycle-configuration '{"Rules":[{
      "ID":"empty-bucket",
      "Status":"Enabled",
      "Prefix":"",
      "Expiration":{"Days":1},
      "NoncurrentVersionExpiration":{"NoncurrentDays":1}
    }]}' \
  --bucket YOUR-BUCKET
