
# COMPLETE TEST SUITE - ALL 5 HANDLERS


# Step 1: Create all misconfigurations
gsutil iam ch allUsers:objectViewer gs://test-bucket-gcpguard12
gcloud projects add-iam-policy-binding gcpguard-project12 \
  --member="serviceAccount:test-sa-scc@gcpguard-project12.iam.gserviceaccount.com" \
  --role="roles/editor" --quiet
gcloud compute firewall-rules update test-open-ssh --disabled=false --quiet
gcloud compute instances add-access-config test-instance \
  --zone=us-central1-a \
  --access-config-name="external-nat" 2>/dev/null || echo "IP already exists"

echo "All misconfigurations created. Waiting 3 seconds..."
sleep 3

# Step 2: Trigger all 5 handlers
gcloud pubsub topics publish gcpguard-findings --message='{"finding":{"category":"PUBLIC_BUCKET_ACL","resourceName":"//storage.googleapis.com/projects/_/buckets/test-bucket-gcpguard12"}}' && sleep 3
gcloud pubsub topics publish gcpguard-findings --message='{"finding":{"category":"ADMIN_SERVICE_ACCOUNT","resourceName":"//cloudresourcemanager.googleapis.com/projects/gcpguard-project12"}}' && sleep 3
gcloud pubsub topics publish gcpguard-findings --message='{"finding":{"category":"OPEN_FIREWALL","resourceName":"//compute.googleapis.com/projects/gcpguard-project12/global/firewalls/test-open-ssh"}}' && sleep 3
gcloud pubsub topics publish gcpguard-findings --message='{"finding":{"category":"DISK_CMEK_DISABLED","resourceName":"//compute.googleapis.com/projects/gcpguard-project12/zones/us-central1-a/disks/test-disk"}}' && sleep 3
gcloud pubsub topics publish gcpguard-findings --message='{"finding":{"category":"PUBLIC_IP_ADDRESS","resourceName":"//compute.googleapis.com/projects/gcpguard-project12/zones/us-central1-a/instances/test-instance"}}'

echo "All handlers triggered. Waiting 15 seconds for processing..."
sleep 15

# Step 3: Verify all remediations
echo "=========================================="
echo "VERIFICATION RESULTS"
echo "=========================================="
echo -n "Handler 1: " && gsutil iam get gs://test-bucket-gcpguard12 | grep -q allUsers && echo "❌ Failed" || echo "✅ Fixed"
echo -n "Handler 2: " && gcloud projects get-iam-policy gcpguard-project12 --flatten="bindings[].members" --filter="bindings.members:serviceAccount:test-sa-scc@*" --format="value(bindings.role)" | grep -q editor && echo "❌ Failed" || echo "✅ Fixed"
echo -n "Handler 3: " && [ "$(gcloud compute firewall-rules describe test-open-ssh --format='value(disabled)')" = "True" ] && echo "✅ Fixed" || echo "❌ Failed"
echo "Handler 4: ⚠️  Manual (expected)"
echo -n "Handler 5: " && [ -z "$(gcloud compute instances describe test-instance --zone=us-central1-a --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)" ] && echo "✅ Fixed" || echo "❌ Failed"
echo "=========================================="

# View logs
gcloud logging read "textPayload=~\"GCP GUARD\"" --limit=30 --freshness=5m --format="value(textPayload)"
