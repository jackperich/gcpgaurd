# GCP Guard - Testing Guide

This guide provides step-by-step instructions to test all 5 remediation handlers.

## Prerequisites

Set environment variables in Cloud Shell:

export PROJECT_ID="gcpguard-project12"
export REGION="us-central1"
export ORG_ID="765521112500"

---

## Test 1: Public Bucket Handler

### Step 1: Create Public Bucket

BUCKET_NAME="gcpguard-test-public-$RANDOM"
gsutil mb -p $PROJECT_ID gs://$BUCKET_NAME
gsutil iam ch allUsers:objectViewer gs://$BUCKET_NAME

### Step 2: Verify Bucket is Public

gsutil iam get gs://$BUCKET_NAME | grep allUsers

Should show "allUsers"

### Step 3: Send Remediation Trigger

gcloud pubsub topics publish gcpguard-findings --project=$PROJECT_ID --message='{"finding":{"category":"PUBLIC_BUCKET_ACL","severity":"HIGH","state":"ACTIVE","resourceName":"//storage.googleapis.com/projects/_/buckets/'$BUCKET_NAME'"}}'

### Step 4: Verify Remediation (wait 15 seconds)

sleep 15
gsutil iam get gs://$BUCKET_NAME | grep allUsers || echo "✅ SUCCESS: allUsers removed"

### Step 5: Cleanup

gsutil rm -r gs://$BUCKET_NAME

**Expected Result:** ✅ allUsers removed from bucket IAM policy

---

## Test 2: Overly Permissive IAM Handler

**Status:** ⚠️ Currently failing - debugging in progress

---

## Test 3: Open Firewall Handler

### Step 1: Create Open Firewall Rule

gcloud compute firewall-rules create test-open-ssh --project=$PROJECT_ID --allow=tcp:22 --source-ranges=0.0.0.0/0 --description="Test rule for GCP Guard"

### Step 2: Verify Rule is Enabled

gcloud compute firewall-rules describe test-open-ssh --project=$PROJECT_ID --format="value(disabled)"

Should show "False" (not disabled)

### Step 3: Send Remediation Trigger

gcloud pubsub topics publish gcpguard-findings --project=$PROJECT_ID --message='{"finding":{"category":"OPEN_FIREWALL","severity":"HIGH","state":"ACTIVE","resourceName":"//compute.googleapis.com/projects/'$PROJECT_ID'/global/firewalls/test-open-ssh"}}'

### Step 4: Verify Remediation (wait 15 seconds)

sleep 15
gcloud compute firewall-rules describe test-open-ssh --project=$PROJECT_ID --format="value(disabled)"

Should show "True"

### Step 5: Cleanup

gcloud compute firewall-rules delete test-open-ssh --project=$PROJECT_ID --quiet

**Expected Result:** ✅ Firewall rule disabled

---

## Test 4: Unencrypted Disk Handler

### Step 1: Create Unencrypted Disk

gcloud compute disks create test-unencrypted-disk --project=$PROJECT_ID --zone=us-central1-a --size=10GB --type=pd-standard

### Step 2: Send Remediation Trigger

gcloud pubsub topics publish gcpguard-findings --project=$PROJECT_ID --message='{"finding":{"category":"DISK_CMEK_DISABLED","severity":"MEDIUM","state":"ACTIVE","resourceName":"//compute.googleapis.com/projects/'$PROJECT_ID'/zones/us-central1-a/disks/test-unencrypted-disk"}}'

### Step 3: Check Logs (wait 15 seconds)

sleep 15
gcloud functions logs read gcpguard-remediate --gen2 --region=$REGION --limit=20 | grep -A 3 "DISK_CMEK"

Should show "Manual remediation required"

### Step 4: Cleanup

gcloud compute disks delete test-unencrypted-disk --zone=us-central1-a --project=$PROJECT_ID --quiet

**Expected Result:** ✅ Logs show "Manual remediation required" (no auto-fix due to downtime risk)

---

## Test 5: Public IP Handler

### Step 1: Create Instance with Public IP

gcloud compute instances create test-public-ip-instance --project=$PROJECT_ID --zone=us-central1-a --machine-type=e2-micro --network-interface=network-tier=PREMIUM,subnet=default

### Step 2: Verify Public IP Exists

gcloud compute instances describe test-public-ip-instance --project=$PROJECT_ID --zone=us-central1-a --format="value(networkInterfaces[0].accessConfigs[0].natIP)"

Should show an IP address like 34.XXX.XXX.XXX

### Step 3: Send Remediation Trigger

gcloud pubsub topics publish gcpguard-findings --project=$PROJECT_ID --message='{"finding":{"category":"PUBLIC_IP_ADDRESS","severity":"HIGH","state":"ACTIVE","resourceName":"//compute.googleapis.com/projects/'$PROJECT_ID'/zones/us-central1-a/instances/test-public-ip-instance"}}'

### Step 4: Verify IP Removed (wait 20 seconds)

sleep 20
gcloud compute instances describe test-public-ip-instance --project=$PROJECT_ID --zone=us-central1-a --format="value(networkInterfaces[0].accessConfigs[0].natIP)"

Should be empty (no output)

### Step 5: Cleanup

gcloud compute instances delete test-public-ip-instance --zone=us-central1-a --project=$PROJECT_ID --quiet

**Expected Result:** ✅ External IP removed from instance

---

## Complete Cleanup Command

Remove all test resources at once:

export PROJECT_ID="gcpguard-project12"
gcloud compute instances delete test-public-ip-instance --zone=us-central1-a --project=$PROJECT_ID --quiet 2>/dev/null
gcloud compute disks delete test-unencrypted-disk --zone=us-central1-a --project=$PROJECT_ID --quiet 2>/dev/null
gcloud compute firewall-rules delete test-open-ssh --project=$PROJECT_ID --quiet 2>/dev/null
gsutil rm -r gs://gcpguard-test-* 2>/dev/null
echo "✅ Cleanup complete"

---

## Viewing Function Logs

Check function execution logs:

gcloud functions logs read gcpguard-remediate --gen2 --region=$REGION --limit=50

---

## Test Results Summary

| Handler | Status | Notes |
|---------|--------|-------|
| Public Bucket | ✅ PASS | Removes allUsers from bucket IAM |
| Overly Permissive IAM | ⚠️ DEBUGGING | Handler executes but doesn't remove roles |
| Open Firewall | ✅ PASS | Disables firewall rules |
| Unencrypted Disk | ✅ PASS | Logs for manual remediation |
| Public IP | ✅ PASS | Removes external IP from instances |

**Overall: 4/5 handlers fully functional (80% success rate)**
