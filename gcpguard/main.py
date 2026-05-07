import base64
import json
import functions_framework
from datetime import datetime

from google.cloud import storage
from google.cloud import compute_v1
from google.cloud import resourcemanager
from google.cloud import bigquery
import time
import google.auth
from google.api_core import exceptions


# ENTRY POINT — Triggered by Pub/Sub via Eventarc from SCC

@functions_framework.cloud_event
def process_security_finding(cloud_event):
    """
    Main entry point for GCP Guard Cloud Function.
    Processes security findings from Security Command Center and routes them
    to appropriate remediation handlers.
    """
    try:
        # ── Extract and parse the Pub/Sub message ──────────────────────────
        if hasattr(cloud_event, 'data') and 'message' in cloud_event.data:
            pubsub_message = cloud_event.data["message"]
            
            if 'data' in pubsub_message:
                message_data = base64.b64decode(pubsub_message["data"]).decode("utf-8")
                finding = json.loads(message_data)
            else:
                finding = pubsub_message
        else:
            finding = cloud_event.data if hasattr(cloud_event, 'data') else {}
        
        # ── Extract finding information ────────────────────────────────────
        finding_info = finding.get("finding", {})
        notification_config = finding.get("notificationConfigName", "unknown")
        
        category = finding_info.get("category", "UNKNOWN")
        severity = finding_info.get("severity", "UNKNOWN")
        state = finding_info.get("state", "UNKNOWN")
        resource_name = finding_info.get("resourceName", "UNKNOWN")
        finding_name = finding_info.get("name", "UNKNOWN")
        
        # ── Log the finding ────────────────────────────────────────────────
        print("[GCP GUARD] New Security Finding Received")
        print(f"Timestamp: {datetime.utcnow().isoformat()}Z")
        print(f"Category: {category}")
        print(f"Severity: {severity}")
        print(f"State: {state}")
        print(f"Resource: {resource_name}")
        print(f"Finding: {finding_name}")
        print(f"Config: {notification_config}")
        
        # ── Route to remediation handler ───────────────────────────────────
        result = route_to_handler(finding_info)
        
        print(f"[GCP GUARD] Remediation Result: {result}")
        
        return result
        
    except Exception as e:
        print(f"[GCP GUARD ERROR] Failed to process finding: {str(e)}")
        print(f"CloudEvent data: {cloud_event.data if hasattr(cloud_event, 'data') else 'N/A'}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}


# ROUTING LOGIC

def route_to_handler(finding_info):
    """
    Routes a finding to the appropriate remediation handler based on category.
    Returns a dict with status and message.
    """
    category = finding_info.get("category", "")
    resource_name = finding_info.get("resourceName", "")
    
    print(f"[GCP GUARD] Routing finding: category={category}")
    
    # Map SCC categories to handler functions
    handlers = {
        # Public bucket findings
        "PUBLIC_BUCKET_ACL": handle_public_bucket,
        "PUBLIC_BUCKET_IAM": handle_public_bucket,
        "BUCKET_POLICY_ONLY_DISABLED": handle_public_bucket,
        
        # IAM findings
        "ADMIN_SERVICE_ACCOUNT": handle_overly_permissive_iam,
        "KMS_ROLE_SEPARATION": handle_overly_permissive_iam,
        
        # Firewall findings
        "OPEN_FIREWALL": handle_open_firewall,
        "FIREWALL_OPEN_TO_WORLD": handle_open_firewall,
        "OPEN_SSH_PORT": handle_open_firewall,
        "OPEN_RDP_PORT": handle_open_firewall,
        
        # Disk encryption findings
        "DISK_CMEK_DISABLED": handle_unencrypted_disk,
        
        # Public IP findings
        "PUBLIC_IP_ADDRESS": handle_public_ip,
    }
    
    handler = handlers.get(category)
    
    if handler:
        return handler(finding_info)
    else:
        print(f"[GCP GUARD] No handler configured for category: {category}")
        return {
            "status": "unsupported",
            "category": category,
            "message": f"No remediation handler for {category}"
        }

# BIGQUERY LOGGING HELPER

def log_to_bigquery(category, handler_name, resource_name, status, message, execution_time):
    """
    Logs remediation events to BigQuery for analytics.
    """
    try:
        client = bigquery.Client()
        table_id = "gcpguard-project12.gcpguard_logs.remediation_events"
        
        rows_to_insert = [{
            "timestamp": datetime.utcnow().isoformat(),
            "category": category,
            "handler": handler_name,
            "resource_name": resource_name,
            "status": status,
            "message": message,
            "execution_time": execution_time
        }]
        
        errors = client.insert_rows_json(table_id, rows_to_insert)
        if errors:
            print(f"[BIGQUERY] Insert errors: {errors}")
        else:
            print(f"[BIGQUERY] ✅ Logged to BigQuery: {handler_name} - {status}")
            
    except Exception as e:
        print(f"[BIGQUERY] ⚠️ Failed to log (non-critical): {str(e)}")


# HANDLER 1: Public Bucket Remediation

def handle_public_bucket(finding_info):
    """
    Removes public access (allUsers, allAuthenticatedUsers) from a Cloud Storage bucket.
    
    Categories handled:
    - PUBLIC_BUCKET_ACL
    - PUBLIC_BUCKET_IAM
    - BUCKET_POLICY_ONLY_DISABLED
    """
    try:
        resource_name = finding_info.get("resourceName", "")
        
        # Extract bucket name from resource_name
        # Format: //storage.googleapis.com/projects/_/buckets/BUCKET_NAME
        if "/buckets/" not in resource_name:
            return {"status": "error", "message": "Invalid bucket resource name"}
        
        bucket_name = resource_name.split("/buckets/")[-1]
        
        print(f"[GCP GUARD] Remediating public bucket: {bucket_name}")
        
        # Get bucket and its IAM policy
        client = storage.Client()
        bucket = client.bucket(bucket_name)
        
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
        except exceptions.NotFound:
            return {"status": "error", "message": f"Bucket not found: {bucket_name}"}
        
        # Remove public members from all bindings
        public_members = {"allUsers", "allAuthenticatedUsers"}
        modified = False
        new_bindings = []
        
        for binding in policy.bindings:
            original_members = set(binding.get("members", []))
            safe_members = original_members - public_members
            
            if original_members != safe_members:
                print(f"[GCP GUARD] Removing public access from role: {binding.get('role')}")
                modified = True
            
            if safe_members:  # Only keep binding if there are non-public members
                binding["members"] = list(safe_members)
                new_bindings.append(binding)
        
        if modified:
            policy.bindings = new_bindings
            bucket.set_iam_policy(policy)
            print(f"[GCP GUARD] ✅ Removed public access from bucket: {bucket_name}")
            return {
                "status": "success",
                "bucket": bucket_name,
                "message": "Public access removed"
            }
        else:
            print(f"[GCP GUARD] No public bindings found on bucket: {bucket_name}")
            return {
                "status": "no_action",
                "bucket": bucket_name,
                "message": "No public bindings to remove"
            }
            
    except Exception as e:
        print(f"[GCP GUARD] ❌ Failed to remediate public bucket: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}


# HANDLER 2: Overly Permissive IAM - Using v1 API

def handle_overly_permissive_iam(finding_info):
    """
    Removes overly permissive IAM bindings (roles/owner, roles/editor) from
    service accounts and external users.
    
    Categories handled:
    - ADMIN_SERVICE_ACCOUNT
    - KMS_ROLE_SEPARATION
    """
    try:
        resource_name = finding_info.get("resourceName", "")
        
        # Extract project ID from resource_name
        # Format: //cloudresourcemanager.googleapis.com/projects/PROJECT_ID
        if "/projects/" not in resource_name:
            return {"status": "error", "message": "Invalid project resource name"}
        
        project_id = resource_name.split("/projects/")[-1]
        
        print(f"[GCP GUARD] Remediating overly permissive IAM on project: {project_id}")
        
        # SWITCHED TO v1 API - much simpler!
        from google.cloud import resourcemanager
        
        client = resourcemanager.Client()
        project = client.fetch_project(project_id)
        
        # Get current IAM policy
        policy = project.get_iam_policy()
        
        print(f"[GCP GUARD] DEBUG: Current policy has {len(policy.bindings)} role bindings")
        
        # Roles to remove from service accounts
        dangerous_roles = {"roles/owner", "roles/editor"}
        modified = False
        removed_members = []
        
        # Iterate through each role in the policy
        for role in list(policy.bindings.keys()):
            if role not in dangerous_roles:
                continue
            
            print(f"[GCP GUARD] DEBUG: Found dangerous role: {role}")
            
            # Get current members for this role
            current_members = set(policy.bindings[role])
            print(f"[GCP GUARD] DEBUG: Current members: {current_members}")
            
            # Filter out service accounts
            safe_members = {
                m for m in current_members
                if not m.startswith("serviceAccount:")
            }
            
            # Check if we need to remove any
            members_to_remove = current_members - safe_members
            
            if members_to_remove:
                print(f"[GCP GUARD] Removing {role} from: {members_to_remove}")
                removed_members.extend(members_to_remove)
                modified = True
                
                # Update the policy - set to safe members only
                if safe_members:
                    policy.bindings[role] = safe_members
                else:
                    # If no safe members left, remove the entire role binding
                    del policy.bindings[role]
        
        if modified:
            print(f"[GCP GUARD] DEBUG: Applying updated policy...")
            
            # Apply the updated policy
            project.set_iam_policy(policy)
            
            print(f"[GCP GUARD] ✅ Removed overly permissive IAM bindings from: {project_id}")
            print(f"[GCP GUARD] Removed {len(removed_members)} service account binding(s)")
            
            return {
                "status": "success",
                "project": project_id,
                "removed_count": len(removed_members),
                "message": f"Removed {len(removed_members)} overly permissive IAM binding(s)"
            }
        else:
            print(f"[GCP GUARD] No overly permissive bindings found on: {project_id}")
            return {
                "status": "no_action",
                "project": project_id,
                "message": "No overly permissive bindings to remove"
            }
            
    except Exception as e:
        print(f"[GCP GUARD] ❌ Failed to remediate IAM: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}

# HANDLER 3: Open Firewall Rules

def handle_open_firewall(finding_info):
    """
    Disables firewall rules that allow unrestricted access (0.0.0.0/0) on
    sensitive ports like SSH (22) and RDP (3389).
    
    Categories handled:
    - OPEN_FIREWALL
    - FIREWALL_OPEN_TO_WORLD
    - OPEN_SSH_PORT
    - OPEN_RDP_PORT
    """
    try:
        resource_name = finding_info.get("resourceName", "")
        
        # Extract project and firewall name from resource_name
        # Format: //compute.googleapis.com/projects/PROJECT/global/firewalls/RULE_NAME
        if "/firewalls/" not in resource_name:
            return {"status": "error", "message": "Invalid firewall resource name"}
        
        parts = resource_name.split("/")
        project_id = parts[parts.index("projects") + 1]
        firewall_name = parts[-1]
        
        print(f"[GCP GUARD] Disabling open firewall rule: {firewall_name} in {project_id}")
        
        # Use Compute Engine API
        firewalls_client = compute_v1.FirewallsClient()
        
        # Get the firewall rule
        firewall = firewalls_client.get(project=project_id, firewall=firewall_name)
        
        # Check if it's actually open to 0.0.0.0/0
        source_ranges = firewall.source_ranges
        if "0.0.0.0/0" not in source_ranges:
            print(f"[GCP GUARD] Firewall {firewall_name} does not allow 0.0.0.0/0, skipping")
            return {
                "status": "no_action",
                "firewall": firewall_name,
                "message": "Rule does not allow 0.0.0.0/0"
            }
        
        # Disable the firewall rule (safer than deleting)
        firewall.disabled = True
        
        patch_request = compute_v1.PatchFirewallRequest(
            project=project_id,
            firewall=firewall_name,
            firewall_resource=firewall
        )

        operation = firewalls_client.patch(request=patch_request)
        
        print(f"[GCP GUARD] ✅ Disabled open firewall rule: {firewall_name}")
        return {
            "status": "success",
            "firewall": firewall_name,
            "project": project_id,
            "message": "Firewall rule disabled"
        }
        
    except Exception as e:
        print(f"[GCP GUARD] ❌ Failed to remediate firewall: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}


# HANDLER 4: Unencrypted Disks

def handle_unencrypted_disk(finding_info):
    """
    Logs unencrypted disk findings for manual remediation.
    
    Automated disk encryption requires creating snapshots, new encrypted disks,
    and instance downtime. Flagged for manual review instead.
    
    Categories handled:
    - DISK_CMEK_DISABLED
    """
    try:
        resource_name = finding_info.get("resourceName", "")
        
        print(f"[GCP GUARD] ⚠️ Unencrypted disk detected: {resource_name}")
        print(f"[GCP GUARD] Manual remediation required: Create snapshot, then encrypted disk")
        
        return {
            "status": "manual_action_required",
            "resource": resource_name,
            "message": "Disk encryption requires manual intervention"
        }
        
    except Exception as e:
        print(f"[GCP GUARD] ❌ Failed to process unencrypted disk: {str(e)}")
        return {"status": "error", "message": str(e)}


# HANDLER 5: Public IP Exposure

def handle_public_ip(finding_info):
    """
    Removes external IP addresses from Compute Engine instances.
    
    Categories handled:
    - PUBLIC_IP_ADDRESS
    """
    try:
        resource_name = finding_info.get("resourceName", "")
        
        # Extract project, zone, and instance name from resource_name
        # Format: //compute.googleapis.com/projects/PROJECT/zones/ZONE/instances/INSTANCE
        if "/instances/" not in resource_name:
            return {"status": "error", "message": "Invalid instance resource name"}
        
        parts = resource_name.split("/")
        project_id = parts[parts.index("projects") + 1]
        zone = parts[parts.index("zones") + 1]
        instance_name = parts[-1]
        
        print(f"[GCP GUARD] Removing public IP from instance: {instance_name} in {zone}")
        
        # Use Compute Engine API
        instances_client = compute_v1.InstancesClient()
        
        # Delete the access config
        delete_request = compute_v1.DeleteAccessConfigInstanceRequest(
            project=project_id,
            zone=zone,
            instance=instance_name,
            access_config="external-nat",
            network_interface="nic0"
        )
        
        operation = instances_client.delete_access_config(request=delete_request)
        operation.result()  # Wait for completion
        
        print(f"[GCP GUARD] ✅ Removed external IP from instance: {instance_name}")
        return {
            "status": "success",
            "instance": instance_name,
            "zone": zone,
            "message": "External IP removed"
        }
        
    except Exception as e:
        print(f"[GCP GUARD] ❌ Failed to remove public IP: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}
