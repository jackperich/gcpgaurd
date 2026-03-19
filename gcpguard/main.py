import base64
import json
import functions_framework
from google.cloud import logging as cloud_logging

# Initialize Cloud Logging client
logging_client = cloud_logging.Client()
logger = logging_client.logger("gcpguard")


@functions_framework.cloud_event
def remediate(cloud_event):
    """
    Cloud Function entry point.
    Triggered by a Pub/Sub message from SCC findings.
    Logs the finding to Cloud Logging.
    """
    try:
        # Decode the Pub/Sub message
        pubsub_message = cloud_event.data["message"]
        message_data = base64.b64decode(pubsub_message["data"]).decode("utf-8")
        finding = json.loads(message_data)

        # Extract key fields from the SCC finding
        finding_info = finding.get("finding", {})
        finding_name = finding_info.get("name", "unknown")
        category = finding_info.get("category", "unknown")
        severity = finding_info.get("severity", "unknown")
        resource_name = finding_info.get("resourceName", "unknown")
        state = finding_info.get("state", "unknown")

        # Log the finding to Cloud Logging
        log_entry = {
            "message": "GCPGuard SCC Finding Received",
            "finding_name": finding_name,
            "category": category,
            "severity": severity,
            "resource_name": resource_name,
            "state": state,
        }

        logger.log_struct(log_entry, severity="WARNING")
        print(f"[GCPGuard] Finding logged: category={category}, severity={severity}, resource={resource_name}")

    except Exception as e:
        logger.log_text(f"[GCPGuard] Error processing finding: {str(e)}", severity="ERROR")
        print(f"[GCPGuard] Error: {str(e)}")
        raise e