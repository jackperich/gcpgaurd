PROJECT_ID="gcpguard-project12"
REGION="us-central1"
FUNCTION_NAME="gcpguard-remediate"
PUBSUB_TOPIC="gcpguard-findings"
SA_EMAIL="gcpguard-sa@${PROJECT_ID}.iam.gserviceaccount.com"

echo "🚀 Deploying GCPGuard Cloud Function..."

gcloud functions deploy $FUNCTION_NAME \
  --gen2 \
  --runtime=python311 \
  --region=$REGION \
  --source=. \
  --entry-point=process_security_finding \
  --trigger-topic=$PUBSUB_TOPIC \
  --service-account=$SA_EMAIL \
  --memory=512MB \
  --timeout=540s \
  --project=$PROJECT_ID

echo "✅ Deployment complete!"
echo ""
echo "To view logs run:"
echo "gcloud functions logs read $FUNCTION_NAME --gen2 --region=$REGION --project=$PROJECT_ID"
