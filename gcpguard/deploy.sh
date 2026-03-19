PROJECT_ID="gcpguard-project1"
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
  --entry-point=remediate \
  --trigger-topic=$PUBSUB_TOPIC \
  --service-account=$SA_EMAIL \
  --memory=256Mi \
  --timeout=120s \
  --project=$PROJECT_ID

echo "✅ Deployment complete!"
echo ""
echo "To view logs run:"
echo "gcloud functions logs read $FUNCTION_NAME --region=$REGION --project=$PROJECT_ID"