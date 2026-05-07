PROJECT_ID="gcpguard-project12"
PROJECT_NUMBER="299847109623"
REGION="us-central1"
FUNCTION_NAME="gcpguard-function"
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

echo ""
echo "✅ Deployment complete!"
echo ""

# Grant service account permission to invoke
gcloud run services add-iam-policy-binding $FUNCTION_NAME \
  --region=$REGION \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/run.invoker" \
  --project=$PROJECT_ID

# Grant Pub/Sub service account permission to invoke
gcloud run services add-iam-policy-binding $FUNCTION_NAME \
  --region=$REGION \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-pubsub.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --project=$PROJECT_ID

echo ""
echo "✅ Permissions granted!"
echo ""
