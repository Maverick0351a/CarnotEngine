#!/usr/bin/env bash
set -euo pipefail
SERVICE=${1:-carnot-attest}
REGION=${REGION:-us-central1}
PROJECT=${PROJECT:?Set PROJECT env var}
ARGS=${ARGS:-}

gcloud run deploy "$SERVICE" \
  --source api \
  --region "$REGION" \
  --allow-unauthenticated \
  --min-instances 0 \
  --project "$PROJECT" $ARGS
