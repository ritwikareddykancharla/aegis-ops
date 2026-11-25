#!/usr/bin/env bash
# ==============================================================================
# AegisOps Production AWS Deployment:
#   - Amazon CloudFront CDN (`https://dxxxx.cloudfront.net`)
#   - Origin 1 (`*`): Private Amazon S3 Bucket (`aegisops-web-796330847946-us-west-2`) via OAC
#   - Origin 2 (`/api/*`): Python 3.12 Lambda (`aegisops-api-origin`) in `us-west-2`
#     with IAM permission for Amazon Bedrock (`us.amazon.nova-lite-v1:0`)
# ==============================================================================
set -euo pipefail

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
export AWS_PROFILE="portfolio"

REGION="${AWS_REGION:-us-west-2}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="${PROJECT_ROOT}/web"
STAGE_DIR="/tmp/aegisops-aws-build"
ZIP_PATH="/tmp/aegisops-api.zip"
FUNC_NAME="aegisops-api-origin"
ROLE_NAME="QuickSpacesBedrockApiRole"
OAC_NAME="aegisops-s3-oac"
CF_COMMENT="AegisOps Incident Investigation Console"

echo "======================================================================"
echo " 1. Verifying AWS Session (Profile: ${AWS_PROFILE}, Region: ${REGION})"
echo "======================================================================"
IDENTITY_JSON="$(aws sts get-caller-identity --output json)"
ACCOUNT_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["Account"])' <<< "${IDENTITY_JSON}")"
BUCKET_NAME="aegisops-web-${ACCOUNT_ID}-${REGION}"
echo "✅ Authenticated to AWS Account: ${ACCOUNT_ID}"

echo ""
echo "======================================================================"
echo " 2. Verifying IAM Role with Amazon Bedrock Converse Access"
echo "======================================================================"
if ROLE_JSON="$(aws iam get-role --role-name "${ROLE_NAME}" --output json 2>/dev/null)"; then
  ROLE_ARN="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["Role"]["Arn"])' <<< "${ROLE_JSON}")"
else
  TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
  CREATE_ROLE_JSON="$(aws iam create-role --role-name "${ROLE_NAME}" --assume-role-policy-document "${TRUST}" --output json)"
  ROLE_ARN="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["Role"]["Arn"])' <<< "${CREATE_ROLE_JSON}")"
  aws iam attach-role-policy --role-name "${ROLE_NAME}" --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  sleep 10
fi

BEDROCK_POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
      "Resource": [
        "arn:aws:bedrock:*::foundation-model/*",
        "arn:aws:bedrock:*:*:inference-profile/*"
      ]
    }
  ]
}'
aws iam put-role-policy \
  --role-name "${ROLE_NAME}" \
  --policy-name "QuickSpacesBedrockInvoke" \
  --policy-document "${BEDROCK_POLICY}"

echo ""
echo "======================================================================"
echo " 3. Packaging & Deploying /api/* Origin (${FUNC_NAME})"
echo "======================================================================"
cp "${PROJECT_ROOT}/docs/architecture.svg" "${WEB_DIR}/architecture.svg"
rm -rf "${STAGE_DIR}" "${ZIP_PATH}"
mkdir -p "${STAGE_DIR}/docs"
cp -R "${PROJECT_ROOT}/aegis_ops" "${STAGE_DIR}/aegis_ops"
cp -R "${PROJECT_ROOT}/web" "${STAGE_DIR}/web"
cp "${PROJECT_ROOT}/docs/architecture.svg" "${STAGE_DIR}/docs/architecture.svg"
find "${STAGE_DIR}" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
(cd "${STAGE_DIR}" && zip -qr "${ZIP_PATH}" .)

if aws lambda get-function --function-name "${FUNC_NAME}" --region "${REGION}" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "${FUNC_NAME}" --zip-file "fileb://${ZIP_PATH}" --region "${REGION}" >/dev/null
  aws lambda wait function-updated --function-name "${FUNC_NAME}" --region "${REGION}"
  aws lambda update-function-configuration \
    --function-name "${FUNC_NAME}" \
    --runtime "python3.12" \
    --handler "aegis_ops.web_api.lambda_handler" \
    --timeout 30 \
    --memory-size 512 \
    --environment "Variables={AEGISOPS_DELIVERY=cloudfront-s3-oac,AEGISOPS_BEDROCK_MODEL=us.amazon.nova-lite-v1:0}" \
    --region "${REGION}" >/dev/null
  aws lambda wait function-updated --function-name "${FUNC_NAME}" --region "${REGION}"
else
  aws lambda create-function \
    --function-name "${FUNC_NAME}" \
    --runtime "python3.12" \
    --role "${ROLE_ARN}" \
    --handler "aegis_ops.web_api.lambda_handler" \
    --zip-file "fileb://${ZIP_PATH}" \
    --timeout 30 \
    --memory-size 512 \
    --environment "Variables={AEGISOPS_DELIVERY=cloudfront-s3-oac,AEGISOPS_BEDROCK_MODEL=us.amazon.nova-lite-v1:0}" \
    --region "${REGION}" >/dev/null
  aws lambda wait function-active --function-name "${FUNC_NAME}" --region "${REGION}"
fi

if FURL_JSON="$(aws lambda get-function-url-config --function-name "${FUNC_NAME}" --region "${REGION}" --output json 2>/dev/null)"; then
  API_ORIGIN_URL="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["FunctionUrl"])' <<< "${FURL_JSON}")"
else
  FURL_JSON="$(aws lambda create-function-url-config --function-name "${FUNC_NAME}" --auth-type NONE --region "${REGION}" --output json)"
  API_ORIGIN_URL="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["FunctionUrl"])' <<< "${FURL_JSON}")"
fi
aws lambda add-permission --function-name "${FUNC_NAME}" --statement-id "AllowCloudFrontPublicApi" --action "lambda:InvokeFunctionUrl" --principal "*" --function-url-auth-type NONE --region "${REGION}" >/dev/null 2>&1 || true
aws lambda add-permission --function-name "${FUNC_NAME}" --statement-id "AllowCloudFrontInvoke" --action "lambda:InvokeFunction" --principal "*" --invoked-via-function-url --region "${REGION}" >/dev/null 2>&1 || true

API_DOMAIN="$(python3 -c 'from urllib.parse import urlparse; import sys; print(urlparse(sys.argv[1]).netloc)' "${API_ORIGIN_URL}")"
echo "✅ /api/* Origin Domain: ${API_DOMAIN}"

echo ""
echo "======================================================================"
echo " 4. Creating Private S3 Bucket (${BUCKET_NAME}) & Syncing Web UI"
echo "======================================================================"
if ! aws s3api head-bucket --bucket "${BUCKET_NAME}" 2>/dev/null; then
  aws s3api create-bucket \
    --bucket "${BUCKET_NAME}" \
    --region "${REGION}" \
    --create-bucket-configuration "LocationConstraint=${REGION}" >/dev/null
fi

aws s3api put-public-access-block \
  --bucket "${BUCKET_NAME}" \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

aws s3 sync "${WEB_DIR}/" "s3://${BUCKET_NAME}/" --delete

echo ""
echo "======================================================================"
echo " 5. Provisioning Amazon CloudFront Distribution (S3 OAC + /api/*)"
echo "======================================================================"
OAC_ID="$(aws cloudfront list-origin-access-controls --output json | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
items = (json.loads(raw) if raw else {}).get("OriginAccessControlList", {}).get("Items", [])
for it in items:
    if it.get("Name") == "'"${OAC_NAME}"'":
        print(it["Id"]); break
')"

if [[ -z "${OAC_ID}" ]]; then
  OAC_CFG='{"Name":"'"${OAC_NAME}"'","Description":"OAC for AegisOps private S3 web bucket","SigningProtocol":"sigv4","SigningBehavior":"always","OriginAccessControlOriginType":"s3"}'
  OAC_ID="$(aws cloudfront create-origin-access-control --origin-access-control-config "${OAC_CFG}" --output json | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["OriginAccessControl"]["Id"])')"
fi

EXISTING_DIST="$(aws cloudfront list-distributions --output json | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
items = (json.loads(raw) if raw else {}).get("DistributionList", {}).get("Items", [])
for d in items:
    if d.get("Comment") == "'"${CF_COMMENT}"'":
        print(d["Id"] + "|" + d["DomainName"]); break
')"

S3_ORIGIN_DOMAIN="${BUCKET_NAME}.s3.${REGION}.amazonaws.com"

if [[ -n "${EXISTING_DIST}" ]]; then
  DIST_ID="${EXISTING_DIST%%|*}"
  CF_DOMAIN="${EXISTING_DIST##*|}"
  echo "   Reusing existing CloudFront distribution: ${DIST_ID} (${CF_DOMAIN})"
else
  CF_CONFIG="$(python3 - "${S3_ORIGIN_DOMAIN}" "${OAC_ID}" "${API_DOMAIN}" "${CF_COMMENT}" <<'PY'
import json, sys, time
s3_domain, oac_id, api_domain, comment = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
cfg = {
    "CallerReference": f"aegisops-{int(time.time())}",
    "Comment": comment,
    "Enabled": True,
    "DefaultRootObject": "index.html",
    "HttpVersion": "http2and3",
    "PriceClass": "PriceClass_100",
    "Origins": {
        "Quantity": 2,
        "Items": [
            {
                "Id": "s3-web-origin",
                "DomainName": s3_domain,
                "OriginAccessControlId": oac_id,
                "S3OriginConfig": {"OriginAccessIdentity": ""},
            },
            {
                "Id": "api-backend-origin",
                "DomainName": api_domain,
                "CustomOriginConfig": {
                    "HTTPPort": 80,
                    "HTTPSPort": 443,
                    "OriginProtocolPolicy": "https-only",
                    "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    "OriginReadTimeout": 30,
                    "OriginKeepaliveTimeout": 5,
                },
            },
        ],
    },
    "DefaultCacheBehavior": {
        "TargetOriginId": "s3-web-origin",
        "ViewerProtocolPolicy": "redirect-to-https",
        "Compress": True,
        "AllowedMethods": {
            "Quantity": 2,
            "Items": ["GET", "HEAD"],
            "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
        },
        "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
    },
    "CacheBehaviors": {
        "Quantity": 1,
        "Items": [
            {
                "PathPattern": "/api/*",
                "TargetOriginId": "api-backend-origin",
                "ViewerProtocolPolicy": "redirect-to-https",
                "Compress": True,
                "AllowedMethods": {
                    "Quantity": 7,
                    "Items": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
                    "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
                },
                "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
                "OriginRequestPolicyId": "b689b0a8-53d0-40ab-baf2-68738e2966ac",
            }
        ],
    },
}
print(json.dumps(cfg))
PY
)"
  CREATED_JSON="$(aws cloudfront create-distribution --distribution-config "${CF_CONFIG}" --output json)"
  DIST_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["Distribution"]["Id"])' <<< "${CREATED_JSON}")"
  CF_DOMAIN="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["Distribution"]["DomainName"])' <<< "${CREATED_JSON}")"
fi

BUCKET_POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudFrontServicePrincipalReadOnly",
      "Effect": "Allow",
      "Principal": {"Service": "cloudfront.amazonaws.com"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::'"${BUCKET_NAME}"'/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::'"${ACCOUNT_ID}"':distribution/'"${DIST_ID}"'"
        }
      }
    }
  ]
}'
aws s3api put-bucket-policy --bucket "${BUCKET_NAME}" --policy "${BUCKET_POLICY}"
aws cloudfront create-invalidation --distribution-id "${DIST_ID}" --paths "/*" >/dev/null

echo ""
echo "======================================================================"
echo " 🚀 AEGISOPS LIVE ON AMAZON CLOUDFRONT"
echo "    CloudFront URL : https://${CF_DOMAIN}"
echo "    Distribution ID: ${DIST_ID}"
echo "    Private S3 OAC : s3://${BUCKET_NAME}"
echo "    API + Bedrock  : ${API_ORIGIN_URL}"
echo "======================================================================"
