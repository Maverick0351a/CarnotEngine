# 4_PKI_KMS_Inventory_AWS/inventory_aws_crypto.py
import boto3
import json
from datetime import datetime
from botocore.exceptions import ClientError
import logging

# Setup basic logging
# logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Note: This code requires 'boto3' and configured AWS credentials.

def inventory_aws_crypto(region='us-east-1'):
    """Inventories AWS KMS keys and ACM certificates, mapping to CryptoBOM fields."""
    logger.info(f"Starting AWS crypto inventory in region: {region}")
    try:
        # Boto3 clients handle retries by default
        kms_client = boto3.client('kms', region_name=region)
        acm_client = boto3.client('acm', region_name=region)
    except Exception as e:
        logger.error(f"Could not initialize AWS clients: {e}")
        return []

    inventory = []

    # --- Inventory KMS Keys ---
    inventory.extend(inventory_kms(kms_client))
    
    # --- Inventory ACM Certificates ---
    inventory.extend(inventory_acm(acm_client))

    return inventory

def inventory_kms(kms_client):
    kms_inventory = []
    # Use paginator for scalability
    kms_paginator = kms_client.get_paginator('list_keys')
    try:
        for page in kms_paginator.paginate():
            for key_summary in page['Keys']:
                key_id = key_summary['KeyId']
                try:
                    # Describe key to get details
                    metadata = kms_client.describe_key(KeyId=key_id)['KeyMetadata']
                    
                    # Focus on Customer Managed Keys (CMKs)
                    if metadata.get('KeyManager') != 'CUSTOMER':
                        continue
                    
                    spec = metadata.get('KeySpec')
                    # Determine quantum vulnerability based on AWS KMS Specs
                    is_quantum_vulnerable = spec.startswith("RSA_") or spec.startswith("ECC_")

                    # TODO: Implement fetching resource tags to populate owner/lifetime
                    
                    kms_inventory.append({
                        "asset_id": metadata['Arn'],
                        "source": "AWS_KMS_CarnotEngine",
                        "exposure": "Internal", # KMS keys are generally internal assets
                        # Placeholders: In production, fetch these from Tags or resource policies
                        "owner": metadata.get("AWSAccountId"), 
                        "secrecy_lifetime_years": 5, # Default assumption, requires context/tags
                        "crypto_metadata": {
                            "algorithm": spec,
                            "is_quantum_vulnerable": is_quantum_vulnerable,
                            "usage": metadata.get("KeyUsage"),
                            "state": metadata.get("KeyState")
                        }
                    })
                except ClientError as e:
                    logger.warning(f"Could not describe KMS key {key_id}: {e}")
    except ClientError as e:
        logger.error(f"Error listing KMS keys: {e}")
    return kms_inventory

def inventory_acm(acm_client):
    """Inventories AWS Certificate Manager (ACM) certificates."""
    acm_inventory = []
    acm_paginator = acm_client.get_paginator('list_certificates')
    try:
        for page in acm_paginator.paginate():
            for cert_summary in page.get('CertificateSummaryList', []):
                cert_arn = cert_summary['CertificateArn']
                try:
                    # Describe certificate to get details (KeyAlgorithm, InUseBy, Expiry)
                    details = acm_client.describe_certificate(CertificateArn=cert_arn)['Certificate']
                    
                    alg = details.get('KeyAlgorithm')
                    # Determine quantum vulnerability based on common algorithms
                    is_quantum_vulnerable = alg.startswith("RSA") or alg.startswith("EC")

                    # Determine exposure based on associated resources (e.g., CloudFront, ELB)
                    # Simplified logic: assume external if InUseBy is populated, requires refinement.
                    exposure = "External" if details.get("InUseBy") else "Internal"
                    
                    # Handle potential missing NotAfter field and ensure ISO format
                    not_after = details.get("NotAfter")
                    if isinstance(not_after, datetime):
                        not_after = not_after.isoformat()

                    acm_inventory.append({
                        "asset_id": cert_arn,
                        "source": "AWS_ACM_CarnotEngine",
                        "exposure": exposure,
                        "owner": "Unknown", # Requires tagging strategy
                        "secrecy_lifetime_years": 1, # TLS certs typically have short lives, but the data they protect might not.
                        "crypto_metadata": {
                            "algorithm": alg,
                            "is_quantum_vulnerable": is_quantum_vulnerable,
                            "not_after": not_after,
                            "domain": details.get("DomainName"),
                            "in_use_by": details.get("InUseBy")
                        }
                    })
                except ClientError as e:
                    logger.warning(f"Could not describe ACM cert {cert_arn}: {e}")
    except ClientError as e:
        logger.error(f"Error listing ACM certificates: {e}")
    return acm_inventory

# Example usage:
# if __name__ == "__main__":
#     results = inventory_aws_crypto()
#     # Use default=str for datetime objects if not using isoformat() consistently
#     print(json.dumps(results, indent=2, default=str))

# Unit Test Strategy: Use the 'moto' library (pip install moto) to mock AWS API calls for KMS and ACM.