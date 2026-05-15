import boto3
import json
from typing import List
from typing import List
from resource_mapping import *


KEYSPEC_METADATA = {
    "RSA_2048":  {"family": "RSA", "name": "RSA-2048", "pqc": False},
    "RSA_3072":  {"family": "RSA", "name": "RSA-3072", "pqc": False},
    "RSA_4096":  {"family": "RSA", "name": "RSA-4096", "pqc": False},
    "ECC_NIST_P256": {"family": "ECC", "name": "ECDSA P-256", "pqc": False},
    "ECC_NIST_P384": {"family": "ECC", "name": "ECDSA P-384", "pqc": False},
    "ECC_NIST_P521": {"family": "ECC", "name": "ECDSA P-521", "pqc": False},
    "ECC_SECG_P256K1": {"family": "ECC", "name": "ECDSA secp256k1", "pqc": False},
    "ECC_NIST_EDWARDS25519": {"family": "ECC", "name": "Ed25519", "pqc": False},
    "SYMMETRIC_DEFAULT": {"family": "SYMMETRIC", "name": "AES-256", "pqc": True},
    "HMAC_224": {"family": "HMAC", "name": "HMAC-SHA224", "pqc": True},
    "HMAC_256": {"family": "HMAC", "name": "HMAC-SHA256", "pqc": True},
    "HMAC_384": {"family": "HMAC", "name": "HMAC-SHA384", "pqc": True},
    "HMAC_512": {"family": "HMAC", "name": "HMAC-SHA512", "pqc": True},
    "SM2": {"family": "ECC", "name": "SM2", "pqc": False},
    "ML_DSA_44": {"family": "PQC", "name": "ML-DSA-44", "pqc": True},
    "ML_DSA_65": {"family": "PQC", "name": "ML-DSA-65", "pqc": True},
    "ML_DSA_87": {"family": "PQC", "name": "ML-DSA-87", "pqc": True},
}


def scan_kms(regions=None):
    if regions is None:
        regions = ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'sa-east-1']
    all_kms_reports = []
    for region in regions:
        kms = boto3.client('kms', region_name=region)        
        paginator = kms.get_paginator('list_keys')
        for page in paginator.paginate():
            keys = page['Keys']
            for key in keys:
                key_report = {}
                key_id = key['KeyId']
                key_desc = kms.describe_key(KeyId=key_id)
                key_metadata = key_desc["KeyMetadata"]
                key_spec = key_metadata['KeySpec']
                fallback = {
                    "family": "UNKNOWN",
                    "name" : key_spec,
                    "pqc" : False,
                }
                meta = KEYSPEC_METADATA.get(key_spec, fallback)
                key_report = {
                    "region": region,
                    "key_id": key_id,
                    "creation_date": key_desc["KeyMetadata"]["CreationDate"],
                    "key_spec": key_spec,
                    "algorithm_family": meta["family"],
                    "algorithm_name": meta["name"],
                    "is_pqc_compatible": meta["pqc"],
                }
                all_kms_reports.append(key_report)
    
    return all_kms_reports

def scan_acm(regions: List, session=None):
    if session is None:
        session = boto3.session.Session()
    if regions is None:
        regions = session.get_available_regions("acm")
    all_certs = []
    for region in regions:
        acm = session.client('acm', region_name=region)
        paginator = acm.get_paginator("list_certificates")
        for page in paginator.paginate(CertificateStatuses=["PENDING_VALIDATION","ISSUED","INACTIVE","EXPIRED","VALIDATION_TIMED_OUT","REVOKED","FAILED"]):
            for cert_summary in page["CertificateSummaryList"]:
                cert_arn = cert_summary["CertificateArn"]
                cert_detail = acm.describe_certificate(CertificateArn=cert_arn)
                cert_data = {
                    "region": region,
                    "certificate_arn": cert_arn,
                    "domain_name": cert_detail.get("DomainName"),
                    "subject_alternative_names": cert_detail.get("SubjectAlternativeNames", []),
                    "status": cert_detail.get("Status"),
                    "type": cert_detail.get("Type"),
                    "key_algorithm": cert_detail.get("KeyAlgorithm"),
                    "not_before": cert_detail.get("NotBefore"),
                    "not_after": cert_detail.get("NotAfter"),
                    "created_at": cert_detail.get("CreatedAt"),
                    "issued_at": cert_detail.get("IssuedAt"),
                }                
                all_certs.append(cert_data)
    
    return all_certs
            
            
def scan_s3(regions=None):
    if regions is None:
        regions = ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'sa-east-1']
    all_s3_reports = []
    for region in regions:
        s3 = boto3.client('s3', region_name=region)
        try:
            response = s3.list_buckets()
            buckets = response.get('Buckets', [])
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    location_response = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
                    if bucket_region != region and not (bucket_region is None and region == 'us-east-1'):
                        continue
                    encryption_config = None
                    encryption_method = "None"
                    kms_key_id = None
                    is_pqc_compatible = False
                    try:
                        encryption_response = s3.get_bucket_encryption(Bucket=bucket_name)
                        encryption_config = encryption_response.get('ServerSideEncryptionConfiguration', {})
                        if encryption_config and 'Rules' in encryption_config:
                            rule = encryption_config['Rules'][0]
                            sse_config = rule.get('ApplyServerSideEncryptionByDefault', {})
                            encryption_method = sse_config.get('SSEAlgorithm', 'None')
                            kms_key_id = sse_config.get('KMSMasterKeyID')
                            
                            if encryption_method == 'AES256':
                                is_pqc_compatible = True  # AES-256 is quantum-resistant
                            elif encryption_method == 'aws:kms' and kms_key_id:
                                # Need to check the KMS key spec
                                try:
                                    kms = boto3.client('kms', region_name=bucket_region)
                                    key_desc = kms.describe_key(KeyId=kms_key_id)
                                    key_spec = key_desc['KeyMetadata'].get('KeySpec', 'UNKNOWN')
                                    meta = KEYSPEC_METADATA.get(key_spec, {"pqc": False})
                                    is_pqc_compatible = meta.get("pqc", False)
                                except Exception:
                                    is_pqc_compatible = False
                    
                    except Exception:
                        # No encryption configured
                        pass
                    
                    bucket_report = {
                        "region": bucket_region,
                        "bucket_name": bucket_name,
                        "creation_date": bucket['CreationDate'],
                        "encryption_method": encryption_method,
                        "kms_key_id": kms_key_id,
                        "is_pqc_compatible": is_pqc_compatible,
                        "has_encryption": encryption_method != "None"
                    }
                    all_s3_reports.append(bucket_report)
                    
                except Exception as e:
                    bucket_report = {
                        "region": "unknown",
                        "bucket_name": bucket_name,
                        "creation_date": bucket['CreationDate'],
                        "encryption_method": "error",
                        "kms_key_id": None,
                        "is_pqc_compatible": False,
                        "has_encryption": False,
                        "error": str(e)
                    }
                    all_s3_reports.append(bucket_report)
        
        except Exception as e:
            print(f"Error scanning S3 in region {region}: {str(e)}")
    
    return all_s3_reports

def scan_secrets_manager(regions=None):
    """
    Scan AWS Secrets Manager for cryptographic compliance and PQC readiness.
    
    Args:
        regions (List[str], optional): List of AWS regions to scan. 
                                     Defaults to ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'sa-east-1'] if None.
    
    Returns:
        List[dict]: List of secret reports with encryption and PQC compatibility info.
    """
    if regions is None:
        regions = ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'sa-east-1']
    
    all_secrets_reports = []
    
    for region in regions:
        try:
            secrets_client = boto3.client('secretsmanager', region_name=region)
            paginator = secrets_client.get_paginator('list_secrets')
            
            for page in paginator.paginate():
                secrets = page.get('SecretList', [])
                
                for secret in secrets:
                    secret_report = {}
                    secret_arn = secret['ARN']
                    secret_name = secret['Name']
                    
                    try:
                        # Get detailed secret information
                        secret_details = secrets_client.describe_secret(SecretId=secret_arn)
                        
                        # Extract encryption information
                        kms_key_id = secret_details.get('KmsKeyId')
                        encryption_method = "aws-managed"  # Default for Secrets Manager
                        is_pqc_compatible = True  # AWS managed keys use AES-256 by default
                        algorithm_family = "SYMMETRIC"
                        algorithm_name = "AES-256 (AWS Managed)"
                        
                        # If using customer-managed KMS key, check its specifications
                        if kms_key_id:
                            encryption_method = "customer-kms"
                            try:
                                kms_client = boto3.client('kms', region_name=region)
                                key_desc = kms_client.describe_key(KeyId=kms_key_id)
                                key_spec = key_desc['KeyMetadata'].get('KeySpec', 'SYMMETRIC_DEFAULT')
                                
                                fallback = {
                                    "family": "UNKNOWN",
                                    "name": key_spec,
                                    "pqc": False,
                                }
                                meta = KEYSPEC_METADATA.get(key_spec, fallback)
                                
                                algorithm_family = meta["family"]
                                algorithm_name = meta["name"]
                                is_pqc_compatible = meta["pqc"]
                                
                            except Exception as e:
                                # If we can't describe the KMS key, assume it's not PQC compatible
                                algorithm_family = "UNKNOWN"
                                algorithm_name = "Unknown KMS Key"
                                is_pqc_compatible = False
                        
                        secret_report = {
                            "region": region,
                            "secret_arn": secret_arn,
                            "secret_name": secret_name,
                            "creation_date": secret_details.get('CreatedDate'),
                            "last_accessed_date": secret_details.get('LastAccessedDate'),
                            "last_changed_date": secret_details.get('LastChangedDate'),
                            "encryption_method": encryption_method,
                            "kms_key_id": kms_key_id,
                            "algorithm_family": algorithm_family,
                            "algorithm_name": algorithm_name,
                            "is_pqc_compatible": is_pqc_compatible,
                            "description": secret_details.get('Description', ''),
                            "tags": secret_details.get('Tags', [])
                        }
                        
                    except Exception as e:
                        # Handle individual secret errors
                        secret_report = {
                            "region": region,
                            "secret_arn": secret_arn,
                            "secret_name": secret_name,
                            "creation_date": secret.get('CreatedDate'),
                            "last_accessed_date": secret.get('LastAccessedDate'),
                            "last_changed_date": secret.get('LastChangedDate'),
                            "encryption_method": "error",
                            "kms_key_id": None,
                            "algorithm_family": "UNKNOWN",
                            "algorithm_name": "Error retrieving details",
                            "is_pqc_compatible": False,
                            "description": secret.get('Description', ''),
                            "tags": [],
                            "error": str(e)
                        }
                    
                    all_secrets_reports.append(secret_report)
                    
        except Exception as e:
            print(f"Error scanning Secrets Manager in region {region}: {str(e)}")
    
    return all_secrets_reports

    







