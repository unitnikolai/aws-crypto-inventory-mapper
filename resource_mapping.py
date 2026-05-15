import boto3
import json
from typing import List
from typing import List

def scan_rds(regions=None):
    """
    Scan RDS DB instances and Aurora clusters for KMS encryption keys and map
    each resource back to the key's algorithm metadata (family, name, PQC status).

    Returns:
        List[dict]: One entry per DB instance / cluster found in the given regions.
    """
    if regions is None:
        regions = [
            'us-east-1', 'us-west-2', 'us-west-1',
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
            'sa-east-1',
        ]

    all_rds_reports = []

    for region in regions:
        rds = boto3.client('rds', region_name=region)

        # ── DB instances ──────────────────────────────────────────────────────
        try:
            paginator = rds.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for instance in page.get('DBInstances', []):
                    report = _build_rds_report(instance, resource_type='db_instance', region=region)
                    all_rds_reports.append(report)
        except Exception as e:
            print(f"Error scanning RDS DB instances in {region}: {e}")

        # ── Aurora / DB clusters ──────────────────────────────────────────────
        try:
            paginator = rds.get_paginator('describe_db_clusters')
            for page in paginator.paginate():
                for cluster in page.get('DBClusters', []):
                    report = _build_rds_report(cluster, resource_type='db_cluster', region=region)
                    all_rds_reports.append(report)
        except Exception as e:
            print(f"Error scanning RDS DB clusters in {region}: {e}")

    return all_rds_reports


def _build_rds_report(resource: dict, resource_type: str, region: str) -> dict:
    """Resolve KMS key metadata for a single RDS instance or cluster dict."""
    storage_encrypted = resource.get('StorageEncrypted', False)
    kms_key_id = resource.get('KmsKeyId')

    encryption_method = "none"
    algorithm_family = "NONE"
    algorithm_name = "No encryption"
    is_pqc_compatible = False
    key_spec = None

    if storage_encrypted and kms_key_id:
        encryption_method = "aws-kms"
        try:
            kms = boto3.client('kms', region_name=region)
            key_desc = kms.describe_key(KeyId=kms_key_id)
            key_spec = key_desc['KeyMetadata'].get('KeySpec', 'UNKNOWN')
            fallback = {"family": "UNKNOWN", "name": key_spec, "pqc": False}
            meta = KEYSPEC_METADATA.get(key_spec, fallback)
            algorithm_family = meta["family"]
            algorithm_name = meta["name"]
            is_pqc_compatible = meta["pqc"]
        except Exception as e:
            algorithm_family = "UNKNOWN"
            algorithm_name = "Error retrieving key"
            is_pqc_compatible = False
    elif storage_encrypted:
        # Encrypted with an AWS-managed key (no explicit KmsKeyId)
        encryption_method = "aws-managed"
        algorithm_family = "SYMMETRIC"
        algorithm_name = "AES-256 (AWS Managed)"
        is_pqc_compatible = True

    if resource_type == 'db_instance':
        identifier = resource.get('DBInstanceIdentifier')
        arn = resource.get('DBInstanceArn')
        engine = resource.get('Engine')
        engine_version = resource.get('EngineVersion')
        status = resource.get('DBInstanceStatus')
        instance_class = resource.get('DBInstanceClass')
        creation_time = resource.get('InstanceCreateTime')
    else:  # db_cluster
        identifier = resource.get('DBClusterIdentifier')
        arn = resource.get('DBClusterArn')
        engine = resource.get('Engine')
        engine_version = resource.get('EngineVersion')
        status = resource.get('Status')
        instance_class = None
        creation_time = resource.get('ClusterCreateTime')

    return {
        "region": region,
        "resource_type": resource_type,
        "identifier": identifier,
        "arn": arn,
        "engine": engine,
        "engine_version": engine_version,
        "status": status,
        "instance_class": instance_class,
        "creation_time": creation_time,
        "storage_encrypted": storage_encrypted,
        "encryption_method": encryption_method,
        "kms_key_id": kms_key_id,
        "key_spec": key_spec,
        "algorithm_family": algorithm_family,
        "algorithm_name": algorithm_name,
        "is_pqc_compatible": is_pqc_compatible,
    }

def scan_ebs(regions=None):
    """
    Scan EBS volumes for KMS encryption keys and map each resource back to the
    key's algorithm metadata (family, name, PQC status).

    Returns:
        List[dict]: One entry per EBS volume found in the given regions.
    """
    if regions is None:
        regions = [
            'us-east-1', 'us-west-2', 'us-west-1',
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
            'sa-east-1',
        ]

    all_ebs_reports = []

    for region in regions:
        ec2 = boto3.client('ec2', region_name=region)

        try:
            paginator = ec2.get_paginator('describe_volumes')
            for page in paginator.paginate():
                for volume in page.get('Volumes', []):
                    report = _build_ebs_report(volume, region=region)
                    all_ebs_reports.append(report)
        except Exception as e:
            print(f"Error scanning EBS volumes in {region}: {e}")

    return all_ebs_reports


def _build_ebs_report(volume: dict, region: str) -> dict:
    """Resolve KMS key metadata for a single EBS volume dict."""
    encrypted = volume.get('Encrypted', False)
    kms_key_id = volume.get('KmsKeyId')

    encryption_method = "none"
    algorithm_family = "NONE"
    algorithm_name = "No encryption"
    is_pqc_compatible = False
    key_spec = None

    if encrypted and kms_key_id:
        encryption_method = "aws-kms"
        try:
            kms = boto3.client('kms', region_name=region)
            key_desc = kms.describe_key(KeyId=kms_key_id)
            key_spec = key_desc['KeyMetadata'].get('KeySpec', 'UNKNOWN')
            fallback = {"family": "UNKNOWN", "name": key_spec, "pqc": False}
            meta = KEYSPEC_METADATA.get(key_spec, fallback)
            algorithm_family = meta["family"]
            algorithm_name = meta["name"]
            is_pqc_compatible = meta["pqc"]
        except Exception as e:
            algorithm_family = "UNKNOWN"
            algorithm_name = "Error retrieving key"
            is_pqc_compatible = False
    elif encrypted:
        # Encrypted with an AWS-managed key (no explicit KmsKeyId)
        encryption_method = "aws-managed"
        algorithm_family = "SYMMETRIC"
        algorithm_name = "AES-256 (AWS Managed)"
        is_pqc_compatible = True

    return {
        "region": region,
        "volume_id": volume.get('VolumeId'),
        "encrypted": encrypted,
        "encryption_method": encryption_method,
        "kms_key_id": kms_key_id,
        "key_spec": key_spec,
        "algorithm_family": algorithm_family,
        "algorithm_name": algorithm_name,
        "is_pqc_compatible": is_pqc_compatible,
    }


def build_kms_resource_map(kms_reports, *resource_report_lists):
    """
    Build a map of KMS key ID → key metadata + list of resources using that key.

    Args:
        kms_reports:           Output of scan_kms().
        *resource_report_lists: Any number of resource scan outputs
                                (scan_rds, scan_s3, scan_secrets_manager, …).

    Returns:
        dict: {key_id: {"key_metadata": {...}, "resources": [...]}}
    """
    kms_map = {}

    # Index key metadata by key_id
    for key in kms_reports:
        kms_map[key['key_id']] = {
            "key_metadata": {
                "region": key['region'],
                "key_id": key['key_id'],
                "creation_date": key['creation_date'],
                "key_spec": key['key_spec'],
                "algorithm_family": key['algorithm_family'],
                "algorithm_name": key['algorithm_name'],
                "is_pqc_compatible": key['is_pqc_compatible'],
            },
            "resources": [],
        }

    # Attach resources to their key entries
    for report_list in resource_report_lists:
        for resource in report_list:
            kid = resource.get('kms_key_id')
            if not kid:
                continue
            # Normalise ARN → key ID for direct KMS entries
            # (resource may store the full ARN while kms_map uses the key ID)
            matched_key = kid if kid in kms_map else next(
                (k for k in kms_map if kid.endswith(k)), None
            )
            if matched_key:
                kms_map[matched_key]['resources'].append(resource)
            else:
                # Key used by a resource but not in our KMS scan (cross-account, alias, etc.)
                kms_map.setdefault(kid, {
                    "key_metadata": {"key_id": kid, "note": "key not found in KMS scan"},
                    "resources": [],
                })['resources'].append(resource)

    return kms_map
