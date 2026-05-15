import boto3
import json
from typing import List
from typing import List
from resource_mapping import *
from awscompliance import *


def main():
    scan_kms_results = scan_kms('us-east-2')
    scan_acm_results = scan_acm('us-east-2')
    scan_s3_results = scan_s3('us-east-2')
    scan_secrets_results = scan_secrets_manager('us-east-2')
    scan_rds_results = scan_rds('us-east-2')
    kms_resource_map = build_kms_resource_map(
        scan_kms_results,
        scan_rds_results,
        scan_s3_results,
        scan_secrets_results,
    )

    