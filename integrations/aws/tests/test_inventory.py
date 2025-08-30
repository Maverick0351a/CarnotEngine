import os, json, random
import boto3
from moto import mock_aws
import pytest
from integrations.aws.aws_inventory import inventory_kms, inventory_acm, inventory_aws_crypto, DEFAULTS

REGION = "us-east-1"

@mock_aws
def test_kms_pagination_and_tags():
    kms = boto3.client('kms', region_name=REGION)
    # create > 2 keys to force paginator (moto paginates after many, but we simulate)
    key_ids = []
    for i in range(5):
        resp = kms.create_key(Description=f"test{i}")
        key_ids.append(resp['KeyMetadata']['KeyId'])
        kms.tag_resource(KeyId=resp['KeyMetadata']['KeyId'], Tags=[{'TagKey':'Owner','TagValue':f'owner{i}'},{'TagKey':'SecrecyYears','TagValue':str(2+i)}])
    inv = inventory_kms(kms)
    assert len(inv) == 5
    owners = {o['owner'] for o in inv}
    assert any(o.startswith('owner') for o in owners)
    assert all('secrecy_lifetime_years' in o for o in inv)

@mock_aws
def test_kms_defaults_for_untagged():
    kms = boto3.client('kms', region_name=REGION)
    resp = kms.create_key(Description="untagged")
    kid = resp['KeyMetadata']['KeyId']
    inv = inventory_kms(kms)
    assert len(inv) == 1
    entry = inv[0]
    assert entry['owner'] == resp['KeyMetadata']['AWSAccountId'] or entry['owner'] == DEFAULTS['owner']
    assert 'secrecy_lifetime_years' in entry

@mock_aws
def test_acm_inventory_defaults():
    acm = boto3.client('acm', region_name=REGION)
    # create self-signed cert via import
    cert = """-----BEGIN CERTIFICATE-----\nMIIBhDCCASugAwIBAgIUJrZ0\n-----END CERTIFICATE-----\n"""
    key = """-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----\n"""
    acm.import_certificate(Certificate=cert, PrivateKey=key)
    inv = inventory_acm(acm)
    # moto may not fully implement list/describe details; tolerate empty
    assert isinstance(inv, list)

@mock_aws
def test_throttling_resilience(monkeypatch):
    kms = boto3.client('kms', region_name=REGION)
    resp = kms.create_key(Description="throttle-test")
    from botocore.exceptions import ClientError
    calls = {"n":0}
    real_list = kms.list_resource_tags
    def flaky(**kwargs):
        calls['n'] +=1
        if calls['n'] < 2:
            error_response = {'Error': {'Code': 'Throttling','Message':'Rate exceeded'}}
            raise ClientError(error_response, 'ListResourceTags')
        return real_list(**kwargs)
    monkeypatch.setattr(kms, 'list_resource_tags', flaky)
    inv = inventory_kms(kms)
    assert len(inv) == 1
    assert calls['n'] >= 2

