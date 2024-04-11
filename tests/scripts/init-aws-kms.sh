#!/usr/bin/env bash

# Create test keys
awslocal kms create-key \
    --key-spec RSA_4096 \
    --key-usage SIGN_VERIFY

awslocal kms create-key \
    --key-spec ECC_NIST_P256 \
    --key-usage SIGN_VERIFY

awslocal kms create-key \
    --key-spec ECC_NIST_P384 \
    --key-usage SIGN_VERIFY

# Create test keyid aliases ("alias/" prefix is mandatory)
awslocal kms create-alias \
    --alias-name alias/rsa \
    --target-key-id $(awslocal kms list-keys --query "Keys[0].KeyId" --output text)

awslocal kms create-alias \
    --alias-name alias/ecdsa_nistp256 \
    --target-key-id $(awslocal kms list-keys --query "Keys[1].KeyId" --output text)

awslocal kms create-alias \
    --alias-name alias/ecdsa_nistp384 \
    --target-key-id $(awslocal kms list-keys --query "Keys[2].KeyId" --output text)
