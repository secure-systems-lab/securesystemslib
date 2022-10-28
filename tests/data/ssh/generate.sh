#!/usr/bin/env sh

types="ecdsa ed25519 rsa"  # dsa

for t in $types; do
    yes | ssh-keygen -t $t -C "$t key" -N "" -f ./$t;
done
