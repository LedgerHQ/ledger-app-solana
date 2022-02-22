#/bin/sh

sudo docker run --rm -ti -v "$(realpath .):/app" --privileged ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest
