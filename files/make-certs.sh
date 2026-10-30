#!/bin/sh
# Makes the private CA and the certificates the indexer, Filebeat and the
# dashboard use to talk to each other, on the host, so no key leaves it.
# The distinguished names are the ones the indexer package's opensearch.yml
# already expects. Usage: make-certs.sh DIR SUBJECT_ALT_NAMES
set -eu
dir=$1
san=$2
subject="/C=US/L=California/O=Wazuh/OU=Wazuh/CN="
umask 077
mkdir -p "$dir.new"
cd "$dir.new"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out root-ca-key.pem 2>/dev/null
openssl req -x509 -new -sha256 -days 3650 -key root-ca-key.pem -subj "${subject}Wazuh root CA" -out root-ca.pem

for pair in indexer:node-1 filebeat:wazuh-1 dashboard:dashboard admin:admin; do
  name=${pair%%:*}
  cn=${pair##*:}
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$name-key.pem" 2>/dev/null
  openssl req -new -sha256 -key "$name-key.pem" -subj "$subject$cn" -out "$name.csr"
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\n' "$san" > ext
  openssl x509 -req -sha256 -days 3650 -in "$name.csr" -CA root-ca.pem -CAkey root-ca-key.pem \
    -CAcreateserial -extfile ext -out "$name.pem" 2>/dev/null
done
rm -f ./*.csr ext root-ca.srl
cd ..
mv "$dir.new" "$dir"
