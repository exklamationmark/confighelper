#!/bin/bash
# run this after 'cd internal/tlsconfig/testdata'
set -e -x

# this scripts generates the some files used for testing tlsconfig package
# we want extra RSA and ECDSA keys with password, to test some paths in the code
# what we will do:
# - spawn a vault server for signing RSA keys in the background
#   and create a root CA + intermediate CA
# - issue a key-cert pairs signed by intermediate CA
#   - algo: RSA, key have no password
#   - algo: RSA, key have password= "password"
# - stop vault server
# - spawn a vault server for signing EC keys in the background
#   and create a root CA + intermediate CA.
#   We have to do this because vault either handles RSA or EC
#   - algo: ECDSA, key have no password
#   - algo: ECDSA, key have password= "password"

spawn_vault() {
	local keyType=$1
	local keyBits=$2

	local rootCN=$keyType-root.locol.dev
	local intermediateCN=$keyType-intermediate.locol.dev
	local tmpJSON=$(mktemp)
	local tmpCSR=$(mktemp)

	# spawn vault server
	docker-compose -p locol.dev --file=./vault.yml down --volumes --remove-orphans
	docker-compose -p locol.dev --file=./vault.yml up vault.locol.dev &
	./wait_for_it.sh 127.0.0.1 8200
	export VAULT_ADDR="http://127.0.0.1:8200"
	export VAULT_TOKEN="vault_root_token"

	vault secrets enable pki
	vault secrets tune -max-lease-ttl=87600h pki
	# root CA
	vault write pki/root/generate/internal \
	    common_name=$rootCN \
		key_type=$keyType \
		key_bits=$keyBits \
	    ttl=87600h \
	    --format=json > $tmpJSON
	vault write pki/config/urls \
	    issuing_certificates='http://vault.locol.dev:8200/v1/pki/ca' \
	    crl_distribution_points='http://vault.locol.dev:8200/v1/pki/crl'
	jq -r '.data.certificate' \
	    < $tmpJSON \
	    > $rootCN.certificate.pem
	jq -r '.data.issuing_ca' \
	    < $tmpJSON \
	    > $rootCN.ca-certificate.pem
	jq -r '.data.private_key' \
	    < $tmpJSON \
	    > $rootCN.key.pem
	# intermediate CA
	vault secrets enable -path=pki_int pki
	vault secrets tune -max-lease-ttl=43800h pki_int
	vault write pki_int/intermediate/generate/internal \
	    common_name=$intermediateCN \
	    ttl=43800h \
	    --format=json > $tmpJSON
	jq -r '.data.csr' \
	    < $tmpJSON	\
	    > $tmpCSR
	vault write pki/root/sign-intermediate csr=@$tmpCSR \
	    format=pem_bundle \
	    ttl=43800h \
	    --format=json > $tmpJSON
	jq -r '.data.certificate' \
	    < $tmpJSON \
	    > $intermediateCN.certificate.pem
	jq -r '.data.issuing_ca' \
	    < $tmpJSON \
	    > $intermediateCN.ca-certificate.pem
	jq -r '.data.private_key' \
	    < $tmpJSON \
	    > $intermediateCN.key.pem
	vault write pki_int/intermediate/set-signed certificate=@$intermediateCN.certificate.pem
	cat $rootCN.certificate.pem $intermediateCN.certificate.pem \
		>> $keyType.ca-certificate.pem
	# create role to issue cert
	if [ "$keyType" == "ec" ]
	then
		vault write pki_int/roles/locol \
		    allowed_domains=locol.dev \
		    allow_subdomains=true \
			key_type=$keyType \
			key_bits=$keyBits \
		    max_ttl=72h
	else
		vault write pki_int/roles/locol \
		    allowed_domains=locol.dev \
		    allow_subdomains=true \
		    max_ttl=72h
	fi

	rm $tmpJSON $tmpCSR
}

stop_vault() {
	docker-compose -p locol.dev --file=./vault.yml down --volumes --remove-orphans
}

get_cert_for() {
	local clientID=$1
	local password=$2

	local keyFile=$clientID.key.pem
	local certFile=$clientID.certificate.pem
	local tmpCSR=$(mktemp)
	local tmpJSON=$(mktemp)
	local passIn
	if [ -n "$password" ]
	then
		passIn="-passin pass:$password"
	fi

	openssl req -new \
		-out $tmpCSR \
		-days 365 \
		-subj "/CN=$clientID.client.locol.dev" \
		$passIn \
		-key $keyFile
	vault write pki_int/sign/locol csr=@$tmpCSR \
	    format=pem_bundle \
	    ttl=43800h \
	    --format=json > $tmpJSON
	jq -r '.data.certificate' \
	    < $tmpJSON \
	    > $certFile
	rm $tmpCSR $tmpJSON
}

rm -f *.pem
rm -f *.password
KEY_PASSWORD="password"

# RSA vault
spawn_vault rsa 2048
# RSA listener key
openssl genpkey -algorithm RSA -out rsa-listener.key.pem -pkeyopt rsa_keygen_bits:2048
get_cert_for rsa-listener
# RSA key, no password
openssl genpkey -algorithm RSA -out rsa-no-password.key.pem -pkeyopt rsa_keygen_bits:2048
get_cert_for rsa-no-password
# RSA key with password
# openssl genrsa -aes128 -passout pass:$KEY_PASSWORD -out rsa-with-password.key.pem 2048
openssl rsa -des -in rsa-no-password.key.pem -out rsa-with-password.key.pem -passout pass:$KEY_PASSWORD
sed '$ d' rsa-with-password.key.pem | sed '1,1d' > rsa-with-password-bad.key.pem
echo -n $KEY_PASSWORD > rsa-with-password.key.password
get_cert_for rsa-with-password $KEY_PASSWORD
stop_vault

# EC vault
spawn_vault ec 256
# EC listener key
openssl ecparam -genkey -name prime256v1 -noout -out ec-listener.key.pem
get_cert_for ec-listener
# EC key, no password
openssl ecparam -genkey -name prime256v1 -noout -out ec-no-password.key.pem
get_cert_for ec-no-password
# EC key, with password
openssl ec -in ec-no-password.key.pem -out ec-with-password.key.pem -aes256 -passout pass:$KEY_PASSWORD
sed '$ d' ec-with-password.key.pem | sed '1,1d' > ec-with-password-bad.key.pem
echo -n $KEY_PASSWORD > ec-with-password.key.password
get_cert_for ec-with-password $KEY_PASSWORD
stop_vault

# combine ec.ca-certificate.pem and rsa.ca-certificate.pem for convenience
cat ec.ca-certificate.pem rsa.ca-certificate.pem > ca-certificate.pem

# empty key.password
touch empty.key.password
echo "" > newline.key.password
# wrong key.password
echo -n "wrong password" > wrong.key.password
