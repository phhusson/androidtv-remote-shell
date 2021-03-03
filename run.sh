#!/bin/bash

SERVER=192.168.1.30

if [ ! -f server.pub ];then
	# This will trigger a fail server side because we send no client certificate, but meh
	openssl s_client -connect "$SERVER":6467 | openssl x509 -pubkey -noout > server.pub
fi

if [ ! -f key.pem ] || [ ! -f cert.pem ];then
	openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -days $((365*30)) -subj '/CN=anymote\/phhproduct\/phhdevice\/phhmodel\/5554463/'
	openssl rsa -in key.pem -pubout > key.pub
fi

jsonsize() {
	len="$(echo -n "$1" | wc -c)"
	len=$(printf '%08x' $len)
	(echo $len | xxd -r -p ; echo -n "$1") > request
	(echo $len | xxd -r -p ; echo -n "$1")
}

# Do this once to pair locale certificate with AndroidTV device
if false;then
(
# Pairing request
jsonsize '{"status":200,"type":10, "payload": {"service_name": "phh", "client_name": "Phh"}}'

# TODO: Receive type 11 = Pairing request ACK 

# Roles: 0 = unknown, 1 = input, 2 = display
# Encodings: 0 = unknown, 1 = alphanumeric, 2 = numeric, 3 = hexadecimal, 4 = qrcode
 jsonsize '{"status":200,"type":20, "payload": {"input_encodings":[{"type":1,"symbol_length":10}], "output_encodings":[{"type":1,"symbol_length":10}], "preferred_role":1}}'

# TODO: Receive type 20 = OPTIONS


# Configuration send actual encoding and role
 jsonsize '{"status":200,"type":30, "payload": {"encoding": {"type":3, "symbol_length":4}, "client_role":1}}'

 # Send passcode
 read pass
 nonce="$(echo "$pass" |grep -oE '..$')"
 gammaCheck="$(echo "$pass" |grep -oE '^..')"

 result="$(
 (

 	openssl rsa -pubin -inform PEM -text -noout < key.pub  |grep -A 100 Modulus |grep -v Expon |tail -n +2 |tr -d '\n: ' |sed -E 's/^(00)*//g' | xxd -r -p
	 (echo -n 0; openssl rsa -pubin -inform PEM -text -noout < key.pub  |sed -nE 's/.*Exponent:.*0x([0-9a-fA-F]*).*/\1/p') | xxd -r -p

	 openssl rsa -pubin -inform PEM -text -noout < server.pub  |grep -A 100 Modulus |grep -v Expon |tail -n +2 |tr -d '\n: ' |sed -E 's/^(00)*//g' | xxd -r -p
	 # the "0" here is because openssl command will output 0x10001, which is 5 digits, but we ned a pair number of digits
	 (echo -n 0; openssl rsa -pubin -inform PEM -text -noout < server.pub  |sed -nE 's/.*Exponent:.*0x([0-9a-fA-F]*).*/\1/p') | xxd -r -p

	 echo -n "$nonce" | xxd -r -p
 )|sha256sum |grep -oE '^[0-9a-fA-F]*')"
 resultGamma="$(echo "$result" |grep -oE '^..')"

echo "Received gamma $gammaCheck expected $resultGamma" >&2

jsonsize '{"status":200,"type":40, "payload": {"secret":"'$(echo "$result" |xxd -r -p |base64)'"}}'

 # TODO: Receive secret ACK

) | openssl s_client -cert cert.pem -key key.pem -quiet -connect "$SERVER":6467 > result
fi

(
# Commands format is [version] [cmdid] [MSB additional len] [LSB additional len] .... 

# Configure screen 1024x1024, one pointer, input mode 2
echo '01 00 00 0c 00 00 04 00 00 00 04 00 01 02 00 00' | xxd -r -p

sleep 1
# Mark client as active (probably useless)
# echo '01 13 00 01 01' |xxd -r -p 
# sleep .1

# Send KEYACTION_DOWN (01) for KEYCODE_HOME (3)
echo '01 02 00 10 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 03' | xxd -r -p

#Send KEYACTION_UP (00) for KEYCODE_HOME (3)
echo '01 02 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03' |xxd -r -p

sleep 1

#Send an intent
echo '01 10 00 52' | xxd -r -p ; echo -n 'android-app://com.android.tv.settings/#Intent;action=android.settings.SETTINGS;end'

#Send a string
# echo '01 0f 00 05' | xxd -r -p ; echo -n 'hello'

) | openssl s_client -cert cert.pem -key key.pem -quiet -connect 192.168.1.30:6466
