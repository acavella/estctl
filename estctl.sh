#!/usr/bin/env bash
#
# estctl.sh - EST Client for Certificate Enrollment and Management
#
# Description: RFC 7030 compliant EST client script for certificate lifecycle management. 
# Author: Tony Cavella <tony@cavella.com>
# Dependencies: yq, curl, openssl, GNU date
# Usage: ./estctl.sh [-c config.yaml] [-p password] {cacerts|enroll|reenroll|status}
#
# Copyright (c) 2026 Tony Cavella <tony@cavella.com>
#
# This source code is licensed under the MIT license.
#

set -eo pipefail

# --- Defaults ---
CONFIG_FILE="config.yaml"

# --- Dependencies Check ---
if ! command -v yq &> /dev/null; then
    echo "Error: 'yq' utility is required to parse YAML configurations but was not found." >&2
    exit 1
fi

if ! command -v curl &> /dev/null; then
    echo "Error: 'curl' utility is required to make HTTP(s) requests but was not found." >&2
    exit 1
fi

if ! command -v openssl &> /dev/null; then
    echo "Error: 'openssl' utility is required to handle PKCS#7 certificates but was not found." >&2
    exit 1
fi

show_help() {
    cat << EOF
Usage: estctl [options] <command> [args]

An RFC 7030 EST client script for certificate lifecycle management.

Options:
  -c, --config <path>        Path to configuration YAML (Default: $CONFIG_FILE)
  -p, --password <string>    Provide basic auth password (skips interactive prompt)
  -h, --help                 Show this help message

Commands:
  cacerts                    Retrieve the CA Certificates trust anchor
  enroll                     Enroll a new certificate (requires CSR)
  reenroll                   Renew an existing certificate
EOF
}

load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "Error: Configuration file not found at $CONFIG_FILE" >&2
        exit 1
    fi

    # Server Core
    EST_HOST=$(yq '.server.host' "$CONFIG_FILE")
    EST_PUBLIC_PORT=$(yq '.server.public_port' "$CONFIG_FILE")
    EST_ADMIN_PORT=$(yq '.server.admin_port' "$CONFIG_FILE")
    TLS_VERIFY=$(yq '.server.tls_verify' "$CONFIG_FILE")
    
    # Endpoints (with RFC 7030 defaults if missing)
    EP_CACERTS=$(yq '.endpoints.cacerts' "$CONFIG_FILE")
    [[ "$EP_CACERTS" == "null" || -z "$EP_CACERTS" ]] && EP_CACERTS=".well-known/est/cacerts"

    EP_ENROLL=$(yq '.endpoints.simpleenroll' "$CONFIG_FILE")
    [[ "$EP_ENROLL" == "null" || -z "$EP_ENROLL" ]] && EP_ENROLL=".well-known/est/simpleenroll"

    EP_REENROLL=$(yq '.endpoints.simplereenroll' "$CONFIG_FILE")
    [[ "$EP_REENROLL" == "null" || -z "$EP_REENROLL" ]] && EP_REENROLL=".well-known/est/simplereenroll"
    
    # Paths
    CONFIG_DIR=$(yq '.paths.config_dir' "$CONFIG_FILE")
    STATE_DIR=$(yq '.paths.state_dir' "$CONFIG_FILE")
    CERTS_DIR=$(yq '.paths.certs_dir' "$CONFIG_FILE")
    PRIV_KEY=$(yq '.paths.private_key' "$CONFIG_FILE")
    BOOTSTRAP_CERT=$(yq '.paths.bootstrap_cert' "$CONFIG_FILE")
    BOOTSTRAP_KEY=$(yq '.paths.bootstrap_key' "$CONFIG_FILE")
    
    # Auth
    ENROLL_AUTH_METHOD=$(yq '.auth.enroll_method' "$CONFIG_FILE")
    REENROLL_AUTH_METHOD=$(yq '.auth.reenroll_method' "$CONFIG_FILE")
    AUTH_USER=$(yq '.auth.username' "$CONFIG_FILE")
    
    # Fallbacks just in case the keys are empty
    [[ "$ENROLL_AUTH_METHOD" == "null" || -z "$ENROLL_AUTH_METHOD" ]] && ENROLL_AUTH_METHOD="basic"
    [[ "$REENROLL_AUTH_METHOD" == "null" || -z "$REENROLL_AUTH_METHOD" ]] && REENROLL_AUTH_METHOD="mtls"

    # Cryptographic CSR Variables
    CSR_KEY=$(yq '.csr_defaults.key' "$CONFIG_FILE")
    CSR_HASH=$(yq '.csr_defaults.hash' "$CONFIG_FILE")
    CSR_CN=$(yq '.csr_defaults.cn' "$CONFIG_FILE")

    # Operations
    RENEW_WARNING_DAYS=$(yq '.operations.renew_warning_days' "$CONFIG_FILE")
    [[ "$RENEW_WARNING_DAYS" == "null" || -z "$RENEW_WARNING_DAYS" ]] && RENEW_WARNING_DAYS=30

    # Targets
    EST_PUBLIC_SERVER="${EST_HOST}:${EST_PUBLIC_PORT}"
    EST_ADMIN_SERVER="${EST_HOST}:${EST_ADMIN_PORT}"
}

generate_key_and_csr() {
    # Accept an optional argument for the key path, default to standard PRIV_KEY
    local target_key="${1:-$PRIV_KEY}"
    local csr_out="${STATE_DIR}/client.csr"
    
    mkdir -p "$(dirname "$target_key")" "$STATE_DIR"

    echo "[-] Generating private key and CSR (${CSR_CN}) via OpenSSL..."

    case "$CSR_HASH" in
        sha256|sha384) ;;
        *) echo "Error: Unsupported hash type '$CSR_HASH'." >&2; exit 1 ;;
    esac

    case "$CSR_KEY" in
        rsa2048)
            openssl req -new -newkey rsa:2048 -nodes -keyout "$target_key" -out "$csr_out" \
                -"$CSR_HASH" -subj "/CN=${CSR_CN}" 2>/dev/null ;;
        rsa3072)
            openssl req -new -newkey rsa:3072 -nodes -keyout "$target_key" -out "$csr_out" \
                -"$CSR_HASH" -subj "/CN=${CSR_CN}" 2>/dev/null ;;
        rsa4096)
            openssl req -new -newkey rsa:4096 -nodes -keyout "$target_key" -out "$csr_out" \
                -"$CSR_HASH" -subj "/CN=${CSR_CN}" 2>/dev/null ;;
        secp384r1)
            openssl req -new -newkey ec:<(openssl ecparam -name secp384r1) -nodes -keyout "$target_key" \
                -out "$csr_out" -"$CSR_HASH" -subj "/CN=${CSR_CN}" 2>/dev/null ;;
        *)
            echo "Error: Unsupported key type '$CSR_KEY'." >&2; exit 1 ;;
    esac

    echo "[+] Private key securely saved to: $target_key"
    echo "[+] CSR generated at: $csr_out"
}

cmd_cacerts() {
    # Dynamically inject the endpoint, stripping any errant leading slash
    local cacerts_url="https://${EST_PUBLIC_SERVER}/${EP_CACERTS#/}"
    local output_p7="${STATE_DIR}/cacerts.p7"
    local output_pem="${CERTS_DIR}/est_ca_trust.pem"
    
    mkdir -p "$STATE_DIR" "$CERTS_DIR"

    local curl_opts=("-s" "-S" "-f")
    if [[ "$TLS_VERIFY" != "true" ]]; then
        curl_opts+=("-k")
    fi

    echo "[-] Fetching CA certificates from ${cacerts_url} ..."
    
    if ! curl "${curl_opts[@]}" -o "$output_p7" "$cacerts_url"; then
        echo "Error: Failed to fetch CA certificates from EST server." >&2
        exit 1
    fi

    if [[ ! -s "$output_p7" ]]; then
        echo "Error: Received an empty response from the EST server." >&2
        rm -f "$output_p7"
        exit 1
    fi

    echo "[-] Decoding PKCS#7 certificate bundle..."

    if ! openssl pkcs7 -in "$output_p7" -inform DER -print_certs -out "$output_pem" 2>/dev/null; then
        if ! openssl pkcs7 -in "$output_p7" -inform PEM -print_certs -out "$output_pem" 2>/dev/null; then
            echo "Error: Failed to parse the received data as a valid PKCS#7 bundle." >&2
            rm -f "$output_p7"
            exit 1
        fi
    fi

    echo "[+] Success! CA certificates stored in PEM format at: ${output_pem}"
    rm -f "$output_p7"
}

cmd_enroll() {
    local target_server
    if [[ "$ENROLL_AUTH_METHOD" == "basic" ]]; then
        target_server="$EST_PUBLIC_SERVER"
    elif [[ "$ENROLL_AUTH_METHOD" == "mtls" ]]; then
        target_server="$EST_ADMIN_SERVER"
    else
        echo "Error: Unknown enroll auth method '$ENROLL_AUTH_METHOD'." >&2
        exit 1
    fi

    # Dynamically inject the enrollment endpoint, stripping any errant leading slash
    local enroll_url="https://${target_server}/${EP_ENROLL#/}"
    local csr_file="${STATE_DIR}/client.csr"
    local b64_csr="${STATE_DIR}/client.b64"
    local output_p7="${STATE_DIR}/enrolled_cert.p7"
    local output_pem="${CERTS_DIR}/est_client.pem"

    generate_key_and_csr

    # Strip PEM headers for EST RFC 7030 strict compliance
    grep -v '^-' "$csr_file" > "$b64_csr"

    echo "[-] Executing simpleenroll request to ${enroll_url} ..."

    local curl_opts=("-s" "-S" "-f" "-X" "POST")
    curl_opts+=("-H" "Content-Type: application/pkcs10")
    curl_opts+=("--data-binary" "@${b64_csr}")

    if [[ "$TLS_VERIFY" != "true" ]]; then
        curl_opts+=("-k")
    fi

    if [[ "$ENROLL_AUTH_METHOD" == "basic" ]]; then
        echo "[-] Authenticating via HTTP Basic Auth."
        
        local enroll_pass="$CLI_PASS"
        if [[ -z "$enroll_pass" ]]; then
            read -r -s -p "Enter basic auth password for '${AUTH_USER}': " enroll_pass
            echo ""
        fi

        if [[ -z "$enroll_pass" ]]; then
            echo "Error: Password is required for HTTP Basic Authentication." >&2
            rm -f "$b64_csr"
            exit 1
        fi

        curl_opts+=("-u" "${AUTH_USER}:${enroll_pass}")
        
    elif [[ "$ENROLL_AUTH_METHOD" == "mtls" ]]; then
        if [[ ! -f "$BOOTSTRAP_CERT" || ! -f "$BOOTSTRAP_KEY" ]]; then
            echo "Error: mTLS selected but bootstrap credentials not found." >&2
            rm -f "$b64_csr"
            exit 1
        fi
        
        echo "[-] Authenticating via mTLS using bootstrap credentials."
        curl_opts+=("--cert" "$BOOTSTRAP_CERT" "--key" "$BOOTSTRAP_KEY")
    fi

    if ! curl "${curl_opts[@]}" -o "$output_p7" "$enroll_url"; then
        echo "Error: simpleenroll request failed." >&2
        rm -f "$b64_csr"
        exit 1
    fi

    echo "[-] Decoding returned PKCS#7 client certificate..."

    if ! openssl pkcs7 -in "$output_p7" -inform DER -print_certs -out "$output_pem" 2>/dev/null; then
        if ! openssl pkcs7 -in "$output_p7" -inform PEM -print_certs -out "$output_pem" 2>/dev/null; then
            echo "Error: Failed to parse the received client certificate." >&2
            rm -f "$b64_csr" "$output_p7"
            exit 1
        fi
    fi

    echo "[+] Success! Enrolled certificate stored at: ${output_pem}"
    
    rm -f "$b64_csr" "$output_p7"
}

cmd_reenroll() {
    local target_server
    if [[ "$REENROLL_AUTH_METHOD" == "basic" ]]; then
        target_server="$EST_PUBLIC_SERVER"
    elif [[ "$REENROLL_AUTH_METHOD" == "mtls" ]]; then
        target_server="$EST_ADMIN_SERVER"
    else
        echo "Error: Unknown re-enroll auth method '$REENROLL_AUTH_METHOD'." >&2
        exit 1
    fi

    # Dynamically inject the re-enrollment endpoint
    local reenroll_url="https://${target_server}/${EP_REENROLL#/}"
    local csr_file="${STATE_DIR}/client.csr"
    local b64_csr="${STATE_DIR}/client.b64"
    local output_p7="${STATE_DIR}/enrolled_cert.p7"
    
    # Define current and temporary paths for safe rotation
    local current_pem="${CERTS_DIR}/est_client.pem"
    local current_key="${PRIV_KEY}"
    local new_pem="${CERTS_DIR}/est_client.pem.new"
    local new_key="${PRIV_KEY}.new"

    # Generate the new key securely to a temporary file
    generate_key_and_csr "$new_key"

    grep -v '^-' "$csr_file" > "$b64_csr"

    echo "[-] Executing simplereenroll request to ${reenroll_url} ..."

    local curl_opts=("-s" "-S" "-f" "-X" "POST")
    curl_opts+=("-H" "Content-Type: application/pkcs10")
    curl_opts+=("--data-binary" "@${b64_csr}")

    if [[ "$TLS_VERIFY" != "true" ]]; then
        curl_opts+=("-k")
    fi

    if [[ "$REENROLL_AUTH_METHOD" == "basic" ]]; then
        echo "[-] Authenticating via HTTP Basic Auth."
        
        local enroll_pass="$CLI_PASS"
        if [[ -z "$enroll_pass" ]]; then
            read -r -s -p "Enter basic auth password for '${AUTH_USER}': " enroll_pass
            echo ""
        fi

        if [[ -z "$enroll_pass" ]]; then
            echo "Error: Password is required for HTTP Basic Authentication." >&2
            rm -f "$b64_csr" "$new_key"
            exit 1
        fi

        curl_opts+=("-u" "${AUTH_USER}:${enroll_pass}")
        
    elif [[ "$AUTH_METHOD" == "mtls" ]]; then
        # For RE-enrollment, we authenticate with the currently active certificate, NOT the bootstrap
        if [[ ! -f "$current_pem" || ! -f "$current_key" ]]; then
            echo "Error: Current certificate or key missing. Cannot perform mTLS re-enrollment." >&2
            rm -f "$b64_csr" "$new_key"
            exit 1
        fi
        
        echo "[-] Authenticating via mTLS using existing client certificate."
        curl_opts+=("--cert" "$current_pem" "--key" "$current_key")
    fi

    if ! curl "${curl_opts[@]}" -o "$output_p7" "$reenroll_url"; then
        echo "Error: simplereenroll request failed." >&2
        rm -f "$b64_csr" "$new_key"
        exit 1
    fi

    echo "[-] Decoding returned PKCS#7 renewed certificate..."

    if ! openssl pkcs7 -in "$output_p7" -inform DER -print_certs -out "$new_pem" 2>/dev/null; then
        if ! openssl pkcs7 -in "$output_p7" -inform PEM -print_certs -out "$new_pem" 2>/dev/null; then
            echo "Error: Failed to parse the received renewed certificate." >&2
            rm -f "$b64_csr" "$output_p7" "$new_key"
            exit 1
        fi
    fi

    # Atomic swap: Commit the new keys into production
    mv -f "$new_key" "$current_key"
    mv -f "$new_pem" "$current_pem"

    echo "[+] Success! Renewed certificate and rotated key stored at:"
    echo "    Cert: $current_pem"
    echo "    Key : $current_key"
    
    rm -f "$b64_csr" "$output_p7"
}

cmd_status() {
    local cert_file="${CERTS_DIR}/est_client.pem"
    
    # 1. Ensure the certificate exists
    if [[ ! -f "$cert_file" ]]; then
        echo "Error: Certificate not found at $cert_file" >&2
        echo "The node may not be enrolled yet." >&2
        exit 1
    fi

    # 2. Extract certificate metadata
    local subject
    local issuer
    local expiration_date
    subject=$(openssl x509 -subject -noout -in "$cert_file" | sed 's/^subject=//')
    issuer=$(openssl x509 -issuer -noout -in "$cert_file" | sed 's/^issuer=//')
    expiration_date=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)

    if [[ -z "$expiration_date" ]]; then
        echo "Error: Could not parse expiration date from $cert_file" >&2
        exit 1
    fi

    # 3. Convert dates to Unix Epoch for math
    local exp_epoch
    local now_epoch
    exp_epoch=$(date -d "$expiration_date" +%s 2>/dev/null) || {
        echo "Error: Could not parse date string '$expiration_date'. Ensure GNU date is installed." >&2
        exit 1
    }
    now_epoch=$(date +%s)

    # 4. Calculate the delta
    local diff_sec=$(( exp_epoch - now_epoch ))
    local days_remaining=$(( diff_sec / 86400 ))

    # 5. Output the results
    echo "[-] Certificate Status"
    echo "    File:        $cert_file"
    echo "    Subject:    $subject"
    echo "    Issuer:     $issuer"
    echo "    Valid Until: $expiration_date"

    # 6. Evaluate health against the configured threshold
    if [[ $days_remaining -lt 0 ]]; then
        echo "    State:       [ EXPIRED ] ($(( -days_remaining )) days ago)"
        exit 2 
    elif [[ $days_remaining -le "$RENEW_WARNING_DAYS" ]]; then
        echo "    State:       [ WARNING ] ($days_remaining days remaining - within $RENEW_WARNING_DAYS day threshold)"
        # Note: You can change this to exit 3 or another code if your monitoring system needs a distinct "warning" state
    else
        echo "    State:       [ VALID ] ($days_remaining days remaining)"
    fi
    
    exit 0
}

# --- Main Runtime Routing ---
CLI_PASS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -p|--password)
            CLI_PASS="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -*)
            echo "Error: Unknown option $1" >&2
            show_help
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

load_config

case "$1" in
    cacerts)
        cmd_cacerts
        ;;
    enroll)
        cmd_enroll
        ;;
    reenroll)
        cmd_reenroll
        ;;
    status)
        cmd_status
        ;;
    *)
        echo "Usage: estctl [-c config.yaml] [-p password] {cacerts|enroll|reenroll|status}" >&2
        exit 1
        ;;
esac