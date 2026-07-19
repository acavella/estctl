#!/usr/bin/env bash
#
# estctl - RFC 7030 Enrollment over Secure Transport (EST) Client
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

    # Read values using yq
    EST_HOST=$(yq '.server.host' "$CONFIG_FILE")
    EST_PUBLIC_PORT=$(yq '.server.public_port' "$CONFIG_FILE")
    EST_ADMIN_PORT=$(yq '.server.admin_port' "$CONFIG_FILE")
    TLS_VERIFY=$(yq '.server.tls_verify' "$CONFIG_FILE")
    
    CONFIG_DIR=$(yq '.paths.config_dir' "$CONFIG_FILE")
    STATE_DIR=$(yq '.paths.state_dir' "$CONFIG_FILE")
    CERTS_DIR=$(yq '.paths.certs_dir' "$CONFIG_FILE")
    PRIV_KEY=$(yq '.paths.private_key' "$CONFIG_FILE")
    
    AUTH_METHOD=$(yq '.auth.method' "$CONFIG_FILE")
    AUTH_USER=$(yq '.auth.username' "$CONFIG_FILE")
    AUTH_PASS=$(yq '.auth.password' "$CONFIG_FILE")

    # Cryptographic CSR Variables
    CSR_KEY=$(yq '.csr_defaults.key' "$CONFIG_FILE")
    CSR_HASH=$(yq '.csr_defaults.hash' "$CONFIG_FILE")
    CSR_CN=$(yq '.csr_defaults.cn' "$CONFIG_FILE")

    # Construct the base target addresses
    EST_PUBLIC_SERVER="${EST_HOST}:${EST_PUBLIC_PORT}"
    EST_ADMIN_SERVER="${EST_HOST}:${EST_ADMIN_PORT}"
}

cmd_cacerts() {
    local cacerts_url="https://${EST_PUBLIC_SERVER}/.well-known/est/cacerts"
    local output_p7="${STATE_DIR}/cacerts.p7"
    local output_pem="${CERTS_DIR}/est_ca_trust.pem"
    
    # Ensure target directories exist
    mkdir -p "$STATE_DIR" "$CERTS_DIR"

    # Set curl verification flags based on config
    local curl_opts=("-s" "-S" "-f" "--tlsv1.2")
    if [[ "$TLS_VERIFY" != "true" ]]; then
        curl_opts+=("-k")
    fi

    echo "[-] Fetching CA certificates from ${cacerts_url} ..."
    
    # 1. Fetch the raw PKCS#7 data from the EST server
    if ! curl "${curl_opts[@]}" -o "$output_p7" "$cacerts_url"; then
        echo "Error: Failed to fetch CA certificates from EST server." >&2
        exit 1
    fi

    # Check if the file is empty (some servers return 204 or empty on misconfiguration)
    if [[ ! -s "$output_p7" ]]; then
        echo "Error: Received an empty response from the EST server." >&2
        rm -f "$output_p7"
        exit 1
    fi

    echo "[-] Decoding PKCS#7 certificate bundle..."

    # 2. RFC 7030 allows the response to be base64 wrapped or raw DER. 
    # OpenSSL's pkcs7 tool handles both if we pipe it cleanly, but it expects PEM or DER.
    # We attempt to print it out as clean text/PEM.
    if ! openssl pkcs7 -in "$output_p7" -inform DER -print_certs -out "$output_pem" 2>/dev/null; then
        # If raw DER parsing fails, the server likely returned it as base64-encoded text (PEM-ish)
        if ! openssl pkcs7 -in "$output_p7" -inform PEM -print_certs -out "$output_pem" 2>/dev/null; then
            echo "Error: Failed to parse the received data as a valid PKCS#7 bundle." >&2
            rm -f "$output_p7"
            exit 1
        fi
    fi

    echo "[+] Success! CA certificates stored in PEM format at: ${output_pem}"
    
    # Clean up the raw transit file
    rm -f "$output_p7"
}

cmd_enroll() {
    # Typically, operations like simpleenroll interact with the admin interface
    local enroll_url="https://${EST_ADMIN_SERVER}/.well-known/est/simpleenroll"
    echo "[-] Enrolling via administrative endpoint: ${enroll_url} ..."
    echo "[-] Authentication strategy: ${AUTH_METHOD}"
    # Next step: implementing CSR reading and authentication wrappers
}

# --- Parse Global Options ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--config)
            CONFIG_FILE="$2"
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

# --- Initialize and Execute ---
load_config

COMMAND="$1"
shift 2>/dev/null || true

case "$COMMAND" in
    cacerts)
        cmd_cacerts "$@"
        ;;
    enroll)
        cmd_enroll "$@"
        ;;
    reenroll)
        echo "[-] Re-enrolling..."
        ;;
    "")
        echo "Error: Missing command." >&2
        show_help
        exit 1
        ;;
    *)
        echo "Error: Invalid command '$COMMAND'." >&2
        show_help
        exit 1
        ;;
esac