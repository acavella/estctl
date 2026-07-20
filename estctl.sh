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

    # Read values using yq
    EST_HOST=$(yq '.server.host' "$CONFIG_FILE")
    EST_PUBLIC_PORT=$(yq '.server.public_port' "$CONFIG_FILE")
    EST_ADMIN_PORT=$(yq '.server.admin_port' "$CONFIG_FILE")
    TLS_VERIFY=$(yq '.server.tls_verify' "$CONFIG_FILE")
    
    CONFIG_DIR=$(yq '.paths.config_dir' "$CONFIG_FILE")
    STATE_DIR=$(yq '.paths.state_dir' "$CONFIG_FILE")
    CERTS_DIR=$(yq '.paths.certs_dir' "$CONFIG_FILE")
    PRIV_KEY=$(yq '.paths.private_key' "$CONFIG_FILE")
    BOOTSTRAP_CERT=$(yq '.paths.bootstrap_cert' "$CONFIG_FILE")
    BOOTSTRAP_KEY=$(yq '.paths.bootstrap_key' "$CONFIG_FILE")
    
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

generate_key_and_csr() {
    local csr_out="${STATE_DIR}/client.csr"
    mkdir -p "$(dirname "$PRIV_KEY")" "$STATE_DIR"

    echo "[-] Generating private key and CSR (${CSR_CN}) via OpenSSL..."

    # 1. Validate hash strength
    case "$CSR_HASH" in
        sha256|sha384) ;;
        *) echo "Error: Unsupported hash type '$CSR_HASH'. Choose sha256 or sha384." >&2; exit 1 ;;
    esac

    # 2. Generate based on key type selection
    case "$CSR_KEY" in
        rsa2048)
            openssl req -new -newkey rsa:2048 -nodes -keyout "$PRIV_KEY" -out "$csr_out" \
                -"$CSR_HASH" -subj "/CN=${CSR_CN}" 2>/dev/null
            ;;
        rsa3072)
            openssl req -new -newkey rsa:3072 -nodes -keyout "$PRIV_KEY" -out "$csr_out" \
                -"$CSR_HASH" -subj "/CN=${CSR_CN}" 2>/dev/null
            ;;
        rsa4096)
            openssl req -new -newkey rsa:4096 -nodes -keyout "$PRIV_KEY" -out "$csr_out" \
                -"$CSR_HASH" -subj "/CN=${CSR_CN}" 2>/dev/null
            ;;
        secp384r1)
            # Elliptic Curve keys require creating parameters or explicit curve targeting
            openssl req -new -newkey ec:<(openssl ecparam -name secp384r1) -nodes -keyout "$PRIV_KEY" \
                -out "$csr_out" -"$CSR_HASH" -subj "/CN=${CSR_CN}" 2>/dev/null
            ;;
        *)
            echo "Error: Unsupported key type '$CSR_KEY'. Choose rsa2048, rsa3072, rsa4096, or secp384r1." >&2
            exit 1
            ;;
    esac

    echo "[+] Private key securely saved to: $PRIV_KEY"
    echo "[+] CSR generated at: $csr_out"
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
    # 1. Determine target server based on authentication method
    local target_server
    if [[ "$AUTH_METHOD" == "basic" ]]; then
        target_server="$EST_PUBLIC_SERVER"
    elif [[ "$AUTH_METHOD" == "mtls" ]]; then
        target_server="$EST_ADMIN_SERVER"
    else
        echo "Error: Unknown auth method '$AUTH_METHOD'. Must be 'basic' or 'mtls'." >&2
        exit 1
    fi

    local enroll_url="https://${target_server}/.well-known/est/simpleenroll"
    local csr_file="${STATE_DIR}/client.csr"
    local b64_csr="${STATE_DIR}/client.b64"
    local output_p7="${STATE_DIR}/enrolled_cert.p7"
    local output_pem="${CERTS_DIR}/est_client.pem"

    # 2. Run dynamic key and CSR generation
    generate_key_and_csr

    # 3. Strip PEM headers for EST RFC 7030 strict compliance
    grep -v '^-' "$csr_file" > "$b64_csr"

    echo "[-] Executing simpleenroll request to ${enroll_url} ..."

    # 4. Prepare base curl options
    local curl_opts=("-s" "-S" "-f" "-X" "POST")
    curl_opts+=("-H" "Content-Type: application/pkcs10")
    curl_opts+=("--data-binary" "@${b64_csr}")

    if [[ "$TLS_VERIFY" != "true" ]]; then
        curl_opts+=("-k")
    fi

    # 5. Append authentication-specific curl flags
    if [[ "$AUTH_METHOD" == "basic" ]]; then
        echo "[-] Authenticating via HTTP Basic Auth."
        curl_opts+=("-u" "${AUTH_USER}:${AUTH_PASS}")
        
    elif [[ "$AUTH_METHOD" == "mtls" ]]; then
        if [[ ! -f "$BOOTSTRAP_CERT" || ! -f "$BOOTSTRAP_KEY" ]]; then
            echo "Error: mTLS selected but bootstrap credentials not found." >&2
            echo "   Checked Cert: $BOOTSTRAP_CERT" >&2
            echo "   Checked Key : $BOOTSTRAP_KEY" >&2
            rm -f "$b64_csr"
            exit 1
        fi
        
        echo "[-] Authenticating via mTLS using bootstrap credentials."
        curl_opts+=("--cert" "$BOOTSTRAP_CERT" "--key" "$BOOTSTRAP_KEY")
    fi

    # 6. Execute transport
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
    
    # Clean up transient files
    rm -f "$b64_csr" "$output_p7"
}

# --- Main Runtime Routing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--config) CONFIG_FILE="$2"; shift 2 ;;
        *) break ;;
    esac
done

load_config

case "$1" in
    cacerts) cmd_cacerts ;;
    enroll)  cmd_enroll ;;
    *)       echo "Usage: estctl [-c config.yaml] {cacerts|enroll}" >&2; exit 1 ;;
esac