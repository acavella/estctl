#!/usr/bin/env bash
#
# estctl - RFC 7030 Enrollment over Secure Transport (EST) Client
#

set -eo pipefail

# --- Defaults ---
CONFIG_FILE="/etc/estctl/config.yaml"

# --- Dependencies Check ---
if ! command -v yq &> /dev/null; then
    echo "Error: 'yq' utility is required to parse YAML configurations but was not found." >&2
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
    EST_PORT=$(yq '.server.port' "$CONFIG_FILE")
    TLS_VERIFY=$(yq '.server.tls_verify' "$CONFIG_FILE")
    
    CONFIG_DIR=$(yq '.paths.config_dir' "$CONFIG_FILE")
    STATE_DIR=$(yq '.paths.state_dir' "$CONFIG_FILE")
    CERTS_DIR=$(yq '.paths.certs_dir' "$CONFIG_FILE")
    PRIV_KEY=$(yq '.paths.private_key' "$CONFIG_FILE")
    
    AUTH_METHOD=$(yq '.auth.method' "$CONFIG_FILE")
    AUTH_USER=$(yq '.auth.username' "$CONFIG_FILE")
    AUTH_PASS=$(yq '.auth.password' "$CONFIG_FILE")

    # Construct the base URL
    EST_SERVER="${EST_HOST}:${EST_PORT}"
}

cmd_cacerts() {
    echo "[-] Fetching CA certificates from https://${EST_SERVER}/.well-known/est/cacerts ..."
    # curl / openssl logic goes here using loaded variables
}

cmd_enroll() {
    echo "[-] Enrolling via https://${EST_SERVER}/.well-known/est/simpleenroll ..."
    echo "[-] Using authentication method: ${AUTH_METHOD}"
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