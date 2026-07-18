#!/usr/bin/env bash
#
# estctl - RFC 7030 Enrollment over Secure Transport (EST) Client
#

set -eo pipefail

# --- Configuration Defaults ---
EST_SERVER="${EST_SERVER:-localhost:8443}"
CONFIG_DIR="/etc/estctl"
STATE_DIR="/var/lib/estctl"

show_help() {
    cat << EOF
Usage: estctl [options] <command> [args]

An RFC 7030 EST client script for certificate lifecycle management.

Options:
  -s, --server <host:port>   EST server address (Default: $EST_SERVER)
  -h, --help                 Show this help message

Commands:
  cacerts                    Retrieve the CA Certificates trust anchor
  enroll                     Enroll a new certificate (requires CSR)
  reenroll                   Renew an existing certificate
  status                     Check current certificate expiration status
EOF
}

cmd_cacerts() {
    echo "[-] Fetching CA certificates from https://${EST_SERVER}/.well-known/est/cacerts ..."
    # Your curl / openssl logic here
}

cmd_enroll() {
    echo "[-] Submitting enrollment request to https://${EST_SERVER}/.well-known/est/simpleenroll ..."
    # Your curl / openssl logic here
}

cmd_reenroll() {
    echo "[-] Submitting re-enrollment request to https://${EST_SERVER}/.well-known/est/simplereenroll ..."
    # Your curl / openssl logic here
}

# --- Parse Global Options ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--server)
            EST_SERVER="$2"
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
            break # First non-option is our command
            ;;
    esac
done

# --- Parse Subcommand ---
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
        cmd_reenroll "$@"
        ;;
    status)
        echo "Checking local cert status..."
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