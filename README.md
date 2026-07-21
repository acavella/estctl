# estctl

A lightweight, RFC 7030-compliant Enrollment over Secure Transport (EST) client written in pure Bash.

Designed for enterprise Linux environments and DevOps automation, estctl handles initial node provisioning via HTTP Basic Authentication and subsequent secure renewals via mTLS, featuring atomic key rotation to prevent authentication lockouts.

## Features

- RFC 7030 Compliant: Strictly adheres to EST payload requirements (e.g., stripping PEM boundaries for application/pkcs10 POST bodies).
- Split Authentication Routing: Supports independent authentication methods for initial enrollment (Basic Auth) and re-enrollment (mTLS).
- Atomic Key Rotation: Securely generates new private keys to a temporary file during simplereenroll, rotating them into production only after the EST server successfully returns the renewed certificate.
- Dynamic Configuration: Fully driven by a YAML configuration file, allowing custom cryptographic parameters (RSA/ECC) without modifying the core script.
- Monitoring Ready: Built-in status command evaluates certificate expiration against configurable warning thresholds, exiting with standard codes for easy integration with monitoring agents or systemd timers.
- Automatic Renewal: Automatically execute simplereenroll based on defined certificate warning and renewal thresholds ensuring you never have an expired system certificate.

## Prerequisites

- bash (v4.0+)
- curl
- openssl
- yq (Mike Farah's Go-based YAML processor)
- GNU date (coreutils)

## Installation

1. Clone the repository and place the script in your system path:

    ``` bash
    git clone https://github.com/acavella/estctl.git
    cd estctl
    sudo cp estctl /usr/local/bin/estctl
    sudo chmod +x /usr/local/bin/estctl
    ```

2. Create the configuration and state directories:

    ``` bash
    sudo mkdir -p /etc/estctl /var/lib/estctl
    ```

3. Copy the example configuration file:

    ``` bash
    sudo cp config.example.yaml /etc/estctl/config.yaml
    sudo chmod 600 /etc/estctl/config.yaml
    ```

## Configuration

estctl reads from `/etc/estctl/config.yaml` by default. You can define server targets, authentication methods, and cryptographic request parameters.

``` yaml
server:
  host: "est.example.com"
  public_port: 443
  admin_port: 8443
  tls_verify: true

endpoints:
  cacerts: ".well-known/est/cacerts"
  simpleenroll: ".well-known/est/simpleenroll"
  simplereenroll: ".well-known/est/simplereenroll"

paths:
  config_dir: "/etc/estctl"
  state_dir: "/var/lib/estctl"
  certs_dir: "/etc/pki/tls/certs"
  private_key: "/etc/pki/tls/private/est_client.key"
  bootstrap_cert: "/etc/pki/tls/certs/bootstrap.pem"
  bootstrap_key: "/etc/pki/tls/private/bootstrap.key"

auth:
  enroll_method: "basic"    # basic or mtls
  reenroll_method: "mtls"   # basic or mtls
  username: "est_user"

csr_defaults:
  key: "rsa4096"            # Options: rsa2048, rsa3072, rsa4096, secp384r1
  hash: "sha384"            # Options: sha256, sha384
  cn: "endpoint.example.com"

operations:
  renew_warning_days: 30
```

## Usage

1. **Retrieve the CA Trust Anchor** - Fetch the CA certificates from the EST responder to establish initial trust.

    ``` bash
    estctl cacerts
    ```

2. **Initial Enrollment** - Generate a private key and CSR, and submit an enrollment request. If using Basic Auth, you can supply the password interactively (the script will securely prompt you) or via the -p CLI flag for automation.

    Interactive prompt for password:

    ``` bash
    estctl enroll
    ```

    Non-interactive (use with caution when saving plaintext secrets):

    ``` bash
    estctl -p "provisioning_secret" enroll
    ```

3. **Certificate Renewal (Re-enrollment)** - Request a renewal using the current active certificate for mTLS authentication. The script will generate a .new private key and swap it atomically upon success.

    ``` bash
    estctl reenroll
    ```

4. **Check Certificate Status** - Evaluate the active certificate against the configured renew_warning_days threshold.

    ``` bash
    estctl status
    ```

    **Exit Codes:**
    - 0: Valid (or within the warning window)
    - 1: Execution error / file missing
    - 2: Certificate is fully expired

5. **Automated Renewal** - Evaluate the active certificate and automatically trigger a re-enrollment if the expiration is within the configured `renew_warning_days` threshold.

    ``` bash
    estctl autorenew
    ```

    **Crontab Example**
    Because estctl handles its own math and exit codes gracefully, you can fully automate the certificate lifecycle using a standard cron job.

    To check the certificate status daily at 2:00 AM and silently renew only if it falls within the warning threshold, add the following to /etc/crontab:

    ``` bash
    0 2 * * * root /usr/local/bin/estctl autorenew
    ```

## License

MIT License. See [LICENSE] for more information.

Author: [Tony Cavella](tony@cavella.com)
