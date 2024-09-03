# WASP User Manual

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running WASP](#running-wasp)
5. [API Usage](#api-usage)
   - [Authentication](#authentication)
   - [Integrated Scan](#integrated-scan)
   - [Retrieving Reports](#retrieving-reports)
   - [Exploitation](#exploitation)
6. [Node Discovery](#node-discovery)
7. [Traffic Shaping](#traffic-shaping)
8. [Windows Credential Extraction](#windows-credential-extraction)
9. [Advanced Exploitation Techniques](#advanced-exploitation-techniques)
10. [Logging and Monitoring](#logging-and-monitoring)
11. [Troubleshooting](#troubleshooting)
12. [Security Considerations](#security-considerations)

## 1. Introduction

WASP (Windows Anonymous Swarming Proxy) is an advanced network proxy and security testing tool. It provides anonymity through multi-hop routing, integrated network scanning, exploitation capabilities, and Windows credential extraction features. This manual will guide you through the setup, configuration, and usage of WASP.

## 2. Installation

1. Install Rust and Cargo from https://www.rust-lang.org/tools/install
2. Clone the WASP repository:
   ```
   git clone https://github.com/your-repo/wasp.git
   cd wasp
   ```
3. Build the project:
   ```
   cargo build --release
   ```

## 3. Configuration

1. Copy the example configuration file:
   ```
   cp config/default.toml.example config/default.toml
   ```
2. Edit `config/default.toml` to adjust settings such as:
   - `listen_addr`: The address and port WASP will listen on
   - `node_id`: A unique identifier for this WASP instance
   - `database_url`: Connection string for the database
   - `jwt_secret`: Secret key for JWT token generation

3. Set the `RUN_MODE` environment variable:
   ```
   export RUN_MODE=production
   ```

## 4. Running WASP

To start the WASP server:

```
cargo run --release
```

The server will start and listen on the configured address.

## 5. API Usage

### Authentication

All API endpoints (except `/health`) require a JWT token for authentication. To obtain a token, you need to implement a login mechanism (not provided in the current implementation).

Include the token in the `Authorization` header of your requests:

```
Authorization: Bearer <your_jwt_token>
```

### Integrated Scan

To initiate a network scan:

```http
POST /api/integrated-scan
Content-Type: application/json

{
  "targets": ["192.168.1.1", "example.com"],
  "options": {
    "port_scan": true,
    "service_detection": true,
    "os_detection": true,
    "vulnerability_scan": true
  }
}
```

### Retrieving Reports

To get all scan reports:

```http
GET /api/reports
```

### Exploitation

To trigger the exploitation chain for a target:

```http
POST /api/exploit
Content-Type: application/json

{
  "target": "192.168.1.100"
}
```

## 6. Node Discovery

WASP automatically discovers and configures public proxies and open SSH servers. This process runs periodically in the background. Discovered nodes are added to the swarm and can be used for routing traffic.

## 7. Traffic Shaping

Traffic shaping is employed to prevent timing analysis attacks. The `TrafficShaper` component introduces random delays and packet sizes to obfuscate the true nature of the traffic.

## 8. Windows Credential Extraction

WASP incorporates lsassy features for extracting Windows credentials. This functionality is integrated into the exploitation chain and can be triggered via the API.

## 9. Advanced Exploitation Techniques

WASP includes several advanced exploitation techniques:

- MS17-010 (EternalBlue) exploit
- Privilege escalation using CVE-2021-4034 (PwnKit)
- Reverse shell deployment
- Lateral movement

These are automatically employed during the exploitation chain.

## 10. Logging and Monitoring

WASP uses the `tracing` crate for logging. Logs are output to stdout by default. You can adjust the log level by setting the `RUST_LOG` environment variable:

```
export RUST_LOG=debug
```

## 11. Troubleshooting

- If you encounter database connection issues, ensure your database is running and the `database_url` in the configuration is correct.
- For API authentication problems, check that your JWT token is valid and correctly included in the request headers.
- If node discovery is not working, ensure your firewall is not blocking the necessary ports.

## 12. Security Considerations

WASP is a powerful tool that includes real-world exploitation techniques. It should only be used in controlled environments with explicit permission. Misuse of this tool can lead to severe consequences. Always ensure you have proper authorization before using any of the exploitation or scanning features.

Remember to:
- Use strong, unique passwords for authentication
- Regularly update the `jwt_secret` in the configuration
- Monitor logs for any suspicious activity
- Use HTTPS in production environments
- Regularly update WASP and its dependencies to patch any security vulnerabilities

## Disclaimer

The developers of WASP are not responsible for any misuse or damage caused by this tool. Use at your own risk and only on systems you own or have explicit permission to test.