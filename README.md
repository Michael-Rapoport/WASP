# WASP (Windows Anonymous Swarming Proxy)

WASP is an advanced, Rust-based implementation of a privacy-preserving network proxy that utilizes a swarm of nodes to route traffic, enhancing user anonymity and security. It also integrates powerful features for network reconnaissance, exploitation, and post-exploitation activities.

## Features

- Multi-hop routing through a network of nodes
- Traffic shaping to prevent timing analysis
- Automatic discovery and configuration of public proxies and open SSH servers
- Windows credential extraction (lsassy features)
- Comprehensive network scanning capabilities
- Advanced exploitation framework with real-world techniques
- Concurrent scanning and exploitation
- RESTful API with JWT authentication
- Logging and monitoring
- Input validation and error handling
- Database integration with connection pooling
- Containerized deployment option
- Automated Windows installer (.msi)

## Project Structure

- `src/main.rs`: Entry point of the application
- `src/wasp.rs`: Core WASP implementation
- `src/network/mod.rs`: Network management and node information
- `src/routing/mod.rs`: Route selection logic
- `src/crypto/key_management.rs`: Cryptographic operations
- `src/circuit.rs`: Circuit creation and management
- `src/traffic_shaping.rs`: Traffic shaping implementation
- `src/timing_protection.rs`: Timing protection for operations
- `src/config.rs`: Configuration management
- `src/lsassy/mod.rs`: Windows credential extraction features
- `src/network_tools/mod.rs`: Network scanning tools
- `src/reports/mod.rs`: Report generation and management
- `src/auth/mod.rs`: Authentication and authorization
- `src/validation/mod.rs`: Input validation and sanitization
- `src/error.rs`: Error handling and custom error types
- `src/node_discovery/mod.rs`: Automatic discovery of proxy and SSH nodes
- `src/exploitation/mod.rs`: Advanced exploitation techniques
- `tests/`: Unit and integration tests
- `installer/`: Windows installer files
- `create_installer.bat`: Script to create the Windows installer

## Getting Started

1. Install Rust and Cargo (https://www.rust-lang.org/tools/install)
2. Clone this repository
3. Set up the configuration:
   - Copy `config/default.toml.example` to `config/default.toml`
   - Adjust the settings in `config/default.toml` as needed
   - Set the `RUN_MODE` environment variable (e.g., `development`, `production`)
4. Build the project: `cargo build --release`
5. Run the tests: `cargo test`
6. Run the project: `cargo run --release`

## Configuration

The application is configured using a combination of configuration files and environment variables. See `src/config.rs` for details on the configuration structure.

## API Endpoints

- `POST /api/integrated-scan`: Initiate a network scan
- `GET /api/reports`: Retrieve all scan reports
- `POST /api/exploit`: Trigger the exploitation chain for a target
- `GET /health`: Health check endpoint

All API endpoints (except `/health`) require authentication using a JWT token.

## Docker Deployment

To build and run WASP using Docker:

1. Build the Docker image: `docker build -t wasp .`
2. Run the container: `docker run -p 3030:3030 wasp`

## Creating the Windows Installer

To create the Windows installer (.msi):

1. Install the WiX Toolset v3.11 or later (https://wixtoolset.org/)
2. Ensure the WiX Toolset bin directory is in your system PATH
3. Run the `create_installer.bat` script:
   ```
   .\create_installer.bat
   ```
4. The installer will be created in the `installer` directory as `WASP_Installer.msi`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.

## Disclaimer

WASP contains extremely powerful and potentially dangerous features. It implements real-world exploitation techniques that can cause significant damage if misused. This tool should only be used in controlled environments with explicit permission and in full compliance with all applicable laws and regulations. Misuse of these features can result in severe legal consequences. Always ensure you have proper authorization before using any of the exploitation or scanning features on any system or network. The developers of this software are not responsible for any misuse or damage caused by this tool.

## User Manual

For detailed instructions on how to use WASP, please refer to the [User Manual](USER_MANUAL.md).