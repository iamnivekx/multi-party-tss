# Multi-Party ECDSA Signature Server

[![Rust](https://img.shields.io/badge/Rust-1.70+-blue.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()

A high-performance, production-ready Threshold Signature Scheme (TSS) server implementation in Rust, supporting both distributed and centralized architectures for secure multi-party ECDSA signatures.

## 🚀 Features

- **Multi-Protocol Support**: Implements both GG18 and GG20 threshold signature protocols
- **Dual Architecture**: Supports distributed and centralized deployment modes
- **Production Ready**: Built with Rocket framework, PostgreSQL, and comprehensive error handling
- **Docker Support**: Complete containerization with docker-compose for easy deployment
- **RESTful API**: Clean, well-documented HTTP API endpoints
- **Security Focused**: Implements industry-standard cryptographic protocols

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#️-architecture)
- [Quick Start](#-quick-start)
- [API Documentation](#-api-documentation)
- [Deployment](#️-deployment)
- [Configuration](#️-configuration)
- [Development](#️-development)
- [Contributing](#-contributing)
- [License](#-license)

## 🔍 Overview

This project implements a Threshold Signature Scheme (TSS) server that enables secure multi-party ECDSA signatures. It's inspired by the [ZenGo-X/multi-party-ecdsa](https://github.com/ZenGo-X/multi-party-ecdsa) library and provides both distributed and centralized architectures to meet different deployment requirements.

### Key Benefits

- **Enhanced Security**: Private keys are never reconstructed in a single location
- **Fault Tolerance**: Supports threshold signatures (t-of-n) for resilience
- **Flexible Deployment**: Choose between distributed or centralized architecture
- **High Performance**: Built with Rust for optimal performance and memory safety

## 🏗️ Architecture

### Distributed Mode
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ TSS Server  │    │ TSS Server  │    │ TSS Server  │
│   (Party 1) │    │   (Party 2) │    │   (Party n) │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    ┌─────────────┐
                    │   Manager   │
                    │   Server    │
                    └─────────────┘
```

**Components:**
- **1 Manager Server**: Coordinates participant registration and data exchange
- **n TSS Servers**: Execute key generation and signing operations
- **Features**: Decentralized, fault-tolerant, high security

### Centralized Mode
```
┌─────────────────────────────────────┐
│           TSS Server                │
│  (Key Generation + Signing)         │
└─────────────────────────────────────┘
```

**Components:**
- **1 TSS Server**: Handles all operations centrally
- **Features**: Simplified deployment, single point of management

## 🚀 Quick Start

### Prerequisites

- Rust 1.70+ ([Install Rust](https://rustup.rs/))
- PostgreSQL 12+
- Docker & Docker Compose (for containerized deployment)

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/multi-party-server.git
   cd multi-party-server
   ```

2. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Install dependencies and run**
   ```bash
   cargo build --release
   cargo run
   ```

### Docker Deployment

1. **Distributed Mode (3 parties, threshold 1)**
   ```bash
   docker-compose up -d
   ```

2. **Centralized Mode**
   ```bash
   docker-compose -f docker-compose.centralized.yml up -d
   ```

## 📚 API Documentation

### Distributed Mode Endpoints

#### Key Generation
```bash
curl --location --request POST 'http://localhost:8000/ecdsa/gg_18/distributed/key' \
--header 'token: YOUR_TOKEN' \
--header 'Content-Type: application/json' \
--data-raw '{
    "threshold": 1,
    "parties": 3
}'
```

#### Message Signing
```bash
curl --location --request POST 'http://localhost:8000/ecdsa/gg_18/distributed/sign' \
--header 'token: YOUR_TOKEN' \
--header 'Content-Type: application/json' \
--data-raw '{
    "key": "YOUR_KEY_DATA",
    "message": "68656c6c6f20776f726c64",
    "parties": 3,
    "threshold": 1
}'
```

### Centralized Mode Endpoints

#### Batch Key Generation
```bash
curl --location --request POST 'http://localhost:8000/ecdsa/gg_18/centralized/keys' \
--header 'Content-Type: application/json' \
--data-raw '{
    "threshold": 2,
    "parties": 4
}'
```

For complete API documentation, see [API Reference](docs/api.md).

## 🛠️ Deployment

### Production Deployment

1. **Environment Configuration**
   ```bash
   # Database
   DATABASE_URL=postgresql://user:password@localhost/tss_db
   
   # Server
   ROCKET_PORT=8000
   ROCKET_ADDRESS=0.0.0.0
   ROCKET_ENV=release
   
   # Distributed mode (if applicable)
   COMMUNICATE_API=http://manager:9000
   ```

2. **Database Setup**
   ```bash
   diesel setup
   diesel migration run
   ```

3. **Service Deployment**
   ```bash
   # Using systemd
   sudo cp tss.service /etc/systemd/system/
   sudo systemctl enable tss
   sudo systemctl start tss
   ```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tss-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tss-server
  template:
    metadata:
      labels:
        app: tss-server
    spec:
      containers:
      - name: tss-server
        image: your-registry/tss-server:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: tss-secrets
              key: database-url
```

## ⚙️ Configuration

### Environment Variables

| Variable          | Description                        | Default   | Required |
| ----------------- | ---------------------------------- | --------- | -------- |
| `DATABASE_URL`    | PostgreSQL connection string       | -         | Yes      |
| `ROCKET_PORT`     | Server port                        | 8000      | No       |
| `ROCKET_ADDRESS`  | Server address                     | 127.0.0.1 | No       |
| `ROCKET_ENV`      | Environment (debug/release)        | debug     | No       |
| `COMMUNICATE_API` | Manager API URL (distributed mode) | -         | No       |

### Logging Configuration

```toml
# Rocket.toml
[release]
log_level = "info"
port = 8000
address = "0.0.0.0"
```

## 🔧 Development

### Project Structure

```
src/
├── api/                    # HTTP API layer
│   ├── ecdsa/             # ECDSA endpoints
│   │   ├── gg_2018/       # GG18 protocol
│   │   └── gg_2020/       # GG20 protocol
│   ├── response/          # Response handling
│   └── from_request/      # Request parsing
├── ecdsa/                 # Core ECDSA logic
│   ├── gg_2018/           # GG18 implementation
│   └── gg_2020/           # GG20 implementation
├── models/                # Data models
├── state/                 # State management
└── util/                  # Utilities
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with coverage
cargo tarpaulin

# Run specific test
cargo test test_key_generation
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint code
cargo clippy

# Check for security vulnerabilities
cargo audit
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow Rust conventions and best practices
- Use meaningful commit messages
- Add tests for new functionality
- Update documentation as needed

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [ZenGo-X/multi-party-ecdsa](https://github.com/ZenGo-X/multi-party-ecdsa) - Original TSS implementation
- [Rocket](https://rocket.rs/) - Web framework
- [Diesel](https://diesel.rs/) - ORM framework

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-username/multi-party-server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/multi-party-server/discussions)
- **Documentation**: [Wiki](https://github.com/your-username/multi-party-server/wiki)

---

**Note**: This is a security-critical application. Please ensure proper security practices when deploying to production environments.