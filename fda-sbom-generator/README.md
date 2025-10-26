# FDA SBOM Generator

A comprehensive FDA-compliant Software Bill of Materials (SBOM) generator for small to midsize medical devices.

## Features

- **Multi-format SBOM Support**: SPDX 3.0 and CycloneDX 1.5
- **Comprehensive Package Manager Support**: npm, pip, Maven, NuGet, Cargo, Go modules
- **Vulnerability Assessment**: Real-time CVE scanning with VEX support
- **FDA Compliance**: Automated compliance validation and reporting
- **Support Lifecycle Management**: EOL tracking and migration planning
- **License Compliance**: Automated license conflict detection
- **Dependency Visualization**: Interactive dependency graphs and architecture diagrams

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+

### Backend Setup

```bash
cd fda-sbom-generator/backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend Setup

```bash
cd fda-sbom-generator/frontend
npm install
```

### Running the Application

```bash
# Backend
cd fda-sbom-generator/backend
uvicorn app.main:app --reload

# Frontend
cd fda-sbom-generator/frontend
npm start
```

## Development

### Running Tests

```bash
# Backend tests
cd fda-sbom-generator/backend
pytest

# Frontend tests
cd fda-sbom-generator/frontend
npm test
```

### Code Quality

```bash
# Install pre-commit hooks
pre-commit install

# Run linting
black app/
isort app/
flake8 app/
mypy app/
```

## Documentation

- [Build Plan](BUILD_PLAN.md) - Comprehensive development plan
- [Week 1-2 Implementation](WEEK_1_2_IMPLEMENTATION_PLAN.md) - Detailed implementation steps
- [API Documentation](docs/api/) - REST API documentation
- [Architecture](docs/architecture/) - System architecture overview
- [Compliance](docs/compliance/) - FDA compliance guidelines

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.


