---
orphan: true
---

# StegX Testing Suite (legacy)

This README provides comprehensive documentation for the StegX testing suite, including setup instructions, test categories, and guidelines for running and extending tests.

## Table of Contents

1. [Overview](#overview)
2. [Test Directory Structure](#test-directory-structure)
3. [Setup and Installation](#setup-and-installation)
4. [Running Tests](#running-tests)
5. [Test Categories](#test-categories)
6. [Extending the Test Suite](#extending-the-test-suite)
7. [CI/CD Integration](#cicd-integration)
8. [Kali Linux Considerations](#kali-linux-considerations)
9. [Troubleshooting](#troubleshooting)
10. [Contributing](#contributing)

## Overview

The StegX testing suite is designed to ensure the reliability, security, and performance of the StegX steganography tool. It includes:

- **Unit tests** for individual components
- **Integration tests** for component interactions
- **System tests** for end-to-end functionality
- **Performance tests** for resource usage and scalability
- **Security tests** for cryptographic robustness and vulnerability assessment

## Test Directory Structure

```
tests/
├── __init__.py
├── conftest.py                       # Shared pytest fixtures and configuration
├── resources/                        # Test resources
│   ├── images/                       # Test images
│   │   ├── valid/                    # Valid test images
│   │   └── invalid/                  # Invalid/corrupted test images
│   └── files/                        # Test files to hide
├── unit/                             # Unit tests
│   ├── __init__.py
│   ├── test_steganography.py         # v2 embed/extract round-trip, adaptive,
│   │                                 #   matrix, decoy, keyfile, capacity ceiling
│   ├── test_crypto.py                # v2 AEAD container, dual-cipher, keyfile,
│   │                                 #   AAD tamper detection, legacy v1 decrypt
│   ├── test_utils.py                 # Payload metadata + (de)compression round-trip
│   ├── test_kdf.py                   # Argon2id determinism + HKDF domain separation
│   ├── test_header.py                # v2 container-header pack/unpack + AAD canonicalisation
│   ├── test_shamir.py                # GF(2⁸) k-of-n Shamir secret sharing
│   ├── test_compression.py           # Multi-algorithm compressor (zlib/lzma/bz2/zstd/brotli)
│   └── test_io_sources.py            # Optional URL cover fetcher (http stub server)
├── integration/                      # Integration tests
│   ├── __init__.py
│   └── test_encode_flow.py           # Full encode → decode flows, --stdout, -d -
├── system/                           # System tests
│   ├── __init__.py
│   └── test_cli.py                   # CLI subprocess tests with --password-stdin
├── performance/                      # Performance tests
│   ├── __init__.py
│   └── test_performance.py           # Timing benchmarks across file + image sizes
├── security/                         # Security tests
│   ├── __init__.py
│   └── test_security.py              # AAD tamper detection, sentinel binding,
│                                     #   ±1 change-rate bound, no Pillow fingerprint
└── README.md                         # This file
```

**Total:** 255 tests pass as of StegX 2.0.0 (was 51 in 1.x).

## Setup and Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Kali Linux (recommended for security tests)

### Installation

1. Clone the StegX repository:
   ```bash
   git clone https://github.com/yourusername/StegX.git
   cd StegX
   ```

2. Install StegX and test dependencies:
   ```bash
   pip install -e .
   pip install -r tests/requirements.txt
   ```

### Test Dependencies

Production dependencies (from `requirements.txt`):
- Pillow ≥ 10.0.0
- cryptography ≥ 41.0.0
- tqdm ≥ 4.60.0
- argon2-cffi ≥ 23.1.0
- zxcvbn ≥ 4.4.28
- zstandard ≥ 0.22.0
- brotli ≥ 1.1.0

Test-only dependencies:
- pytest
- pytest-cov (optional, coverage report)
- numpy
- matplotlib (optional, performance plots)
- memory_profiler (optional, memory tests)
- hypothesis (optional, property-based tests)

## Running Tests

### Running All Tests

```bash
pytest tests/
```

### Running Specific Test Categories

```bash
# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/

# Run only system tests
pytest tests/system/

# Run only performance tests
pytest tests/performance/

# Run only security tests
pytest tests/security/
```

### Running Specific Test Files

```bash
# Run tests for the steganography module
pytest tests/unit/test_steganography.py

# Run CLI tests
pytest tests/system/test_cli.py
```

### Running Tests with Coverage

```bash
# Run tests with coverage report
pytest --cov=stegx tests/

# Generate HTML coverage report
pytest --cov=stegx --cov-report=html tests/
```

## Test Categories

### Unit Tests

Unit tests verify the correctness of individual functions and classes in isolation. They focus on:
- Input validation
- Expected outputs
- Error handling
- Edge cases

See [test_case_explanations.md](test_case_explanations.md) for detailed explanations of each unit test.

### Integration Tests

Integration tests verify that different components work correctly together. They test:
- Data flow between components
- Component interactions
- End-to-end workflows

### System Tests

System tests verify the behavior of the complete application from a user's perspective. They test:
- CLI functionality
- Command-line arguments
- Exit codes and error messages
- End-to-end workflows

### Performance Tests

Performance tests measure the efficiency and resource usage of the application. They test:
- Execution time with different file sizes
- Memory usage
- Compression effectiveness
- Scalability with large inputs

### Security Tests

Security tests verify the cryptographic robustness and vulnerability resistance of the application. They test:
- Password strength impact
- Cryptographic implementation
- Tamper resistance
- Steganalysis resistance
- Input validation and sanitization

## Extending the Test Suite

### Adding New Test Cases

1. Identify the appropriate test category and file
2. Follow the existing test patterns
3. Use pytest fixtures for setup and teardown
4. Document the purpose of the test
5. Update test_case_explanations.md with details

### Creating New Test Resources

1. Add images to `tests/resources/images/`
2. Add files to hide in `tests/resources/files/`
3. Document any special properties of the resources

### Adding New Test Categories

1. Create a new directory under `tests/`
2. Add an `__init__.py` file
3. Create test files following the naming convention `test_*.py`
4. Update this README with the new category

## CI/CD Integration

### GitHub Actions

A sample GitHub Actions workflow is provided in `.github/workflows/tests.yml`. It:
- Runs on Kali Linux
- Executes all test categories
- Generates coverage reports
- Performs security scans

### Jenkins

For Jenkins integration, use the provided `Jenkinsfile` which:
- Builds a Kali Linux Docker container
- Runs the test suite
- Archives test results and coverage reports

## Kali Linux Considerations

StegX is designed for use in Kali Linux environments, which introduces specific testing considerations:

- **Security Focus**: Tests must verify resistance to common attack vectors
- **Tool Integration**: Tests should verify compatibility with other Kali tools
- **Privilege Handling**: Tests must verify behavior with different privilege levels
- **Forensic Artifacts**: Tests should verify minimal forensic footprint

See [coverage_and_kali_considerations.md](coverage_and_kali_considerations.md) for detailed guidance.

## Troubleshooting

### Common Issues

- **Image libraries not found**: Install Pillow dependencies
  ```bash
  apt-get install libjpeg-dev zlib1g-dev
  ```

- **Permission errors in Kali**: Run with appropriate privileges
  ```bash
  sudo -E pytest tests/security/
  ```

- **Memory errors with large files**: Increase available memory or use smaller test files

### Getting Help

If you encounter issues not covered here:
1. Check the StegX documentation
2. Open an issue on the GitHub repository
3. Contact the maintainers

## Contributing

Contributions to the test suite are welcome! Please:

1. Follow the existing code style
2. Add appropriate documentation
3. Ensure all tests pass
4. Submit a pull request

For major changes, please open an issue first to discuss your proposed changes.

---

This testing suite documentation was last updated on June 12, 2025.
