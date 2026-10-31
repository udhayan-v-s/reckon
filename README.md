# RECKON

**A modular Bash-based network and web reconnaissance toolkit.**

RECKON is a command-line reconnaissance toolkit designed to automate network and web information gathering by orchestrating established cybersecurity tools through a modular Bash architecture.

The project aims to simplify reconnaissance workflows, organize findings, and generate structured scan reports through a unified interface.

## Objectives

- Automate common network and web reconnaissance tasks.
- Integrate widely used security tools into a unified workflow.
- Provide modular and reusable Bash components.
- Normalize and organize reconnaissance findings.
- Generate structured reports in multiple formats.

## Planned Features

### Network Reconnaissance
- Host discovery
- DNS reconnaissance
- Port scanning
- Service and OS detection
- SSH, FTP, HTTP, HTTPS, SMB and Telnet enumeration

### Web Reconnaissance
- HTTP/HTTPS analysis
- Technology, CMS and WAF fingerprinting
- Subdomain enumeration
- Directory and file enumeration
- Virtual host enumeration
- Web crawling and endpoint discovery
- SSL/TLS analysis
- Historical URL discovery

## Architecture

RECKON follows a modular, function-oriented Bash architecture with separate components for:

- CLI and input validation
- Scan planning and execution
- Network and web modules
- Shared utilities and dependency management
- Result processing and normalization
- Logging and report generation

## Technology Stack

- **Language:** Bash
- **Platform:** Linux
- **Static Analysis:** ShellCheck
- **Version Control:** Git

External reconnaissance tools and their dependencies will be documented as their integrations are implemented.

## Project Status

**Development in progress — v1.0**

The project is currently in its foundation and core CLI development stages. Planned features will be implemented and tested incrementally.

## Usage

CLI commands and usage examples will be documented as the core interface becomes available.

## Responsible Use

RECKON is intended for authorized security assessments, educational labs, and controlled testing environments.

Users are responsible for obtaining appropriate authorization before scanning or enumerating any systems, networks, or web applications.

## License

This project is licensed under the [MIT License](LICENSE).