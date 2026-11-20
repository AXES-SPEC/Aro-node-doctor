
# ARO Node Doctor

A lightweight diagnostic and monitoring toolkit for ARO Network node operators

ARO Node Doctor helps operators identify common system, network, and ARO service issues through simple diagnostic checks

## Features

- System information and resource usage
- CPU, RAM, and disk monitoring
- Internet connectivity checks
- DNS resolution tests
- Separate IPv4 and IPv6 connectivity checks, with family-aware severity
- ARO service status, active uptime, and historical restart counts
- 24-hour agent and RPC log analysis for DNS failures, TCP timeouts, and successful reconnections
- Health scoring that does not warn solely because of an old systemd restart
- Diagnostic report generation

## Supported Systems

- Debian 13
- Ubuntu
- Other Debian-based Linux distributions (planned)

## Requirements

- Python 3.9+
- Linux operating system
- systemd

## Installation

Clone the repository:

    git clone https://github.com/AXES-SPEC/Aro-node-doctor.git

Enter the project directory:

    cd Aro-node-doctor

Run the diagnostic tool:

    python3 main.py

## Safety

ARO Node Doctor is designed to be read-only

It does not automatically restart services, modify configurations, or change firewall settings

## Project Status

🚧 Under development

## Contributions

Contributions, bug reports, and feature suggestions are welcome

## Disclaimer

This is an independent community tool and is not an official ARO Network product
