# Vultus: Network Analysis Tool

Vultus is an advanced, network analysis tool designed to provide comprehensive insights into network activities. It enables network administrators and security professionals to monitor, analyze, and report on network traffic and device status in real-time.

## Features

- **Real-Time Traffic Captures**: Dynamic capturing of network traffic, protocol distribution, and bandwidth usage.
- **Device Discovery**: Identifies active devices on the network using ARP requests.
- **Port Scanning**: Scans and reports on open network ports, helping identify potential security vulnerabilities.
- **Packet Analysis**: Captures and analyzes packets, allowing for detailed inspection of network traffic.
- **Capture Files**: Capture files can be saved locally and analyzed on other network analysis platforms. (e.g. Wireshark)

## Getting Started

This section provides detailed instructions on how to get Vultus up and running on your local machine for development and testing purposes.

### Prerequisites

Before you begin, ensure you have Python installed on your system. Vultus is compatible with Python 3.8 and newer. You can download Python from [python.org](https://www.python.org/downloads/).

You will also need `pip` to install Python packages. Pip typically comes with Python; check its availability with `pip --version`.

### Installation

Follow these steps to set up your development environment:

1. **Clone the Repository**

   Start by cloning the Vultus repository from GitHub to your local machine:

   ```bash
   git clone https://github.com/DaniAbdulm/python-network-analyzer.git
   cd Vultus
