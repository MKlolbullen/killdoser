# KillDoSer - DoS Test Tool

## Overview
The **DoS Test Tool** is a command-line utility designed for testing the robustness of networks and servers under load. It allows users to send packets to a target IP, domain, or CIDR range using configurable protocols and payloads. 

**DISCLAIMER**: This tool is intended for educational purposes, penetration testing, and stress testing only with proper authorization. Unauthorized use is illegal and unethical. Always ensure you have explicit permission from the target system owner before conducting any tests.

---

## Features
- **Network Interface Selection**: Choose from available interfaces dynamically.
- **Target Specification**: Supports domains, IP addresses, and CIDR ranges.
- **Configurable Protocols**: Choose between TCP or UDP packet sending.
- **Custom Payloads**: Send user-defined payloads, with support for multiple encoding types.
- **HTTP Versioning**: Options for HTTP/1.1 or HTTP/2 payload structure.
- **Loop Configuration**: Specify how many iterations the tool should run.

---

## How It Works
1. **Select Network Interface**: The tool dynamically detects available interfaces.
2. **Input Target**: Specify the domain, IP, or CIDR for the test.
3. **Select Port**: Choose the port to which packets will be sent.
4. **Choose Protocol**: Decide between TCP or UDP for packet transmission.
5. **Input Payload**: Define the payload to be sent with optional encoding.
6. **Confirm Permissions**: Explicit prompts ensure compliance with ethical and legal standards.
7. **Run the Test**: The tool sends packets iteratively over a specified range.

---

## Installation
1. Ensure you have [Go](https://golang.org/) installed on your system.
2. Clone this repository:
   ```bash
   git clone https://github.com/MKultralol/killdoser.git
   cd killdoser

3. Build the executable:
```bash
go build -o killdoser
```
or 3.1. run the main.go without building it.
```bash
go run main.go
```

4. Run the tool:
```bash
./killdoser
```

---

Usage

1. Run the tool and follow the on-screen prompts:
```bash
./killdoser
```

2. Select options as needed:

Network Interface: Use arrow keys or enter the corresponding number.

Target Input: Provide a domain, IP address, or CIDR.

Port: Specify the target port (e.g., 80 for HTTP).

Protocol: Choose between TCP or UDP.

Payload: Input a custom payload or string to send.

Encoding: Optionally encode the payload (e.g., Base64, URL, HTML).

Loop Count: Specify the number of iterations for the test.


---

Encoding Options

The tool supports the following encoding types:

URL Encoding

HTML Encoding

Base64 Encoding

Unicode Escaping



---

Legal Disclaimer

This tool is provided for legal testing and educational purposes only. Unauthorized use of this tool on systems you do not own or have explicit permission to test is strictly prohibited and may result in severe penalties under applicable laws.

By using this tool, you agree to use it responsibly and only for lawful purposes.


---

Contribution

Contributions are welcome! Feel free to submit issues, fork the repository, or open pull requests to improve the tool.


---

License

This project is licensed under the MIT License.


---

Note: Always verify the legality and authorization of your testing activities!

### Key Sections in the README:
- **Overview**: Describes the tool's purpose and intended use.
- **Features**: Highlights the tool's capabilities.
- **Installation**: Guides users through setting up the tool.
- **Usage**: Explains how to interact with the tool.
- **Legal Disclaimer**: Explicitly states the ethical and legal boundaries.
- **Contribution**: Encourages community involvement.
- **Acknowledgments**: Recognizes contributors and resources.

Feel free to customize further based on your needs.

