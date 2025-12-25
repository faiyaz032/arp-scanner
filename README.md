# ARP Scanner

This project is a simple, yet effective, ARP scanner written in Go. It's designed to discover all active hosts on a local network by sending ARP requests and listening for replies. This tool is useful for network reconnaissance and mapping.

## How It Works

The scanner operates by performing the following steps:

1.  **Find Active Interface:** It automatically identifies the primary active network interface (e.g., `eth0`, `en0`) on the machine, ignoring loopback and inactive ones.
2.  **Determine Network Range:** It retrieves the IPv4 address and subnet mask of the active interface to calculate the range of all possible IP addresses within the local network.
3.  **Craft & Send ARP Requests:** For each usable IP address in the calculated range, it crafts a custom ARP request packet. The request essentially asks "who has this IP address?". These packets are sent out onto the network.
4.  **Listen for ARP Replies:** Concurrently, the tool listens for incoming ARP reply packets. It uses a BPF (Berkeley Packet Filter) to ensure it only processes ARP traffic, making it highly efficient.
5.  **Identify Hosts:** When a host replies, the scanner captures the reply, extracts the host's IP address and MAC (hardware) address, and prints it to the console. This indicates that the host is active on the network.

The project leverages raw sockets for sending and receiving packets, which is why it requires `sudo` privileges to run.

## Built With

*   [Go](https://golang.org/)
*   [gopacket](https://github.com/google/gopacket): A Go library for packet processing and capturing.

## Getting Started

To get a local copy up and running, follow these simple steps.

### Prerequisites

You need to have Go installed on your system.
*   [Go Installation Guide](https://golang.org/doc/install)

### Running the Scanner

1.  Clone the repository:
    ```sh
    git clone https://github.com/faiyaz032/arp-scanner.git
    cd arp-scanner
    ```

2.  There are two ways to run the scanner:

    **Using the Makefile:**
    The `Makefile` provides a convenient way to run the project with the necessary privileges.
    ```sh
    make run
    ```

    **Using the `go run` command:**
    You can also run the scanner directly using the `go` command. `sudo` is required.
    ```sh
    sudo go run cmd/main.go
    ```

The scanner will then start, and you will see output for each host it discovers on your network.

## Author

This project was created by **Faiyaz**.
