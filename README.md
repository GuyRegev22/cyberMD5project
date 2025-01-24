# Distributed MD5 Hash Cracking Project

## Overview
This project is a distributed system designed to crack a 10-digit number encoded in an MD5 hash. By utilizing the computational power of client machines, the project distributes the workload across multiple devices to efficiently find the original number.

**Important:** This project is intended for educational purposes only. Unauthorized cracking of passwords or sensitive data is illegal and unethical.

---

## Features
- **Distributed Computing:** Utilizes multiple clients to divide the workload and speed up the cracking process.
- **Efficient Workload Distribution:** Each client is assigned a unique range of numbers to process, ensuring no duplication of effort.
- **Progress Monitoring:** Real-time updates on progress and estimated time to completion.
- **Cross-Platform Compatibility:** Works on Windows and Linux.

---

## How It Works
1. **Server Initialization:**  
   The server generates the target MD5 hash and divides the workload into manageable chunks for the clients.
   
2. **Client Connection:**  
   Clients connect to the server, receive their assigned range, and begin computing the MD5 hashes for each number in that range.
   
3. **Hash Matching:**  
   Each client compares computed hashes with the target hash. If a match is found, the client notifies the server.
   
4. **Result Collection:**  
   The server collects the result and notifies all clients to stop their computations.

---

## Prerequisites
- Python 3.8 or higher installed on all machines.
- `hashlib` library (pre-installed with Python).
- Network connectivity between the server and clients.

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/md5-cracker
   cd md5-cracker
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

