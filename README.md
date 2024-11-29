
# Secure File Integrity Checker

## Overview

The Secure File Integrity Checker is a Python-based GUI application engineered for computation and verification of file hashes, ensuring data integrity and protection against unauthorized modifications or corruption. Leveraging industry-standard cryptographic hashing algorithms such as MD5, SHA-1, and SHA-256, the application provides a mechanism for validating file authenticity. Its secure file processing methodology, including chunk-based reading and in-memory hash computation, ensures optimal performance while minimizing potential attack vectors. 

---

## Key Features
### 1. **Accurate Hash Calculation**
- Supports **MD5**, **SHA-1**, and **SHA-256** hashing algorithms.
- Processes files in **chunks** to handle large files securely and efficiently.

### 2. **Reliable Integrity Verification**
- Compares the calculated hash against an expected hash provided by the user.
- Identifies tampered or corrupted files to ensure data security.

### 3. **Clipboard Integration**
- Enables secure copying of calculated hashes for sharing or later verification.

### 4. **Intuitive GUI**
- Built with **Tkinter**, offering a lightweight, responsive, and error-tolerant interface.
- Handles invalid inputs, unsupported algorithms, and file-related errors gracefully.

---


### Cryptographic Hashing Algorithms:
1. **MD5**:
   - Suitable for non-critical integrity checks (e.g., simple checksums).
   - **Not secure** for cryptographic purposes due to collision vulnerabilities.

2. **SHA-1**:
   - Deprecated for secure applications but included for compatibility.
   - Use only when backward compatibility is necessary.

3. **SHA-256**:
   - Part of the SHA-2 family and cryptographically secure.
   - Recommended for all high-security use cases.

### Secure File Processing:
- Reads files in **8192-byte chunks**, optimizing memory usage while maintaining security.
- No temporary storage of sensitive data; hash values are held only in memory.

---

## Installation
### Prerequisites:
1. **Python 3.x** installed on your system.
2. Required modules:
   - **`hashlib`**: Built into Python for cryptographic hash generation.
   - **`tkinter`**: Built into Python for GUI development.

### Steps:
1. Clone or download the repository:
   ```bash
   git clone https://github.com/ramyardaneshgar/File-Integrity-Checker.git
   cd File-Integrity-Checker
   ```
2. Run the application:
   ```bash
   python app.py
   ```

---

## Usage
### Graphical User Interface (GUI):
1. **Select File**:
   - Use the "Browse" button to securely select the file to hash.

2. **Choose Hash Algorithm**:
   - Select from MD5, SHA-1, or SHA-256 in the dropdown menu.

3. **Verify Integrity**:
   - Enter an expected hash in the "Expected Hash" field.
   - Click "Verify Integrity" to compare the calculated and expected hashes.

4. **Copy Hash to Clipboard**:
   - Use the "Copy Hash" button to securely copy the calculated hash.

---

## Code Details
### Core Functions:
1. **`calculate_file_hash(file_path, algorithm)`**:
   - Calculates the hash of a file using the specified algorithm, processing files in chunks.
   - Handles errors such as unsupported algorithms and missing files.

2. **`verify_file_integrity()`**:
   - Compares the calculated hash with the expected hash value.
   - Displays results indicating whether file integrity is intact or compromised.

3. **`copy_to_clipboard()`**:
   - Securely copies the calculated hash to the clipboard for easy sharing.

4. **`calculate_hash_only()`**:
   - Displays the calculated hash without requiring an expected value.

---

## Example Use Cases
1. **Verify File Authenticity**:
   - Check the integrity of downloaded software by comparing its hash with the one published by the vendor.

2. **Incident Response**:
   - Validate if files in a suspected breach or malware attack have been altered.

3. **Secure File Transfers**:
   - Share hash values with recipients to ensure the transmitted file is intact.

4. **Validate Backup Integrity**:
   - Periodically verify backup files to ensure they are uncorrupted and secure.



## Disclaimer
This tool is intended for **educational and testing purposes only**. Users are responsible for ensuring compliance with relevant laws and regulations when using this tool in real-world scenarios.

---

## License
This project is licensed under the **MIT License**. See the LICENSE file for details.

---

## Contact
Developed by **Ramyar Daneshgar**.  
For questions, suggestions, or contributions, please contact: **ramyarda@usc.edu**
