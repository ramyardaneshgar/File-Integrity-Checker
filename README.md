 



# File Integrity Checker
**Developed by Ramyar Daneshgar**

**⚠️ Disclaimer**: This project is strictly for educational and research purposes. All testing has been conducted in secure, authorized environments. Unauthorized use is prohibited.

## Overview
The File Integrity Checker is a Python-based GUI application engineered for computation and verification of file hashes, ensuring data integrity and protection against unauthorized modifications or corruption. Leveraging industry-standard cryptographic hashing algorithms such as MD5, SHA-1, and SHA-256, the application provides a mechanism for validating file authenticity. Its secure file processing methodology, including chunk-based reading and in-memory hash computation, ensures optimal performance while minimizing potential attack vectors.



---

## Key Features
### 1. **Accurate Hash Calculation**
- Supports widely used cryptographic algorithms: **MD5**, **SHA-1**, and **SHA-256**.
- Processes files in **8192-byte chunks** to handle large files securely and efficiently.

### 2. **Reliable Integrity Verification**
- Compares the calculated hash against an expected hash provided by the user.
- Detects tampered or corrupted files, ensuring data security and authenticity.

### 3. **Clipboard Integration**
- Securely copies calculated hashes to the clipboard for sharing or later verification.

### 4. **Intuitive GUI**
- Built with **Tkinter**, offering a lightweight, responsive, and error-tolerant interface.
- Handles invalid inputs, unsupported algorithms, and file-related errors gracefully.

---


### Cryptographic Hashing Algorithms:
1. **MD5**:
   - Suitable for non-critical integrity checks (e.g., simple checksums).
   - **Not secure** for cryptographic purposes due to collision vulnerabilities.
   
2. **SHA-1**:
   - **Deprecated** for secure applications but included for compatibility.
   - Use only when backward compatibility is required.

3. **SHA-256**:
   - A cryptographically secure member of the SHA-2 family.
   - Recommended for all high-security use cases.

### Secure File Processing:
- Files are read in **8192-byte chunks**, optimizing memory usage while maintaining security.
- No temporary storage of sensitive data; hash values are held only in memory during processing.

---

## Installation
### Prerequisites:
1. **Python 3.x** installed on your system.
2. Required Python modules:
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
   - Select from **MD5**, **SHA-1**, or **SHA-256** in the dropdown menu.

3. **Verify Integrity**:
   - Enter an expected hash in the "Expected Hash" field.
   - Click "Verify Integrity" to compare the calculated and expected hashes.

4. **Copy Hash to Clipboard**:
   - Use the "Copy Hash" button to securely copy the calculated hash.

---

## Code Details
### Core Functions:
1. **`calculate_file_hash(file_path, algorithm)`**:
   - Calculates the hash of a file using the specified algorithm.
   - Processes files in chunks for memory efficiency and performance.
   - Handles errors such as unsupported algorithms and missing files.

2. **`verify_file_integrity()`**:
   - Compares the calculated hash with the user-provided expected hash.
   - Displays results indicating whether file integrity is intact or compromised.

3. **`copy_to_clipboard()`**:
   - Securely copies the calculated hash to the clipboard for easy sharing.

4. **`calculate_hash_only()`**:
   - Displays the calculated hash without requiring an expected hash value.

---

## Example Use Cases
1. **Verify File Authenticity**:
   - Validate the integrity of downloaded files by comparing their hashes with vendor-provided values.

2. **Incident Response**:
   - Determine whether files in a suspected breach or malware attack have been altered.

3. **Secure File Transfers**:
   - Share hash values with recipients to confirm the integrity of transmitted files.

4. **Validate Backup Integrity**:
   - Periodically verify backup files to ensure they remain uncorrupted and secure.


---

## License
This project is licensed under the **MIT License**. See the LICENSE file for details.

---

