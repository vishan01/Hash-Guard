# HASH GUARD 🔐: Secure Cryptographic Operations with mbedtls (C++ Version)

**HASH GUARD (C++)** is a robust C++ program leveraging the mbedtls library to provide a suite of essential cryptographic operations. This application empowers users to perform fundamental security tasks, including data integrity verification through SHA-256 hashing, secure communication via RSA and symmetric encryption (3DES and AES), and ensuring data authenticity with digital signatures. Designed for ease of use and deployment through Docker, HASH GUARD (C++) offers a practical demonstration of applied cryptography using modern C++ features.

## Key Features

* **SHA-256 Hashing:** Generates a unique and fixed-size digital fingerprint (hash) of any 32-byte message, ensuring data integrity by detecting unauthorized modifications. Implemented using C++ standard library features and mbedtls.
* **RSA Encryption/Decryption:** Implements asymmetric cryptography for secure data exchange. It includes:
    * **Encryption:** Protects sensitive information by transforming it into an unreadable format using a public key. Leverages C++ classes for key management.
    * **Decryption:** Restores the original message using the corresponding private key.
    * **RSA Key Pair Generation:** Creates a pair of mathematically linked public and private keys, essential for RSA operations, saved as PEM files for secure storage and sharing of the public key. Utilizes C++ file I/O.
    * **Digital Signature:** Enables message authentication and non-repudiation by creating a digital signature using the private key. Employs C++ streams for data handling.
    * **Digital Signature Verification:** Confirms the authenticity and integrity of a signed message using the corresponding public key.
* **3DES Encryption/Decryption:** Provides a symmetric encryption algorithm (Triple DES) for securing 32-byte messages using a shared secret key. Implemented with a C++ interface for ease of use.
* **AES Encryption/Decryption:** Implements the Advanced Encryption Standard (AES-256), a widely adopted symmetric encryption algorithm, to secure 32-byte messages using a shared secret key. Offers a clean C++ API.

## Getting Started

### Prerequisites

* **Docker:** Ensure Docker is installed and running on your system. This simplifies the build and execution process by creating a containerized environment.
* **C++ Compiler:** A modern C++ compiler (e.g., g++ version 17 or later) is required to build the application.

### Compilation and Docker Image Creation

1.  Navigate to the directory containing the project files.
2.  Build the Docker image using the following command in your terminal:
    ```bash
    docker build -t crypto_app_cpp_image .
    ```
    This command uses the `Dockerfile` in the current directory (`.`) to create a Docker image named `crypto_app_cpp_image`.

### Usage

1.  Run the compiled program within a Docker container using the following command:
    ```bash
    docker run -it crypto_app_cpp_image
    ```
    The `-it` flags ensure interactive terminal access to the running container.
2.  Follow the on-screen prompts to select the desired cryptographic operation and provide the necessary inputs. The C++ version might offer a more object-oriented and type-safe interaction.

## Operation Details

1.  **SHA-256 Hashing:**
    * **Operation:** Computes the SHA-256 hash.
    * **Input:** A message up to 32 bytes.
    * **Output:** The resulting SHA-256 hash value (potentially as a `std::string` or `std::vector<unsigned char>`).

2.  **RSA Encryption/Decryption:**
    * **Operation:** Choose from encryption, decryption, key pair generation, digital signature creation, or signature verification.
    * **Options:** Follow the specific prompts for each operation, which may involve entering a message (max 245 bytes for encryption), providing file paths for key files (using `std::filesystem` or `std::fstream`), or the hash value for signing.
    * **Output:** Encrypted/decrypted data (likely as a `std::vector<unsigned char>` or a hex-encoded `std::string`), confirmation of key pair generation, or verification status (boolean).

3.  **3DES Encryption/Decryption:**
    * **Operation:** Choose between encryption and decryption of a 32-byte message.
    * **Options:** Enter the message to encrypt or the ciphertext and the 3DES key (displayed during encryption) to decrypt. The key might be handled as a `std::array` or `std::vector`.
    * **Output:** The encrypted or decrypted data (as `std::vector<unsigned char>` or hex `std::string`), along with the generated 3DES key (potentially as a hex `std::string`).

4.  **AES Encryption/Decryption:**
    * **Operation:** Select between encryption and decryption of a 32-byte message.
    * **Options:** Provide the message for encryption or the ciphertext and the AES key (displayed during encryption) for decryption. The key might be managed using `std::array` or `std::vector`.
    * **Output:** The encrypted or decrypted data (as `std::vector<unsigned char>` or hex `std::string`), and the generated AES key (potentially as a hex `std::string`).

## Project Files

* `private_key.pem`: Stores the generated RSA private key in PEM format (likely handled using C++ file streams).
* `public_key.pem`: Stores the generated RSA public key in PEM format (likely handled using C++ file streams).
* `hash_value.bin`: Contains the binary representation of a message's hash, used in the digital signature process (potentially using `std::fstream` in binary mode).
* `crypto_operations`: The compiled executable binary of the C++ program.
* `dockerfile`: A text file containing instructions for Docker to build the container image, including steps to compile the C++ code (e.g., using `g++` and potentially CMake).

HASH GUARD (C++) demonstrates fundamental cryptographic techniques with a focus on modern C++ practices, potentially offering improved type safety, resource management, and a more object-oriented design compared to a pure C implementation.
