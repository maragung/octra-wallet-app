Octra Wallet Manager

Octra Wallet Manager is a GUI-based desktop application built with Rust for managing wallets on the Octra network. Designed for high efficiency, it allows users to manage hundreds of wallet files, perform batch transactions, and monitor balances in real-time.

🚀 Key Features

1. Wallet Management

Dynamic Loading: Automatically scans and loads .json wallet files from the /wallets folder.

Natural Sorting: Intelligent filename sorting (e.g., wallet_2 appears before wallet_10).

Wallet Generator: Built-in tool to generate new wallets using BIP-39 mnemonics and Ed25519 key derivation.

Key Verification: Validation utility to ensure the mathematical consistency between private keys, public keys, and generated addresses.

2. Transaction Capabilities

Batch Sending: Send specific amounts from a defined range of wallets to a single destination address.

Advanced Sweep Modes:

Sweep to Target: Empty balances from multiple wallets into one "Master" address.

Sweep to Random: Distribute funds to random addresses listed in MyWallet.txt.

Automated Nonce Management: Automatically fetches the latest nonce and accounts for pending transactions in the local queue to prevent transaction collisions.

3. Monitoring & Tools

Global Balance Checker: A dedicated window to monitor and filter balances across all loaded wallets.

Real-time Logs: Detailed logs covering transaction hashes, RPC responses, and execution status.

Target Info: Look up balance and nonce information for any destination address without needing to import its private key.

Export Utilities: Export filtered lists of filenames or wallet addresses to .txt files.

4. UI/UX Customization

Dark/Light Modes: Full support for dark and light visual themes.

RPC Configuration: Configure RPC endpoints per wallet or use a single global RPC for all accounts.

UI Scaling: Adjustable zoom levels to fit various screen resolutions.

🛠 Developed with Gemini AI

This codebase was developed in collaboration with Gemini AI. Utilizing AI assisted in designing efficient logic structures and writing safe Rust boilerplate, accelerating the implementation of complex cryptographic features.

Authenticity & Security (Audit & Build)

The security of your private keys is the top priority. To ensure transparency:

Code Audit: You can directly inspect main.rs to verify that private keys are processed locally for transaction signing and are never sent to any server other than your chosen RPC endpoint.

Verify Binary: If you have concerns regarding the authenticity of a provided executable (.exe), you are highly encouraged to build the application yourself from the source code using the official Rust toolchain.

📖 How to Use

1. Initial Preparation

Create a folder named wallets in the same directory as the application.

Save your JSON wallet files inside that folder using the following format:

{
  "priv": "PRIVATE_KEY_BASE64",
  "addr": "oct_ADDRESS",
  "rpc": ""
}


(Optional) Create MyWallet.txt if you intend to use the "Sweep to Random" feature.

2. Basic Operations

Load Wallets: Click Reload Wallets to refresh the list after adding new files.

Check Balances: Use the Tools > Check All Balances menu to monitor all funds.

Input Transaction: Enter the destination in the Target Address field and the amount in the Amount field.

3. Batch Execution

Set the Start Index (starting point, e.g., 0) and the Wallet Count (number of wallets to process).

Select your mode (Send, Sweep Target, or Sweep Random).

Click Execute Transaction and monitor the progress bar.

🏗 Build Instructions

To ensure the binary you use is 100% identical to this source code, follow these steps:

Install Rust & Cargo.

Open a terminal in the project folder.

Run the command:

cargo build --release


The ready-to-use binary will be located in the target/release/ folder.

Developed by Maragung.
