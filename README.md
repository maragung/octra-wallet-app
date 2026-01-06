# Octra Wallet Manager

Octra Wallet Manager is a comprehensive desktop GUI management tool for the Octra network, built using Rust. It is designed to handle multiple wallet files efficiently, enabling mass transactions and real-time monitoring of various accounts from a single interface.

## 🚀 Key Features

### 1. Wallet Management

* **Dynamic Loading**: Automatically scans and imports JSON wallet files from the `/wallets` directory upon startup.
* **Natural Sorting**: Smart file sorting ensures `wallet_2` appears before `wallet_10`.
* **Wallet Generator**: Built-in utility to create new Octra wallets using BIP-39 mnemonics and Ed25519 derivation.
* **Key Verification**: Mathematical validation tool to check the consistency between private keys, public keys, and derived addresses.

### 2. Transaction Capabilities

* **Batch Sending**: Send specific amounts of assets from a range of wallets to a single target address.
* **Sweep Modes**:
* **Sweep to Target**: Consolidate funds from multiple wallets into one "Master" address.
* **Sweep to Random**: Distribute funds to a random selection of addresses from `MyWallet.txt`.


* **Automated Nonce Management**: Automatically fetches the latest nonce and accounts for local pending transactions to prevent sequence collisions.

### 3. Monitoring & Tools

* **Global Balance Checker**: A specialized dashboard to view and filter balances across all loaded wallets at once.
* **Real-time Logs**: Detailed execution logs including transaction hashes, RPC responses, and error reporting.
* **Target Info**: Query the balance and nonce of any remote address without needing to import its private key.
* **Export Utilities**: Export filtered lists of wallet filenames or addresses to `.txt` files.

### 4. Customization

* **Theming**: Full support for Dark and Light display modes.
* **RPC Configuration**: Use wallet-specific RPC URLs or override them with a global default endpoint.
* **UI Scaling**: Adjustable zoom levels for different high-resolution monitor setups.

---

## 🛠 Built with Gemini AI

This application was developed with the assistance of **Gemini AI**. AI was utilized to optimize structural logic, ensure memory safety through Rust best practices, and accelerate the development of complex cryptographic signing features.

### Security & Transparency

Since this application processes private keys, transparency is paramount:

* **Auditability**: The source code is open for review. You can verify in `main.rs` that private keys are used only for local signing and are never transmitted to any third party other than your specified RPC node.
* **Manual Build**: To ensure the binary matches the source code exactly, users are encouraged to **build the project manually**. This eliminates risks associated with pre-compiled binaries from unknown sources.

---

## 📖 How to Use

### 1. Setup

1. Create a folder named `wallets` in the same directory as the application.
2. Place your wallet files (JSON) inside. Format:
```json
{
  "priv": "YOUR_PRIVATE_KEY_BASE64",
  "addr": "oct_ADDRESS",
  "rpc": ""
}

```


3. (Optional) Populate `MyWallet.txt` with a list of addresses if you plan to use the random sweep feature.

### 2. Basic Operations

* **Load**: Click **Reload Wallets** to refresh the list.
* **Check**: Navigate to **Tools > Check All Balances** for a summary of all funds.
* **Send**: Enter a target address and amount, then select the range of wallets to use for the batch.

---

## 🏗 Build Instructions

To verify the integrity of the binary, build it yourself:

1. Install [Rust](https://rustup.rs/).
2. Open your terminal in the project directory.
3. Run the following command:
```bash
cargo build --release

```


4. The generated file will be in `target/release/`.

---

Developed by Maragung.
