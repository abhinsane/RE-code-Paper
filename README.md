# Post-Quantum Secure E-Voting System

A prototype electronic voting system combining **Blockchain**, **Fully Homomorphic Encryption (FHE)**, **Zero-Knowledge Proofs (ZKP)**, **Post-Quantum Cryptography (PQC)**, and **Cancellable Biometrics** — designed to be secure against quantum adversaries.

---

## System Requirements

### Operating System

| Platform | Status |
|---|---|
| Linux (x86_64) | Fully supported (tested on Ubuntu 20.04+) |
| macOS (x86_64 / Apple Silicon) | Supported |
| Windows 10/11 | Supported via WSL2 (native may have TenSEAL build issues) |

### Python

**Python 3.10 or later is required.** Tested on **Python 3.11**.

```bash
python3 --version (3.10)
```

### Hardware

| Resource | Minimum | Recommended |
|---|---|---|
| RAM | 4 GB | 8 GB+ |
| CPU | Any x86_64 | 4+ cores (FHE is CPU-bound) |
| Disk | 500 MB | 2 GB (SOCOFing dataset ~750 MB) |

### Required Python Packages

All packages are listed in `requirements.txt`. Verified working versions:

| Package | Min Version | Tested Version | Purpose |
|---|---|---|---|
| `pqcrypto` | 0.4.0 | 0.4.0 | ML-KEM-768 / ML-DSA-65 (NIST FIPS 203/204) |
| `tenseal` | 0.3.16 | 0.3.16 | BFV Fully Homomorphic Encryption |
| `numpy` | 2.0 | 2.4.2 | Lattice arithmetic, ZKP vectors |
| `scipy` | 1.0 | latest | Statistical utilities |
| `scikit-learn` | 1.0 | latest | Biometric template utilities |
| `opencv-python-headless` | 4.0 | 4.13.0 | ORB fingerprint feature extraction |
| `Pillow` | 10.0 | latest | Image I/O for fingerprint BMP files |
| `cryptography` | 41.0 | 41.0.7 | AES-256-GCM, SHA3 |
| `streamlit` | 1.40 | 1.55.0 | Web dashboard |
| `plotly` | 5.0 | 6.6.0 | Results bar charts |
| `web3` | 6.0 | 7.14.1 | Ethereum integration (optional) |
| `matplotlib` | 3.0 | latest | Diagram and evaluation figure generation |
| `eth-account` | 0.9.0 | latest | Ethereum account management |
| `eth-tester` | 0.8.0 | latest | In-memory EVM backend for testing |
| `py-evm` | 0.5.0 | latest | PyEVM backend for eth-tester |

---

## Repository Structure

```
pq_evoting/
├── config.py                                              # All cryptographic parameters & tuning constants
├── pq_crypto.py                                           # ML-KEM-768 + ML-DSA-65 + AES-256-GCM primitives
├── cancellable_biometric.py                           # Gabor+HOG BioHashing + SOCOFing image loader
├── fhe_voting.py                                         # BFV homomorphic vote encryption & tallying
├── zkp.py                                                # Lattice ZKP (two-component Sigma + CDS OR proofs)
├── blockchain.py                                         # SHA3-256 chain with PoW + ML-DSA-65 signed blocks
├── voter.py                                              # Voter registration, registry, biometric lockout
├── voting_system.py                                      # ElectionAuthority + Voter orchestration classes
└── __init__.py

contracts/
└── VotingLedger.sol         # Solidity 0.8.20 smart contract (Hardhat/Ganache)

eth_integration/
├── __init__.py              # Module exports (EthBridge)
└── bridge.py                # EthBridge: live Web3 or in-memory simulation

gui/
└── app.py                   # Streamlit 5-tab web dashboard

scripts/
└── deploy.js                # Hardhat deployment script for VotingLedger.sol

diagrams/
├── fig1_system_architecture.py/png    # Overall system architecture


paper/
├── benchmarks.md            # Per-operation latency & scalability data (Section 6)                       
├── strengths.md                                    
├── vulnerabilities.md       
├── far-reduction.md         # FAR/FRR ablation study details
├── fhe-noise-explainer.md   # BFV noise budget explanation
└── expandability.md         # Future work and system expansion

test result/
├── benchmark.py                            # Per-operation & end-to-end latency benchmarks
├── eval_biometric.py                     # FAR/FRR/EER evaluation on SOCOFing
├── fig8_bio_score_distribution.py/png    #  Genuine vs impostor histogram
├── fig9_det_curve.py/png                  # DET curve (ISO/IEC 19795-1)
├── fig10_roc_curve.py/png                 # ROC curve with AUC
└── fig11_ablation.py/png                  # FAR reduction ablation chart

SOCOFing/                     # Fingerprint dataset (not included — download separately)
└── Real/                    # 6,000 BMP images, 600 subjects

demo.py                      # CLI (end-to-end demonstration)
eval_biometric.py            # (Root-level) biometric evaluation script
benchmark.py                 # (Root-level) benchmark script
bio_eval_results.txt         # biometric evaluation output
requirements.txt             # Python dependencies
```

---

## Installation

### Step 1 — Clone the repository

```bash
git clone <repo-url>
cd RE-code
```

### Step 2 — Create a virtual environment

```bash
python3 -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

### Step 3 — Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> If `tenseal` fails to build, install the system build tools first:
> ```bash
> # Ubuntu / Debian
> sudo apt install build-essential cmake libssl-dev
>
> # Fedora / RHEL
> sudo dnf install gcc gcc-c++ cmake openssl-devel
>
> # macOS
> xcode-select --install && brew install cmake openssl
> ```

### Step 4 — Verify the installation

```bash
python3 -c "
import pqcrypto, tenseal, cv2, cryptography, streamlit
print('All core dependencies imported successfully.')
"
```

---

## Running the System

### Option A — Streamlit Web Dashboard

The dashboard provides a 5-tab GUI for the full election lifecycle.

```bash
streamlit run gui/app.py
```

Open **http://localhost:8501** in your browser.

| Tab | What it does |
|---|---|
| **Setup** | Configure election name, candidate list, PoW difficulty, and Ethereum RPC |
| **Register** | Enrol voters — upload a SOCOFing fingerprint image (BMP/PNG) |
| **Vote** | Biometric authentication + cast an FHE-encrypted, ZKP-proven ballot |
| **Results** | Plotly bar chart of the tally + ML-DSA-65 signature verification |
| **Chain** | PQ-blockchain explorer (block hashes, Merkle roots) + Ethereum event log |

Typical session flow inside the GUI:

1. **Setup** tab → set candidates → click *Initialise Election*
2. **Register** tab → add each voter (name + fingerprint)
3. **Vote** tab → for each voter: enter voter ID, upload fingerprint, pick candidate → *Cast Vote*
4. **Results** tab → click *Finalise & Tally* → view results and verify authority signature
5. **Chain** tab → inspect blockchain blocks and Ethereum anchor transaction

---

### Option B — CLI Demo (`demo.py`)

Runs the complete election lifecycle in one command without the GUI.
A SOCOFing dataset path is required (see [SOCOFing Dataset Setup](#socofing-dataset-setup)).

#### Common usage

```bash
# Simulate 5 voters using SOCOFing images
python3 demo.py --dataset ./SOCOFing

# Simulate a specific number of voters
python3 demo.py --dataset ./SOCOFing --voters 5

# Show per-block blockchain summary at the end
python3 demo.py --dataset ./SOCOFing --voters 5 --show-chain

# Full run with chain dump
python3 demo.py --dataset ./SOCOFing --voters 8 --show-chain
```

#### CLI argument reference

| Argument | Short | Default | Description |
|---|---|---|---|
| `--dataset PATH` | `-d` | required | Path to SOCOFing root dir (must contain `Real/` sub-folder). |
| `--voters N` | `-n` | `5` | Number of voters to simulate |
| `--show-chain` | — | off | Print a summary of every blockchain block after the election |

#### What the demo does (step by step)

1. Generates ML-KEM-768 and ML-DSA-65 key pairs for the election authority
2. Sets up the BFV FHE context and the lattice ZKP parameters
3. Mines the genesis block (PoW difficulty = 4)
4. Loads fingerprint images from `SOCOFing/Real/`
5. Registers each voter with an encrypted cancellable biometric template
6. Each voter biometrically authenticates (Hamming distance check)
7. Each voter casts an AES-256-GCM encrypted, ML-DSA-65 signed, ZKP-proven ballot
8. The authority validates every ballot (signature + ZKP + nullifier check)
9. Votes are accumulated via BFV additive homomorphism (no decryption mid-tally)
10. Election is finalised: blockchain verified, FHE tally decrypted once, results signed
11. Template cancellation is demonstrated for one voter

---

## SOCOFing Dataset Setup

The system supports the [Sokoto Coventry Fingerprint Dataset (SOCOFing)](https://www.kaggle.com/datasets/ruizgara/socofing) — 6,000 BMP fingerprint images from 600 subjects.

Expected directory layout:

```
SOCOFing/
└── Real/
    ├── 1__M_Left_index_finger.BMP
    ├── 1__M_Left_little_finger.BMP
    ├── 2__F_Right_thumb_finger.BMP
    └── ...
```

Download and extract the dataset, then pass its root path to `demo.py` via `--dataset` or set it in the GUI **Setup** tab.

---

## Ethereum Integration

### In-Memory Mode (default — no external tools required)

The `EthBridge` runs a Python simulation of `VotingLedger.sol`. It generates Ethereum-style checksummed addresses and SHA3-based transaction hashes. Zero configuration needed — works immediately after `pip install`.

### Live Local Ethereum (Hardhat)

```bash
# Install Node.js toolchain (if not already installed)
npm install --save-dev hardhat @nomiclabs/hardhat-ethers ethers

# Compile the contract
npx hardhat compile

# Start a local Ethereum node
npx hardhat node          # listens at http://localhost:8545

# Deploy VotingLedger.sol
npx hardhat run scripts/deploy.js --network localhost
```

Then export the deployed address and start the GUI:

```bash
export ETH_RPC_URL=http://localhost:8545
export ETH_CONTRACT_ADDR=0xYourDeployedContractAddress
streamlit run gui/app.py
```

### Public Testnet (Sepolia)

```bash
export ETH_RPC_URL=https://sepolia.infura.io/v3/<YOUR_PROJECT_ID>
export ETH_CONTRACT_ADDR=0xYourSepoliaContractAddress
streamlit run gui/app.py
```

Fund the deployer wallet with Sepolia test ETH from any public faucet before deploying.

---

## Cryptographic Architecture

| Layer | Algorithm | Standard | Purpose |
|---|---|---|---|
| Key Encapsulation | ML-KEM-768 (Kyber) | NIST FIPS 203 | Hybrid encryption of biometric templates and votes |
| Digital Signatures | ML-DSA-65 (Dilithium) | NIST FIPS 204 | Vote signing, block signing, result signing |
| Symmetric Encryption | AES-256-GCM | NIST SP 800-38D | Payload encryption under ML-KEM shared secret |
| Key Derivation | SHAKE256 | NIST FIPS 202 | KDF from ML-KEM shared secret |
| Hashing | SHA3-256 / SHAKE256 | NIST FIPS 202 | Blockchain, Merkle trees, commitments |
| Homomorphic Encryption | BFV (TenSEAL) | — | Encrypted vote tallying without decryption |
| Zero-Knowledge Proofs | Ajtai + Fiat-Shamir | Lattice-based | Range proof: vote ∈ {0, …, n−1} |
| Biometrics | BioHashing (Gabor + HOG + QR) | ISO/IEC 24745 | Cancellable fingerprint templates |

ZKP parameters: `q = 2³¹ − 1` (Mersenne prime), `n = 128`, `m = 256`, `β = 2000`.

---

## Security Properties

| Property | Mechanism |
|---|---|
| Voter anonymity | FHE: votes tallied encrypted; ZKP: no vote value revealed |
| Voter authenticity | ML-DSA-65 signature + biometric BioHash verification |
| Double-vote prevention | SHA3-256(voter_id ‖ election_id) nullifier registry on blockchain |
| Template privacy | ML-KEM-768 encryption + AES-256-GCM |
| Template cancelability | BioHash regenerated with new PIN if compromised |
| Ballot integrity | Merkle tree batching + ML-DSA-65 signed blocks |
| Result integrity | ML-DSA-65 signed final tally + SHA3 commitment |
| Quantum resistance | All primitives from NIST PQC standards (FIPS 203/204) |
| Immutability | SHA3-256 chained blocks + Ethereum smart contract anchoring |
| Brute-force protection | 5-attempt lockout with 5-minute timeout on biometric auth |
| Voter registry | SQLite-backed with write-through cache and append-only audit log |

---

## Performance Benchmarks

Measured on: Python 3.11, Windows 11, Intel x86_64, single CPU core, no hardware acceleration.
Run `python "test result/benchmark.py"` to reproduce on your machine.

### Per-Operation Latency

| Operation | Time (ms) | Runs |
|---|---|---|
| BioHash extraction (Gabor+HOG) | 7505.86 | 10 |
| ML-KEM-768 key generation | 1.29 | 20 |
| ML-KEM-768 encrypt | 1.90 | 20 |
| ML-KEM-768 decrypt | 0.19 | 20 |
| ML-DSA-65 sign | 1.89 | 50 |
| ML-DSA-65 verify | 0.56 | 50 |
| FHE vote encrypt (BFV) | 16.10 | 5 |
| ZKP generate | 4.07 | 10 |
| ZKP verify | 0.55 | 10 |

### End-to-End Phase Latency

| Phase | Time (ms) | Breakdown |
|---|---|---|
| Enrollment | ~7509 | BioHash + KEM-keygen + KEM-enc |
| Authentication | ~7506 | BioHash + KEM-dec |
| Vote casting | ~22 | FHE-enc + ZKP-gen + DSA-sign |

### Scalability (ShardedFHETally, shard = 3200 votes)

| N voters | Enrollment (s) | Shards | Tally est. |
|---|---|---|---|
| 100 | ~751 | 1 | ~1 s |
| 1,000 | ~7,509 | 1 | ~1 s |
| 5,000 | ~37,545 | 2 | ~2 s |
| 10,000 | ~75,090 | 4 | ~4 s |

> **Note:** BioHash dominates enrollment/auth (pure-Python Gabor+HOG). All PQ crypto primitives are sub-2 ms. In aacutal scenario deployment, hardware-accelerated biometric processing can be reduce BioHash to ~20–50 ms (possibility).

---

## Limitations and Future Work

- **BFV noise growth**: Supports ~16,000 votes per shard (BFV degree=16384) before noise exceeds the plaintext modulus. ShardedFHETally removes the ceiling by distributing votes across independent shards of ≤3,200 votes each.
- **Biometric accuracy**: Evaluated on SOCOFing (Real + Altered, 8,189 genuine / 40,945 impostor pairs): EER = 2.61% at threshold 0.818. FAR at ISO FRR operating points remains high due to score distribution overlap; multi-impression enrollment or an SVM classifier would reduce it further (see `paper/far-reduction.md`).
- **ZKP-FHE binding**: The lattice ZKP and BFV ciphertext are currently independent; a full binding requires a Proof of Knowledge of BFV plaintext (active research area).



---

## Comparison with Research Literature

| Property | This System | Helios [Adida 2008] | Belenios [Cortier 2013] | PQ-Vote [Chillotti 2021] |
|---|---|---|---|---|
| Post-quantum secure | Yes (ML-KEM + ML-DSA) | No (RSA/ECC) | No (ECC) | Partial (FHE only) |
| Biometric auth | Yes (cancellable) | No | No | No |
| Homomorphic tally | Yes (BFV/FHE) | Yes (ElGamal) | Yes (ElGamal) | Yes (TFHE) |
| Zero-knowledge proofs | Yes (lattice) | Yes (DL-based) | Yes (DL-based) | No |
| Blockchain anchoring | Yes (SHA3 + ETH) | No | No | No |
| Template cancelability | Yes (ISO 24745) | N/A | N/A | N/A |
| End-to-end verifiable | Yes | Yes | Yes | Partial |
| Quantum-safe signatures | Yes (ML-DSA-65) | No | No | No |

---

## References

1. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM / Kyber), 2024
2. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium), 2024
3. Fan & Vercauteren — "Somewhat Practical Fully Homomorphic Encryption" (BFV), 2012
4. Ajtai — "Generating Hard Instances of Lattice Problems", STOC 1996
5. Jin et al. — "Biohashing: Two Factor Authentication Featuring Fingerprint Data and Tokenised Random Number", Pattern Recognition 2004
6. Shehu & Ruiz-Garcia — "SOCOFing: Sokoto Coventry Fingerprint Dataset", 2018
7. Adida — "Helios: Web-based Open-Audit Voting", USENIX Security 2008

---

## License

This project is for research and educational purposes.
