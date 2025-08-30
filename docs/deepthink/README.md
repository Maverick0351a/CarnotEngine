# CarnotEngine Implementation Kit

This repository contains the foundational architecture, code snippets, configuration files, and strategic artifacts for building **CarnotEngine**, the Quantum-Safe Transition Platform.

## Project Overview

CarnotEngine is designed to help organizations find, fix, and prove their migration to post-quantum cryptography (PQC). It addresses the urgent need to secure data against the threat of "Harvest Now, Decrypt Later" (HNDL) attacks and comply with mandates like OMB M-23-02.

The platform covers the entire lifecycle:
1.  **Discover:** SAST, Runtime (eBPF/ETW/JFR), Network, and PKI/KMS inventory (CryptoBOM).
2.  **Plan:** Risk Prioritization Engine (HNDL focused).
3.  **Automate:** Crypto-Agility SDKs, PQC Proxy, CI/CD integrations.
4.  **Verify:** Policy-as-Code (OPA) and Compliance Attestation.

## Instructions for VS Code and GitHub Copilot

This project is structured to maximize the effectiveness of GitHub Copilot for rapid prototyping and development.

### Setup

1.  **Open in VS Code:** Open the root folder (`CarnotEngine_Implementation_Kit`) in VS Code.
2.  **Install Extensions:** Ensure GitHub Copilot and Copilot Chat are active.
3.  **Language Tools:** Install relevant extensions (Python, C/C++, C#, Go, Docker, YAML, Rego).

### Using Copilot Effectively

Copilot excels when provided with clear context, established patterns, and specific instructions.

#### 1. Contextual Awareness

*   **Keep Relevant Tabs Open:** Copilot uses open tabs to infer context. Before starting a task, open related files.
    *   *Example:* When working on the `CarnotSDK.py` (Folder 8), keep `carnot_policy.json` (Folder 8) open so Copilot understands the policy structure.
    *   *Example:* When expanding the AWS inventory (Folder 4), keep the `CycloneDX_CBOM_Example.json` (Folder 9) open so Copilot understands the target data schema.

#### 2. Driving Implementation with Comments (Prompt Engineering)

*   **Detailed Comments:** Use detailed comments to guide Copilot. Describe the function's purpose, inputs, expected outputs, error handling, and specific libraries to use.

    ```python
    # Function: expand_inventory_to_azure_keyvault
    # Purpose: Inventory asymmetric keys (RSA/ECC) in Azure Key Vault using Azure SDK for Python.
    # Inputs: vault_url (str), credential (TokenCredential)
    # Outputs: List of dictionaries mapped to CarnotEngine CryptoBOM format.
    # Requirements: Handle pagination, implement exponential backoff for retries (using tenacity), log errors.
    def expand_inventory_to_azure_keyvault(vault_url, credential):
        # Copilot should now generate the implementation...
    ```

#### 3. Expanding Existing Patterns

*   **Follow the Leader:** The provided snippets establish core patterns. Use Copilot to extend them.
    *   *Task:* Add GCP KMS inventory.
    *   *Action:* Create `inventory_gcp_crypto.py` in Folder 4. Copy the structure of `inventory_aws_crypto.py` and ask Copilot (inline or via Chat) to adapt the `boto3` calls to the Google Cloud SDK.

#### 4. Specific Copilot Prompts (Use Copilot Chat)

*   **eBPF (Folder 1):** "In `CarnotEngine_openssl.bpf.c`, I need to implement the entry probe (`uprobe`) for `SSL_do_handshake`. This should capture the `SSL*` pointer and store it in a BPF hash map keyed by the current PID/TID. Then, update the exit probe (`uretprobe`) to retrieve it and use BPF_CORE_READ to access the negotiated parameters (like the negotiated group ID)."
*   **Risk Engine (Folder 5):** "Using the logic in `calculate_risk_score.py`, generate a comprehensive pytest module with 15 diverse test cases covering edge cases for algorithm types, exposure levels, and extreme secrecy lifetimes."
*   **OPA (Folder 6):** "In `pqc_migration.rego`, add a new policy: 'Systems processing data classified as 'Confidential' with a secrecy lifetime > 20 years must use PQC Level 3 algorithms (not hybrid) by 2028-01-01'. Provide sample input JSON that violates this policy."
*   **PQC Proxy (Folder 7):** "Review the Dockerfile in Folder 7. Finalize the build steps in Stage 1, ensuring specific stable tags are used for `liboqs` and `oqs-provider`. Ensure the configuration files (nginx.conf, openssl.cnf) are copied into the Stage 2 image and the paths align."
*   **CarnotSDK (Folder 8):** "In `CarnotSDK.py`, implement the `_resolve_implementation` method for 'MLDSA65'. Assume we are using the `liboqs-python` wrapper. Show the integration steps for signing and verification."

## Directory Structure

*   `1_Runtime_Discovery_eBPF/`: Linux runtime telemetry (eBPF/OpenSSL).
*   `2_Runtime_Discovery_Windows_Java_DotNet/`: Windows (ETW/SChannel) and managed runtime (JFR, .NET EventListener) telemetry.
*   `3_Network_Discovery_Zeek_QUIC/`: Passive network analysis (Zeek parser) and QUIC/ECH implications.
*   `4_PKI_KMS_Inventory_AWS/`: Cloud key and certificate inventory (AWS KMS/ACM starter).
*   `5_Risk_Prioritization_Engine/`: HNDL risk scoring formula and implementation.
*   `6_Policy_as_Code_OPA/`: Compliance and security enforcement using Open Policy Agent (Rego) and CI/CD.
*   `7_PQC_Proxy_Deployment/`: Reference architecture for the PQC/Hybrid proxy (Nginx/OQS).
*   `8_Crypto_Agility_SDK_Carnot/`: The developer-facing crypto abstraction layer (SDK).
*   `9_CryptoBOM_CycloneDX_Mapping/`: Schema mapping to the CycloneDX standard (CBOM).
*   `10_ROI_Compliance_Strategy/`: ROI model, compatibility matrices, and compliance mappings.