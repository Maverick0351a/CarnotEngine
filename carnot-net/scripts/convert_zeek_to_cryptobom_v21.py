# 3_Network_Discovery_Zeek_QUIC/convert_zeek_to_cryptobom_v21.py
import json
import pandas as pd
import logging

logger = logging.getLogger(__name__)

def convert_zeek_to_cryptobom_v21(ssl_log_path, x509_log_path):
    """
    Converts Zeek ssl.log and x509.log (JSON format) into CryptoBOM v2.1 observations.
    """
    try:
        # Load logs (assuming Zeek JSON output: one JSON object per line)
        ssl_df = pd.read_json(ssl_log_path, lines=True)
        # x509_df = pd.read_json(x509_log_path, lines=True) # Implementation pending X509 linkage
    except Exception as e:
        logger.error(f"Error loading Zeek logs: {e}")
        return {"schema_version": "2.1", "observations": [], "errors": [str(e)]}

    # Future Step 1: Map X509 FUIDs (File Unique IDs) to certificate details.
    # This requires processing x509.log and creating a lookup map for certificate metadata.
    # This map is then used via ssl_df['cert_chain_fuids'].

    observations = []
    # Handle potential missing columns gracefully
    required_cols = ['uid', 'id.resp_h']
    if not all(col in ssl_df.columns for col in required_cols):
        logger.error("Missing required columns (uid or id.resp_h) in ssl.log")
        return {"schema_version": "2.1", "observations": []}

    for index, row in ssl_df.iterrows():
        
        # 'curve' in Zeek holds the negotiated KEM/ECDHE group (e.g., X25519MLKEM768)
        key_exchange_group = row.get('curve')

        observation = {
            "observation_id": f"zeek-{row['uid']}",
            "source_type": "network_passive_carnot",
            "asset_id": f"ip:{row['id.resp_h']}:{row.get('id.resp_p', 'N/A')}",
            "tls_posture": {
                "version": row.get('version'),
                "ciphersuite": row.get('cipher'),
                "key_exchange_group": key_exchange_group,
                "sni": row.get('server_name'),
            },
            "certificate_metadata": {} # TODO: Populate using X509 linkage
        }
        
        observations.append(observation)

    return {"schema_version": "2.1", "observations": observations}

# Example Usage (requires sample ssl.log/x509.log files)
# if __name__ == "__main__":
#     logging.basicConfig(level=logging.INFO)
#     # result = convert_zeek_to_cryptobom_v21("ssl.log", "x509.log")
#     # print(json.dumps(result, indent=2))