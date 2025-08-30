# 5_Risk_Prioritization_Engine/calculate_risk_score.py

# CarnotEngine Risk Prioritization Engine
# Formula: RiskScore = (AlgorithmRisk + StandardsGap) * ExposureWeight * SecrecyLifetimeWeight

# Component Definitions and Defaults

ALGORITHM_RISK = {
    "RSA_1024": 10,
    "ECC_P192": 10,
    "RSA_2048": 8,
    "RSA_3072": 6,
    "RSA_4096": 6,
    "ECC_P256": 6,
    "ECC_P384": 6,
    "HYBRID_PQC": 3,  # Hybrid mitigates risk but indicates transition phase
    "PQC_NIST": 0,    # FIPS 203/204/205 compliant
    "UNKNOWN": 5      # Default risk for unidentified algorithms
}

STANDARDS_GAP = {
    "PROHIBITED": 5,     # e.g., TLS 1.0/1.1, SHA-1
    "NON_COMPLIANT": 3,  # e.g., Missing PQC roadmap for M-23-02, approaching deadline
    "COMPLIANT": 0
}

EXPOSURE_WEIGHT = {
    "PUBLIC_INTERNET": 5,
    "EXTERNAL_B2B": 3,
    "INTERNAL": 1
}

def get_secrecy_lifetime_weight(years):
    """Calculates weight based on HNDL (Harvest Now, Decrypt Later) risk duration."""
    if years > 30: return 10  # Critical long-term secrets
    if years > 10: return 5   # Significant HNDL risk
    if years >= 1: return 2
    return 1                  # Ephemeral data

def calculate_risk_score(algorithm, standards_status, exposure, secrecy_lifetime_years):
    """Calculates the CarnotEngine PQC Risk Score."""
    
    # Get component scores, using defaults for unknowns
    alg_risk = ALGORITHM_RISK.get(algorithm, ALGORITHM_RISK["UNKNOWN"])
    std_gap = STANDARDS_GAP.get(standards_status, 0)
    exp_weight = EXPOSURE_WEIGHT.get(exposure, 1)
    lifetime_weight = get_secrecy_lifetime_weight(secrecy_lifetime_years)
    
    # Calculate total score
    # Max possible score: (10 + 5) * 5 * 10 = 750
    score = (alg_risk + std_gap) * exp_weight * lifetime_weight
    
    # Determine severity level based on thresholds
    if score > 500: severity = "CRITICAL"
    elif score >= 250: severity = "HIGH"
    elif score >= 50: severity = "MEDIUM"
    else: severity = "LOW"
    
    return {
        "score": score,
        "severity": severity,
        "components": {
            "algorithm_risk": alg_risk,
            "standards_gap": std_gap,
            "exposure_weight": exp_weight,
            "lifetime_weight": lifetime_weight
        }
    }

# Test Vectors (Run with pytest or similar)
def test_risk_engine():
    # Test Case 1: Critical HNDL Risk (Long life data, public facing, weak RSA)
    # Score: (8+3)*5*10 = 550, CRITICAL
    tc1 = calculate_risk_score("RSA_2048", "NON_COMPLIANT", "PUBLIC_INTERNET", 50)
    assert tc1["score"] == 550
    assert tc1["severity"] == "CRITICAL"

    # Test Case 2: Medium Internal Risk (Medium life data, internal, weak RSA)
    # Score: (8+3)*1*5 = 55, MEDIUM
    tc2 = calculate_risk_score("RSA_2048", "NON_COMPLIANT", "INTERNAL", 15)
    assert tc2["score"] == 55
    assert tc2["severity"] == "MEDIUM"

    # Test Case 3: Low Risk (PQC implemented)
    # Score: (0+0)*5*10 = 0, LOW
    tc3 = calculate_risk_score("PQC_NIST", "COMPLIANT", "PUBLIC_INTERNET", 50)
    assert tc3["score"] == 0
    assert tc3["severity"] == "LOW"
    
    print("All Risk Engine tests passed.")

if __name__ == "__main__":
    test_risk_engine()