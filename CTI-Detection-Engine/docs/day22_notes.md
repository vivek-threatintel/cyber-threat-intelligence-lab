# Day 22 – Security Dataset & Feature Extraction

Today was the bridge from rule-based detection to **data-driven detection**.  
Instead of hard-coded thresholds, we treated security logs as real data: loaded them from JSON, extracted meaningful features, calculated a basic risk score, classified risk levels, and summarized results.

This is the exact first step in any real ML-based security project — good features are 80% of the work.

## Files Created / Updated

- `data/security_events.json` – Sample dataset with IP, failed_logins, data_transfer (KB), requests
- `src/feature_extraction.py` – Main script for loading, feature extraction, risk scoring, and reporting

## Code Breakdown (feature_extraction.py)

### 1. Loading the dataset

```python
def load_dataset(file_path="data/security_events.json"):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        print(f"Total Events Loaded: {len(data)}")
        return data
    except Exception as e:
        print(f"Error loading dataset: {e}")
        return []

2. Feature ExtractionConverts raw event into numeric features:python

def extract_features(event):
    return {
        "login_risk": event.get("failed_logins", 0),
        "transfer_risk": event.get("data_transfer", 0),
        "request_intensity": event.get("requests", 0)
    }

3. Risk Score CalculationSimple weighted sum:python

def calculate_risk_score(features):
    score = features["login_risk"] * 2
    score += features["transfer_risk"] / 100
    score += features["request_intensity"] / 10
    return score

4. Risk Level ClassificationThreshold-based:python

def get_risk_level(risk_score):
    if risk_score > 50:
        return "HIGH RISK"
    elif risk_score > 20:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"

5. Clean PrintingModular function for readable output:python

def print_results(event, features, risk_score):
    print(f"IP: {event['ip']}")
    print(f"  Login Risk: {features['login_risk']}")
    print(f"  Transfer Risk: {features['transfer_risk']}")
    print(f"  Request Intensity: {features['request_intensity']}")
    print(f"  Risk Score: {risk_score:.2f}")
    print("---")

Final SummaryCounts high/medium/low risk events and shows total.Sample Output (from a run)

Total Events Loaded: 4
IP: 103.45.67.89
  Login Risk: 10
  Transfer Risk: 900
  Request Intensity: 50
  Risk Score: 34.00
---
  Risk Level: MEDIUM RISK
IP: 8.8.8.8
  Login Risk: 0
  Transfer Risk: 50
  Request Intensity: 10
  Risk Score: 1.50
---
  Risk Level: LOW RISK
IP: 23.21.11.90
  Login Risk: 3
  Transfer Risk: 200
  Request Intensity: 15
  Risk Score: 9.50
---
  Risk Level: LOW RISK
IP: 192.168.1.10
  Login Risk: 1
  Transfer Risk: 40
  Request Intensity: 8
  Risk Score: 3.20
---
  Risk Level: LOW RISK

SUMMARY
Total Events: 4
High Risk Events: 0
Medium Risk Events: 1
Low Risk Events: 3

Key Learning PointsFeature extraction is the hardest and most important part of security ML
Raw logs are useless to models — features make them usable
Good features = good detection
Simple weighted scoring already gives strong signals
Login risk gets higher weight (×2) because failed logins are a powerful indicator
Modular functions (load, extract, calculate, print) make code easy to extend

LimitationsHard-coded weights in risk score (real-world: learned from data)
No normalization (features on different scales)
No advanced features (e.g., failed_logins per minute, time of day)
No real anomaly detection yet (just thresholds)

Day 22 complete.
Now we have structured data and basic feature engineering — ready for proper anomaly detection tomorrow.— Vivek | ThreatIntel
