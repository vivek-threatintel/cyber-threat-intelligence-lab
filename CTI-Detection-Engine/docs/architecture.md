# Detection Engine Architecture

## High-Level Flow

Event Log Input
   ↓
Load Baseline + Threat Feed + Lookup
   ↓
For each event:Detect Anomaly (deviation from baseline)
Match IOC (threat feed + lookup enrichment)
Generate Alert Level (CRITICAL / HIGH / MEDIUM / SAFE)
   ↓
Print Alert (with reasons & context)
   ↓
Print Summary Report



## Layers

1. **Data Layer** – load_lookup(), load_feed(), load_baseline()
2. **Anomaly Layer** – detect_anomaly()
3. **Intelligence Layer** – match_intelligence()
4. **Decision Layer** – generate_alert()
5. **Reporting Layer** – print alerts + summary
