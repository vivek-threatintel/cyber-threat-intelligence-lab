# Day 28 – IOC Correlation & Campaign Detection System

## Overview

Today the system evolved from simple IOC detection into a **correlation-driven intelligence platform**.

Instead of treating indicators (IPs, domains, hashes) as isolated entities, the system now performs **link analysis** to identify relationships between them and group them into **attack campaigns**.

---

## Key Enhancements

### 1. Database Schema Upgrade (`ioc_database.py`)

The database schema was extended to include contextual intelligence:

* `campaign` – logical grouping of related IOCs
* `malware_family` – associated malware or toolset

**Why this matters:**
An IOC alone has limited value. Context transforms it into actionable intelligence.

---

### 2. Campaign Detection Logic (`cti_detection_engine.py`)

A new function `detect_campaign(ioc_value)` was introduced.

**Functionality:**

* Queries database for the campaign linked to a given IOC
* Performs reverse lookup to find all IOCs associated with the same campaign
* Returns a structured list of related infrastructure

**Outcome:**
The system can now automatically connect multiple indicators into a single attack narrative.

---

### 3. Pipeline Integration (`ti_pipeline.py`)

The main pipeline was updated to include campaign correlation:

* After enrichment, the system checks for campaign association
* If detected, it triggers a **high-priority alert**
* Outputs all linked IOCs belonging to the same campaign

---

## Strategic Concept – From Detection to Intelligence

Traditional detection answers:

> “Is this IP malicious?”

This system now answers:

> “What larger attack does this belong to?”

### Benefits

* **Infrastructure Mapping**
  Identifies related domains, IPs, and artifacts

* **Early Threat Expansion**
  Detect one IOC → uncover entire campaign

* **Faster Incident Response**
  Analysts get full context immediately instead of manual investigation

---

## Architecture Update

```text
CTI-Detection-Engine/
 ├── data/
 │    └── ioc_database.db
 ├── src/
 │    ├── ioc_database.py
 │    ├── cti_detection_engine.py
 │    └── ti_pipeline.py
```

---

## Limitations

* Campaign tagging is static (manual or rule-based)
* No automated clustering (ML-based grouping not implemented)
* No time-based correlation (campaign evolution not tracked)

---

## Next Steps

* Add time-based campaign tracking
* Implement automatic clustering (similar IOCs grouping)
* Generate structured intelligence reports

---

## Conclusion

This update marks a shift from **indicator-level detection** to **campaign-level intelligence**.

The system now provides not just alerts, but **context, relationships, and strategic insight** — aligning with real-world CTI workflows.

---

Day 28 complete.
