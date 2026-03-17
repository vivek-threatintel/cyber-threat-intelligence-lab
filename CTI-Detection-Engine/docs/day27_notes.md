# Day 27 – Intelligence Memory Layer (SQLite Integration)

## Overview

Today marked a critical shift in the project: transitioning from a stateless detection pipeline to a **stateful intelligence system**.

Instead of processing IOCs and discarding results, the system now **stores and reuses intelligence**, enabling faster analysis, historical tracking, and reduced dependency on external APIs.

---

## Why Persistence is Critical in CTI

A detection pipeline without storage is fundamentally limited. By introducing a database layer, the system gains:

* **Historical Visibility**
  Ability to track when an IOC was first observed and how often it appears.

* **API Cost Optimization (Caching)**
  Previously processed IOCs are retrieved locally, avoiding repeated API calls and rate limits.

* **Correlation Foundation**
  Stored intelligence enables future analysis such as campaign tracking and attacker pattern identification.

---

## Database Design (SQLite)

A lightweight SQLite database was implemented to act as the intelligence store.

**Table: `ioc_table`**

* `ioc` (PRIMARY KEY) – unique indicator
* `type` – IP / Domain / Hash
* `source` – API / Feed / Internal
* `confidence_score` – numeric threat confidence
* `first_seen` – timestamp of initial detection

**Key Design Decision:**
Used `INSERT OR IGNORE` to prevent duplicate entries while maintaining data integrity.

---

## Pipeline Upgrade – Lookup-First Logic

The detection pipeline (`ti_pipeline.py`) was redesigned to follow a cache-first approach:

1. **Check Local Database**

   * If IOC exists → retrieve stored intelligence instantly

2. **Cache Hit**

   * No API call required
   * Faster execution, zero external dependency

3. **Cache Miss**

   * Query threat API
   * Parse and enrich data
   * Store result in database for future reuse

---

## Impact

* **Performance Improvement**
  Repeated runs are significantly faster due to reduced API calls

* **System Evolution**
  The project now behaves like a real CTI platform with memory and persistence

* **Scalability**
  Capable of handling larger datasets without redundant processing

---

## Updated Architecture

```
CTI-Detection-Engine/
 ├── data/
 │    ├── threat_feed.json
 │    └── ioc_database.db
 ├── src/
 │    ├── feed_ingestion.py
 │    ├── ioc_processor.py
 │    ├── threat_api_client.py
 │    ├── ioc_database.py
 │    └── ti_pipeline.py
```

---

## Limitations

* No indexing beyond primary key (performance may degrade at scale)
* No expiration logic for outdated IOCs
* No concurrency handling (single-process design)
* Confidence scoring is still static

---

## Next Steps

* Add IOC expiration / TTL logic
* Implement indexing for faster queries
* Introduce campaign correlation (multi-IOC linkage)
* Expand database schema for relationships

---

## Conclusion

This step transforms the project from a collection of scripts into a **persistent intelligence system**.

The addition of a database introduces memory, efficiency, and the foundation for advanced threat correlation.

---

Day 27 complete.
