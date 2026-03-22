# Day 21 – Turning the Detection Engine into a Portfolio-Ready GitHub Project

Today was not about adding new features or logic.  
The entire focus was on **packaging the detection engine** we built (Days 18–20) into a proper, professional GitHub repository that looks like real work — something recruiters actually notice and respect.

Most people upload raw code with no structure or docs.  
That gets skipped in 5 seconds.  
We made sure this repo stands out.

## Final Project Structure (after Day 21)

CTI-Detection-Engine/
├── data/
│   ├── external_feed.json       # Recent threat IOCs
│   ├── ioc_lookup.json          # Static IOC metadata
│   └── sample_logs.json         # Demo event logs (easy to run)
├── src/
│   └── detection_engine.py      # The main modular engine
├── docs/
│   └── architecture.md          # High-level flow & explanation
├── README.md                    # Project overview + how to run
└── week3_learning_notes.md      # Full Week 3 summary & CTI insights



## What Was Done Today (Step-by-Step)

1. **Created clean folder layout**  
   - Separated data, source code, and documentation  
   - Made it look intentional and organized

2. **Moved files properly**  
   - Data files → `data/` folder  
   - Main script → `src/detection_engine.py`  
   - Architecture explanation → `docs/architecture.md`

3. **Wrote a strong README.md**  
   - Project title & purpose  
   - Features list  
   - Installation & usage instructions  
   - Alert rules explanation  
   - Sample output  
   - Future improvements section

4. **Created architecture.md**  
   - Simple text diagram of the detection flow  
   - Short explanation of each layer (load → anomaly → intel → alert → summary)

5. **Added sample_logs.json**  
   - Made the project instantly runnable without needing external files

6. **Wrote Week 3 learning summary**  
   - Key takeaways from Days 18–20  
   - CTI insights (correlation, anomaly, false positives)  
   - Current limitations & future ideas

## Why This Step is Important

- Recruiters & hiring managers scan repos in <10 seconds  
- Clean structure + good README = "this person understands professionalism"  
- Messy code + no docs = instant skip  
- Sample data + clear instructions = they can run it immediately  
- Architecture doc = shows you think about design, not just coding

## What the Engine Does (Quick Recap for README)

- Loads threat feed, IOC lookup, and baseline  
- Detects anomalies (deviation from normal)  
- Matches IOCs and pulls enrichment  
- Generates prioritized alerts (CRITICAL / HIGH / MEDIUM / SAFE)  
- Prints clean alerts with reasons & context  
- Ends with summary report

## Limitations (honest)

- Static baseline & thresholds  
- Hard-coded logs (no real-time input)  
- No user/entity context  
- No persistence (alerts not saved)  
- Simple rules (no statistical/ML scoring)

Day 21 complete.  
The detection engine is now **portfolio-ready**: structured, documented, runnable, and looks like real work.

— Vivek | ThreatIntel
