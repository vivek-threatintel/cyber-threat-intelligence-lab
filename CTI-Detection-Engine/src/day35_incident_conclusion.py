def generate_incident_conclusion(host, phases, score, priority):
    """
    Day 35: SOC Case Closure Simulation.
    Final summary of the attack chain and risk assessment.
    """
    print("\n" + "█" * 45)
    print("      ⚠️  INCIDENT CONFIRMED: ATTACK SUMMARY      ".center(45))
    print("█" * 45)

    # mapping phases to MITRE tatics for the final report
    tactic_map = {
        "Brute Force": "Initial Access",
        "C2 Beacon": "Command & Control",
        "Suspicious Upload": "Execution",
        "IOC Match": "Threat Intelligence"
    }

    print(f"\n[!] Target Host : {host}")
    print(f"[!] Risk Level :{priority} (Score: {score})")

    print("\n--- 🕵️ RECONSTRUCTED ATTACK CHAIN ---")
    for phase in phases:
        tactic = tactic_map.get(phase, "Unknow Tactic")
        print(f" ✅ {tactic}: {phase.lower()}")

    print("\n[VERDICT]: TRUE POSITIVE - SYSTEM BREACH CONFIRMED")
    print("[STATUS] : CASE CLOSED & ESCALATED FOR REMEDIATION")
    print("█" * 45 + "\n")

# --- Simulation ---
if __name__ == "__main__":
    # final data after investigation
    target = "host1"
    detected_phases = ["Brute Force", "C2 Beacon", "Suspicious Upload"]
    final_score = 14
    final_priority = "CRITICAL"

    generate_incident_conclusion(target, detected_phases, final_score, final_priority)