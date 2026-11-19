import os
import csv

RAW_DIR = r"C:\VAbox\raw_data"
OUTPUT_CSV = r"C:\Users\tejas\OneDrive\Desktop\VAbox\vabox_dataset.csv"

rows = []

if not os.path.exists(RAW_DIR):
    print(f"[!] Directory not found: {RAW_DIR}")
    exit(1)

for filename in os.listdir(RAW_DIR):
    if not filename.endswith(".log"):
        continue
    
    filepath = os.path.join(RAW_DIR, filename)
    with open(filepath, "r", errors="ignore") as f:
        content = f.read()

    # Determine class labels
    if "MALICIOUS" in filename:
        label = 1
        subclass = "LKM" if "LKM" in filename else "EBPF"
    else:
        label = 0
        subclass = "BENIGN"

    # Safely parse text sections
    sections = {}
    current_key = "HEADER"
    for line in content.splitlines():
        if line.startswith("===") and line.endswith("==="):
            current_key = line.strip("=")
            sections[current_key] = []
        elif current_key in sections:
            sections[current_key].append(line)

    lsmod_part = "\n".join(sections.get("LSMOD", []))
    ps_part = "\n".join(sections.get("PS", []))
    net_part = "\n".join(sections.get("NET", []))
    bpf_part = "\n".join(sections.get("BPF", []))

    # Feature Engineering
    loaded_modules_count = max(0, len([l for l in lsmod_part.splitlines() if l.strip()]) - 1)
    proc_count = max(0, len([l for l in ps_part.splitlines() if l.strip()]) - 1)
    zombie_proc_count = len([l for l in ps_part.splitlines() if len(l.split()) >= 3 and 'Z' in l.split()[2]])
    open_tcp_ports = len([l for l in net_part.splitlines() if "tcp" in l.lower() and "LISTEN" in l])
    open_udp_ports = len([l for l in net_part.splitlines() if "udp" in l.lower()])
    hidden_module_anomaly = 1 if (subclass == "LKM" and "diamorphine" not in lsmod_part.lower()) else 0
    has_nfnetlink = 1 if "nfnetlink" in lsmod_part else 0
    has_cfg80211 = 1 if "cfg80211" in lsmod_part else 0
    bpf_indicator = 1 if (subclass == "EBPF" or len(bpf_part.strip()) > 0) else 0
    lsmod_text_density = len(lsmod_part.strip())

    rows.append({
        "sample_id": filename.replace(".log", ""),
        "loaded_modules_count": loaded_modules_count,
        "proc_count": proc_count,
        "zombie_proc_count": zombie_proc_count,
        "open_tcp_ports": open_tcp_ports,
        "open_udp_ports": open_udp_ports,
        "hidden_module_anomaly": hidden_module_anomaly,
        "has_nfnetlink": has_nfnetlink,
        "has_cfg80211": has_cfg80211,
        "bpf_indicator": bpf_indicator,
        "lsmod_text_density": lsmod_text_density,
        "label": label,
        "subclass": subclass
    })

fieldnames = [
    "sample_id", "loaded_modules_count", "proc_count", "zombie_proc_count", 
    "open_tcp_ports", "open_udp_ports", "hidden_module_anomaly", 
    "has_nfnetlink", "has_cfg80211", "bpf_indicator", 
    "lsmod_text_density", "label", "subclass"
]

# Ensure Excel compatibility by using utf-8-sig encoding
with open(OUTPUT_CSV, "w", newline="", encoding="utf-8-sig") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print("\n" + "="*55)
print(f"[+] Feature Extraction Complete! Saved to: {OUTPUT_CSV}")
print(f"[+] Total samples processed: {len(rows)}")
print("="*55)