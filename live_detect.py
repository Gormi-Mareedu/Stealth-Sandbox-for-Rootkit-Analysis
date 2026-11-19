import os
import time
import subprocess
from datetime import datetime
import pandas as pd
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

# ==========================================
# CONFIGURATION & PATHS
# ==========================================
CSV_PATH = r"C:\Users\tejas\OneDrive\Desktop\VAbox\vabox_dataset.csv"
RAW_DIR = r"C:\Users\tejas\OneDrive\Desktop\VAbox\raw_data"
VMRUN = r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"
VMX = r"C:\Users\tejas\OneDrive\Documents\Virtual Machines\Ubuntu 64-bit (7)\Ubuntu 64-bit (7).vmx"

GUEST_USER = "teju"
GUEST_PASS = "teju"
BOOT_WAIT_SECONDS = 20
STOP_AFTER_CAPTURE = False  # Set True if you want the VM powered off after capturing


def run_vmrun(args):
    return subprocess.run([VMRUN] + args, capture_output=True, text=True)


def is_vm_running():
    res = run_vmrun(["-T", "ws", "list"])
    return VMX.lower() in res.stdout.lower()


# ==========================================
# TRAIN / INITIALIZE MODEL
# ==========================================
df_train = pd.read_csv(CSV_PATH)
X = df_train.drop(columns=["sample_id", "label", "subclass"], errors="ignore")
y_raw = df_train["subclass"]

encoder = LabelEncoder()
y = encoder.fit_transform(y_raw)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
xgb_clf = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=4,
    random_state=42,
    eval_metric="mlogloss",
)
xgb_clf.fit(X_train, y_train)


# ==========================================
# STEP 1: POWER ON (NO REVERT) & COLLECT LOG
# ==========================================
def collect_live_log():
    os.makedirs(RAW_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    guest_tmp_log = f"/tmp/live_{timestamp}.log"
    host_log_path = os.path.join(RAW_DIR, f"live_{timestamp}.log")

    started_here = False
    if not is_vm_running():
        print("[*] VM is powered off. Powering on without reverting snapshot...")
        start_res = run_vmrun(["-T", "ws", "start", VMX, "nogui"])
        if start_res.returncode != 0:
            raise RuntimeError(f"Failed to start VM:\n{start_res.stderr or start_res.stdout}")
        started_here = True
        print(f"[*] Waiting {BOOT_WAIT_SECONDS}s for guest OS and VMware Tools...")
        time.sleep(BOOT_WAIT_SECONDS)
    else:
        print("[*] VM is already powered on. Collecting live state...")

    collect_cmd = (
        f"echo '===LSMOD===' > {guest_tmp_log} && lsmod >> {guest_tmp_log} && "
        f"echo '===PS===' >> {guest_tmp_log} && ps -eo pid,comm,stat,ppid >> {guest_tmp_log} && "
        f"echo '===NET===' >> {guest_tmp_log} && ss -tulpn >> {guest_tmp_log} && "
        f"echo '===BPF===' >> {guest_tmp_log} && (bpftool prog list 2>/dev/null || true) >> {guest_tmp_log}"
    )

    print("[*] Capturing live telemetry inside guest...")
    run_res = run_vmrun([
        "-T", "ws", "-gu", GUEST_USER, "-gp", GUEST_PASS,
        "runProgramInGuest", VMX, "/bin/bash", "-c", collect_cmd
    ])
    if run_res.returncode != 0:
        raise RuntimeError(f"Guest telemetry command failed:\n{run_res.stderr or run_res.stdout}")

    print("[*] Copying log to host...")
    cp_res = run_vmrun([
        "-T", "ws", "-gu", GUEST_USER, "-gp", GUEST_PASS,
        "CopyFileFromGuestToHost", VMX, guest_tmp_log, host_log_path
    ])
    if cp_res.returncode != 0:
        raise RuntimeError(f"Failed to copy log from guest:\n{cp_res.stderr or cp_res.stdout}")

    if STOP_AFTER_CAPTURE and started_here:
        print("[*] Powering off VM...")
        run_vmrun(["-T", "ws", "stop", VMX, "hard"])

    print(f"[+] Saved fresh log: {host_log_path}")
    return host_log_path


# ==========================================
# STEP 2: EXTRACT FEATURES FROM LOG CONTENT
# ==========================================
def extract_features(filepath):
    with open(filepath, "r", errors="ignore") as f:
        content = f.read()

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

    has_bpf_trace = 1 if len(bpf_part.strip()) > 0 else 0
    lkm_marker = 1 if ("diamorphine" in lsmod_part.lower() or "nfnetlink" in lsmod_part) else 0

    return {
        "loaded_modules_count": max(0, len([l for l in lsmod_part.splitlines() if l.strip()]) - 1),
        "proc_count": max(0, len([l for l in ps_part.splitlines() if l.strip()]) - 1),
        "zombie_proc_count": len([l for l in ps_part.splitlines() if len(l.split()) >= 3 and "Z" in l.split()[2]]),
        "open_tcp_ports": len([l for l in net_part.splitlines() if "tcp" in l.lower() and "LISTEN" in l]),
        "open_udp_ports": len([l for l in net_part.splitlines() if "udp" in l.lower()]),
        "hidden_module_anomaly": lkm_marker,
        "has_nfnetlink": 1 if "nfnetlink" in lsmod_part else 0,
        "has_cfg80211": 1 if "cfg80211" in lsmod_part else 0,
        "bpf_indicator": has_bpf_trace,
        "lsmod_text_density": len(lsmod_part.strip()),
    }


# ==========================================
# STEP 3: HYBRID DETECTION VERDICT
# ==========================================
def analyze_sample(features):
    if features["bpf_indicator"] == 1:
        return "ROOTKIT DETECTED -> EBPF [Tier 1 Rule Match: BPF trace present]"
    if features["hidden_module_anomaly"] == 1:
        return "ROOTKIT DETECTED -> LKM [Tier 1 Rule Match: LKM module/hook indicator]"

    features_df = pd.DataFrame([features])
    pred_encoded = xgb_clf.predict(features_df)[0]
    predicted_label = encoder.inverse_transform([pred_encoded])[0]

    if predicted_label == "BENIGN":
        return "NO ROOTKIT DETECTED -> BENIGN [Tier 2 ML Classifier]"
    return f"ROOTKIT DETECTED -> {predicted_label} [Tier 2 ML Classifier]"


if __name__ == "__main__":
    print("=" * 55)
    print(" VAbox LIVE ROOTKIT DETECTION ENGINE ")
    print("=" * 55)

    target_log = collect_live_log()
    features = extract_features(target_log)
    verdict = analyze_sample(features)

    print("\n" + "-" * 55)
    print(f" Log File     : {os.path.basename(target_log)}")
    print(f" FINAL VERDICT: {verdict}")
    print("-" * 55)