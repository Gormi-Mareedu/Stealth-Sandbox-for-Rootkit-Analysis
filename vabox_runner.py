import subprocess
import time
import os
import random

# ==========================================
# 1. CONFIGURATION
# ==========================================
VMRUN = r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"
VMX = r"C:\Users\tejas\OneDrive\Documents\Virtual Machines\Ubuntu 64-bit (7)\Ubuntu 64-bit (7).vmx"
SNAPSHOT_NAME = "Clean_Baseline"
GUEST_USER = "teju"          
GUEST_PASS = "teju" # <--- Keep your Ubuntu password here!
OUTPUT_DIR = r"C:\VAbox\raw_data"

# Randomized background noise pool to prevent static VM state memorization
BACKGROUND_NOISE = [
    "sleep 2",
    "ls -laR /usr/bin > /dev/null 2>&1 &",
    "python3 -c 'sum(i*i for i in range(2000000))' &",
    "find /etc -name '*.conf' 2>/dev/null | wc -l > /dev/null &",
    "dd if=/dev/zero of=/tmp/test_io bs=1M count=15 status=none && rm -f /tmp/test_io &"
]

def run_vmrun(args):
    cmd = [VMRUN] + args
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res

def run_single_experiment(sample_name, exec_command, label, run_id):
    print(f"\n[*] Run #{run_id:02d}: {sample_name} [{label}]")
    
    # 1. Revert to baseline
    run_vmrun(["-T", "ws", "revertToSnapshot", VMX, SNAPSHOT_NAME])
    time.sleep(3)

    # 2. Boot VM
    run_vmrun(["-T", "ws", "start", VMX, "nogui"])
    time.sleep(22)

    # 3. Inject random background noise + trigger scenario
    noise = random.choice(BACKGROUND_NOISE)
    capture_delay = random.randint(4, 15)  # Variable observation window
    
    combined_cmd = f"{noise}; {exec_command}; sleep {capture_delay}"
    full_cmd = f"echo '{GUEST_PASS}' | sudo -S bash -c \"{combined_cmd}\""
    
    run_vmrun([
        "-T", "ws", "-gu", GUEST_USER, "-gp", GUEST_PASS,
        "runProgramInGuest", VMX, "/bin/bash", "-c", full_cmd
    ])

    # 4. Extract telemetry
    guest_log = f"/tmp/run_{run_id}.log"
    extract_script = (
        f"echo '===LSMOD===' > {guest_log} && lsmod >> {guest_log} && "
        f"echo '===PS===' >> {guest_log} && ps -eo pid,comm,stat,ppid >> {guest_log} && "
        f"echo '===NET===' >> {guest_log} && ss -tulpn >> {guest_log}"
    )
    run_vmrun([
        "-T", "ws", "-gu", GUEST_USER, "-gp", GUEST_PASS,
        "runProgramInGuest", VMX, "/bin/bash", "-c", extract_script
    ])

    # 5. Copy log to host
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    host_log_path = os.path.join(OUTPUT_DIR, f"run_{run_id:02d}_{label}.log")
    
    run_vmrun([
        "-T", "ws", "-gu", GUEST_USER, "-gp", GUEST_PASS,
        "CopyFileFromGuestToHost", VMX, guest_log, host_log_path
    ])
    
    # 6. Stop VM
    run_vmrun(["-T", "ws", "stop", VMX, "hard"])
    print(f"  [✓] Completed (Delay: {capture_delay}s).")

if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Scenarios split into Benign and Malicious LKM pools for scaled iteration
    benign_scenarios = [
        ("Baseline Idle", "sleep 5", "BENIGN"),
        ("System Stress CPU", "stress-ng --cpu 2 --timeout 10s", "BENIGN"),
        ("Benign Web Server", "python3 -m http.server 8080 & sleep 8", "BENIGN"),
        ("Process Burst", "for i in {1..15}; do sleep 10 & done; sleep 5", "BENIGN"),
        ("Legitimate Kernel Mod", "modprobe dummy && sleep 5", "BENIGN"),
    ]

    lkm_scenarios = [
        ("Diamorphine Visible Hook", "insmod /home/teju/samples/Diamorphine/diamorphine.ko && sleep 5", "MALICIOUS_LKM"),
        ("Diamorphine Stealth Mode", "insmod /home/teju/samples/Diamorphine/diamorphine.ko && kill -63 0 && sleep 5", "MALICIOUS_LKM"),
        ("Diamorphine Hidden Task", "insmod /home/teju/samples/Diamorphine/diamorphine.ko && sleep 50 & PID=$!; kill -31 $PID && kill -63 0", "MALICIOUS_LKM"),
        ("Diamorphine Covert Net", "insmod /home/teju/samples/Diamorphine/diamorphine.ko && kill -63 0 && python3 -m http.server 9090 & sleep 5", "MALICIOUS_LKM"),
        ("Diamorphine Root Escalation", "insmod /home/teju/samples/Diamorphine/diamorphine.ko && kill -64 0 && kill -63 0", "MALICIOUS_LKM"),
    ]

    print("[+] Starting VAbox Scaled Batch Experiment Suite...")
    run_counter = 1

    # Generate 35 Benign Runs (7 iterations across 5 benign templates)
    print("\n--- COLLECTING BENIGN RUNS (35 samples) ---")
    for iteration in range(1, 8):
        for name, cmd, label in benign_scenarios:
            run_single_experiment(f"{name} (iter {iteration})", cmd, label, run_counter)
            run_counter += 1

    # Generate 20 LKM Runs (4 iterations across 5 LKM templates)
    print("\n--- COLLECTING MALICIOUS LKM RUNS (20 samples) ---")
    for iteration in range(1, 5):
        for name, cmd, label in lkm_scenarios:
            run_single_experiment(f"{name} (iter {iteration})", cmd, label, run_counter)
            run_counter += 1

    print("\n[+] VAbox Benign & LKM batch complete!")