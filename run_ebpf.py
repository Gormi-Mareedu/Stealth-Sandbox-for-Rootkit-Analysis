import subprocess
import time
import os
import random

# ==========================================
# 1. CONFIGURATION
# ==========================================
VMRUN = r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"
VMX = r"C:\Users\tejas\OneDrive\Documents\Virtual Machines\Ubuntu 64-bit (8)\Ubuntu 64-bit (8).vmx"
GUEST_USER = "teju"          
GUEST_PASS = "teju"
OUTPUT_DIR = r"C:\VAbox\raw_data"

BACKGROUND_NOISE = [
    "sleep 2",
    "ls -laR /usr/bin > /dev/null 2>&1 &",
    "python3 -c 'sum(i*i for i in range(2000000))' &",
    "find /etc -name '*.conf' 2>/dev/null | wc -l > /dev/null &"
]

def run_vmrun(args):
    cmd = [VMRUN] + args
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res

def run_ebpf_experiment(sample_name, exec_command, run_id):
    print(f"\n[*] eBPF Run #{run_id:02d}: {sample_name} [MALICIOUS_EBPF]", flush=True)
    print("=" * 60, flush=True)
    

    # 2. Boot VM
    print("    -> Booting VM (nogui)...", flush=True)
    run_vmrun(["-T", "ws", "start", VMX, "nogui"])
    print("    -> Waiting 22 seconds for Ubuntu to initialize...", flush=True)
    time.sleep(22)

    # 3. Launch eBPF rootkit with randomized noise & variable delay
    noise = random.choice(BACKGROUND_NOISE)
    capture_delay = random.randint(4, 15)
    
    print(f"    -> Triggering payload: {sample_name} (delay: {capture_delay}s)...", flush=True)
    combined_cmd = f"{noise}; {exec_command}; sleep {capture_delay}"
    full_cmd = f"echo '{GUEST_PASS}' | sudo -S bash -c \"{combined_cmd}\""
    
    run_vmrun([
        "-T", "ws", "-gu", GUEST_USER, "-gp", GUEST_PASS,
        "runProgramInGuest", VMX, "/bin/bash", "-c", full_cmd
    ])
    print("    -> Observing BPF subsystem hooks...", flush=True)

    # 4. Extract telemetry (Including BPF state)
    print("    -> Capturing kernel, process, network, and BPF state...", flush=True)
    guest_log = f"/tmp/run_{run_id}.log"
    extract_script = (
        f"echo '===LSMOD===' > {guest_log} && lsmod >> {guest_log} && "
        f"echo '===PS===' >> {guest_log} && ps -eo pid,comm,stat,ppid >> {guest_log} && "
        f"echo '===NET===' >> {guest_log} && ss -tulpn >> {guest_log} && "
        f"echo '===BPF===' >> {guest_log} && bpftool prog show >> {guest_log}"
    )
    run_vmrun([
        "-T", "ws", "-gu", GUEST_USER, "-gp", GUEST_PASS,
        "runProgramInGuest", VMX, "/bin/bash", "-c", extract_script
    ])

    # 5. Copy to host
    host_log_path = os.path.join(OUTPUT_DIR, f"run_{run_id:02d}_MALICIOUS_EBPF.log")
    print(f"    -> Pulling telemetry to Host: run_{run_id:02d}_MALICIOUS_EBPF.log", flush=True)
    run_vmrun([
        "-T", "ws", "-gu", GUEST_USER, "-gp", GUEST_PASS,
        "CopyFileFromGuestToHost", VMX, guest_log, host_log_path
    ])

    # 6. Stop VM
    print("    -> Powering down VM...", flush=True)
    run_vmrun(["-T", "ws", "stop", VMX, "hard"])
    print(f"    [✓] eBPF Run #{run_id:02d} completed successfully.\n", flush=True)

if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    ebpf_tests = [
        ("Bad-BPF PidHide (Hide PID 1)", "cd /home/teju/samples/bad-bpf/src && ./pidhide 1 & sleep 8"),
        ("Bad-BPF SudoAdd (Privilege Hook)", "cd /home/teju/samples/bad-bpf/src && ./sudoadd & sleep 8"),
        ("Bad-BPF ExecHijack (Hook Exec)", "cd /home/teju/samples/bad-bpf/src && ./exechijack & sleep 8"),
    ]

    print("[+] Starting scaled bad-bpf automated collection (20 runs)...", flush=True)
    run_counter = 21  # Continuing ID sequence after LKM runs

    # 4 iterations across 5 test permutations = 20 distinct eBPF runs
    for iteration in range(1, 5):
        print(f"\n>>> eBPF ITERATION {iteration}/4 <<<")
        for name, cmd in ebpf_tests:
            run_ebpf_experiment(f"{name} (iter {iteration})", cmd, run_counter)
            run_counter += 1

    print("\n[+] Scaled eBPF Rootkit collection finished!", flush=True)
    os.startfile(OUTPUT_DIR)