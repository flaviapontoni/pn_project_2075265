import subprocess, threading, time
try:
    import matplotlib.pyplot as plt
    HAS_PLT = True
except ImportError:
    HAS_PLT = False

# paramentri globali
C_LINK    = 100.0    # Mbps   data link capacity
RTT       = 0.005    # RTT simulato (tc netem 0.5ms * 2 hops * 5)
ALPHA     = 1.5      # fattore di sicurezza sul prodotto banda-ritardo teorico
BASE_PORT = 5000     # schema porte deterministico: w1->5001, w2->5002, ...

TRAININGS = [
    {"name":"blue",   "senders":["w1","w2","w3","w4","w5","w6","w7","w8","w9","w10"],
     "collector":"c1","collector_ip":"10.0.1.1","D":50,  "T":30,"phi":1,  "cycles":4},
    {"name":"green",  "senders":["w11","w12","w13","w14","w15","w16","w17","w18"],
     "collector":"c2","collector_ip":"10.0.1.2","D":62.5,"T":40,"phi":2.5,"cycles":4},
    {"name":"red",    "senders":["w19","w20","w21","w22","w23","w24"],
     "collector":"c3","collector_ip":"10.0.1.3","D":83.35,"T":30,"phi":4, "cycles":4},
    {"name":"yellow", "senders":["w25","w26","w27","w28"],
     "collector":"c4","collector_ip":"10.0.1.4","D":125, "T":40,"phi":5,  "cycles":4},
]

# Funzioni di utilità
def get_container_map():
    r = subprocess.run(["docker","ps","--format","{{.Names}}"],
                       capture_output=True, text=True)
    m = {}
    for name in r.stdout.strip().split("\n"):
        parts = name.split("_")
        if len(parts) >= 2:
            m[parts[-2]] = name
    return m
#wrapper centrale per eseguire comandi dentro i container docker
def docker_exec(node, cmd, cmap, sync=False):
    if node not in cmap:
        print(f"[ERROR] {node} not found in docker ps"); return
    full = ["docker","exec",cmap[node]] + cmd
    if sync:
        return subprocess.run(full, capture_output=True, text=True).stdout.strip()
    subprocess.Popen(full)

def compute_window_bytes(f_v):
    return int(ALPHA * (f_v * 1e6) * RTT / 8)

def get_worker_port(worker):
    return BASE_PORT + int(worker[1:])  

# server iperf3 
def start_servers(cmap):
    used = set()
    for cfg in TRAININGS:
        for w in cfg["senders"]:
            port = get_worker_port(w)
            if port not in used:
                print(f"[SERVER] starting on {cfg['collector']}:{port}")
                docker_exec(cfg["collector"],
                            ["iperf3","-s","-D","-p",str(port)], cmap)
                used.add(port)

# client iperf3
def start_client(worker, ip, port, D_mbit, f_v, cmap):
    window = compute_window_bytes(f_v)
    nbytes = int(D_mbit * 1e6 / 8)
    cmd = (f"iperf3 -c {ip} -p {port} -n {nbytes} -w {window} "
           f"--set-mss 1460 --no-delay > /dev/null 2>&1 &")
    print(f"[FLOW] {worker} -> {ip}:{port}  D={D_mbit}Mb  rate={f_v:.1f}Mbps")
    docker_exec(worker, ["bash","-c",cmd], cmap)

# monitoraggio del traffico in uscita/ingresso dei container
#legge dal kernel i byte trasmessi/ricevuti da eth0 e li converte in Mbps
def get_bytes(node, direction, cmap):
    out = docker_exec(node,
                      ["cat",f"/sys/class/net/eth0/statistics/{direction}_bytes"],
                      cmap, sync=True)
    try: return int(out or 0)
    except: return 0
# gira in un thread dedicato per ogni nodo monitorato
def monitor(node, direction, logfile, stop, cmap):
    prev = get_bytes(node, direction, cmap)
    t = 0
    with open(logfile,"w") as f:
        f.write("time throughput_mbps\n")
        while not stop.is_set():
            time.sleep(1)
            curr = get_bytes(node, direction, cmap)
            mbps = (curr - prev) * 8 / 1e6
            f.write(f"{t} {mbps:.4f}\n"); f.flush()
            prev = curr; t += 1

# training run 
#genera incast
def run_training(cfg, cmap):
    name = cfg["name"]
    print(f"[{name}] waiting phi={cfg['phi']}s before start ...")
    time.sleep(cfg["phi"])
    K   = len(cfg["senders"])
    f_v = C_LINK / K
    print(f"[{name}] START | K={K} workers | rate={f_v:.1f}Mbps each")
    for i in range(cfg["cycles"]):
        print(f"[{name}] ROUND {i+1}/{cfg['cycles']}")
        start = time.time()
        for w in cfg["senders"]:
            start_client(w, cfg["collector_ip"], get_worker_port(w),
                         cfg["D"], f_v, cmap)
        time.sleep(max(0, cfg["T"] - (time.time()-start)))
    print(f"[{name}] DONE")

#  plots 
#quattro curve di throughput ricevuto nel tempo, una per training
def plot_collectors(rx_files):
    plt.figure(figsize=(12,5))
    for label, fname in rx_files.items():
        t, y = [], []
        with open(fname) as f:
            next(f)
            for line in f:
                a, b = line.split(); t.append(float(a)); y.append(float(b))
        plt.plot(t, y, label=label)
    plt.title("Collector RX Throughput — Incast Bottleneck + ECMP Resolution")
    plt.xlabel("Time (s)"); plt.ylabel("Mbps")
    plt.legend(); plt.grid()
    plt.tight_layout(); plt.savefig("incast_result.png", dpi=120)
    print("Saved: incast_result.png")
#throughput trasmesso da ciascuno dei suoi worker
def plot_workers(tx_files, training_name):
    workers = [w for cfg in TRAININGS if cfg["name"]==training_name
               for w in cfg["senders"]]
    plt.figure(figsize=(12,4))
    for w in workers:
        fname = tx_files.get(w)
        if not fname: continue
        t, y = [], []
        with open(fname) as f:
            next(f)
            for line in f:
                a, b = line.split(); t.append(float(a)); y.append(float(b))
        plt.plot(t, y, label=w, alpha=0.7)
    plt.title(f"Training {training_name.upper()} — Worker TX (bottleneck on L1)")
    plt.xlabel("Time (s)"); plt.ylabel("Mbps"); plt.legend(ncol=4, fontsize=8)
    plt.grid(); plt.tight_layout()
    fname = f"workers_{training_name}.png"
    plt.savefig(fname, dpi=120); print(f"Saved: {fname}")

#  main 
def main():
    print("\n=== PNET Project 4 — Incast Simulation ===\n")

    cmap = get_container_map()
    print("Container map:")
    for k,v in sorted(cmap.items()): print(f"  {k} -> {v}")

    print("\nStarting iperf3 servers ...")
    start_servers(cmap)
    time.sleep(2)

    stop = threading.Event()
    rx_files, tx_files = {}, {}

    monitors = []

    for cfg in TRAININGS:
        fname = f"{cfg['collector']}_rx.txt"
        rx_files[cfg["collector"]] = fname
        t = threading.Thread(target=monitor,
                              args=(cfg["collector"],"rx",fname,stop,cmap))
        t.start(); monitors.append(t)

    for cfg in TRAININGS:
        for w in cfg["senders"]:
            fname = f"{w}_tx.txt"
            tx_files[w] = fname
            t = threading.Thread(target=monitor,
                                  args=(w,"tx",fname,stop,cmap))
            t.start(); monitors.append(t)

    print("\nInjecting traffic ...")
    threads = [threading.Thread(target=run_training, args=(cfg,cmap))
               for cfg in TRAININGS]
    for t in threads: t.start()
    for t in threads: t.join()

    stop.set()
    for t in monitors: t.join()  # wait for each monitor to flush its last sample

    print("\n=== DONE ===\n")

    if HAS_PLT:
        plot_collectors(rx_files)
        plot_workers(tx_files, "blue")
        plt.show()
    else:
        print("pip install matplotlib  to enable plots")

if __name__ == "__main__":
    main()
