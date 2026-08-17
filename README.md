# eBPF jAgent

The **eBPF jAgent** is a tool developed as part of a Master’s thesis to explore the potential of eBPF for building a resilient resource-profiling tool for Java applications. This README contains all the important information you need to get started with and understand the design of the project. For deeper motivation and design rationale, please refer to the proposaland the paper.


## Using the eBPF jAgent

Below is an overview of the eBPF jAgent architecture:

![Overview of the eBPF jAgent architecture](/img/architechtural-overview.png)

1. **Build & Run (native)**  
   ```bash
   # Clean, compile, and link
   make clean all

   # Run, probing PID <pid> for methods/packages matching <filter>
   sudo ./ebpf-jagent -p <pid> -f <filter>
   ```
   - **Filter**: any substring in the package or method name.  
     e.g. `doWork` matches `com/example/Main.doWork()`.  
   - **Help**: `./ebpf-jagent -h`  
   - **JVM Flags**  
     The target JVM must enable USDT probes. For OpenJDK 24, add:  
     ```
     -XX:+DTraceAllocProbes -XX:+DTraceMethodProbes
     ```

2. **Containerized Usage**  
   A Docker-based setup is provided under `containerized/`.

   ```bash
   # Build the container image
   docker build -f containerized/Dockerfile -t c-ebpf-jagent .

   # Run the container
   sudo docker run --rm -it 
     --privileged 
     --pid=host 
     --cap-add SYS_ADMIN 
     --cap-add CAP_BPF 
     --cap-add CAP_PERFMON 
     --network=host 
     --security-opt seccomp=unconfined 
     -v /sys/fs/bpf:/sys/fs/bpf:rw 
     -v /lib/modules:/lib/modules:ro 
     -v /sys/kernel/tracing:/sys/kernel/tracing:rw 
     -v "$(pwd)/logs":/logs:rw 
     c-ebpf-jagent 
     doWork
   ```
   - The entrypoint script `containerized/entrypoint.sh` launches the probe.  
   - To change the probed application or filter, edit `entrypoint.sh`.


## Code Structure

All source files live in the project root. Key components:

### 1. `ebpf_jagent.user.c`
- **Role**: User-space controller.  
- **Responsibilities**:  
  - Attach USDT probes to the JVM.  
  - Read events from a pipe and forward them to the metrics exporter.

### 2. `ebpf_jagent.bpf.c`
- **Role**: In-kernel eBPF program.  
- **Responsibilities**:  
  - Implement probe handlers.  
  - Build the resource-demand vector for each USDT event.

### 3. `metrics/`
- Contains helper code that:  
  1. Reads total process CPU time from `/proc/<pid>/stat` (due to eBPF’s in-kernel limitations).  
  2. Combines it with eBPF events.  
  3. Exports metrics via OpenTelemetry.

### 4. `environment/`
- Configure runtime parameters via the `.env` file.
- Loaded automatically by the user-space binary.

### 5. `model/`
- Defines the in-memory event structure exchanged between user and kernel (has to be defined again in the bpf code).


## Benchmarks

All raw benchmark data and visualization scripts used in the thesis are in the `benchmark/` folder.

Run the provided scripts to reproduce the numerical results and plots.


## Grafana Dashboard

To visualize the **SCI** metric (and other metrics):

1. Open Grafana.  
2. Import the JSON dashboard:  
   - File: `grafana/dashboard.json`  
   - (Menu -> Dashboards -> Import)


## Disclaimer

In case of not detecting the transactions inside of the log file (default, method_trace.txt):
- Ensure the JVM is started with the USDT flags.  
- Wait at least **30 seconds** after startup—Grafana only displays data once methods are registered and events flow through the pipeline (check your logs in `logs/`).
- Check the logs for fails when attaching.

---

Happy eBPFrofiling!