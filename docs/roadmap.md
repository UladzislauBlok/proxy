# Roadmap

## Phase 1: Core Observability (L4 Socket Probes)

_Goal: Establish the foundation by hooking into the Linux network stack's socket layer (TCP/UDP)._

- [x] Attach kprobes to `tcp_sendmsg`, `tcp_recvmsg`, `udp_sendmsg`, and `udp_recvmsg`.
      _Note:_ Hooks into the kernel functions called when applications send/receive data. I will learn basic eBPF program attachment and how to read function arguments.
- [x] Export basic packet and byte metrics to user-space via an HTTP endpoint.
      _Note:_ Gets data out of the kernel using eBPF maps and serves it. I will learn how user-space and kernel-space share data safely.
- [ ] Implement PID-based filtering to track network activity by process.
      _Note:_ Uses `bpf_get_current_pid_tgid()` to identify which process is sending/receiving data. I will learn how to filter and attribute traffic at the source.
- [ ] Transition from basic eBPF maps to Ring Buffers for streaming events.
      _Note:_ Replaces polling a static map with a high-performance, asynchronous event stream. I will learn modern eBPF data structures essential for real-time observability.

## Phase 2: Container Context and Workload Identity

_Goal: Understand how the kernel isolates network traffic, crucial for Kubernetes (GKE) and Borg._

- [ ] Extract the Network Namespace (netns) ID from `struct sock` to identify container boundaries.
      _Note:_ A Network Namespace gives a container its own isolated network stack (its own IPs, routing tables, and ports). By reading the `netns` ID directly from the kernel's socket struct, you can definitively prove exactly which container or Kubernetes Pod generated the traffic. This is exactly how GKE and Cilium map raw packets back to Kubernetes workloads.
- [ ] Read cgroup IDs to attribute network traffic to specific workloads or pods.
      _Note:_ Control Groups (cgroups) isolate resource usage (CPU, memory). Reading the `cgroup` ID allows you to tie network activity back to the specific container runtime's workload, providing another layer of identity.
- [ ] Correlate process data (PID, command name) with network socket events.
      _Note:_ Uses `bpf_get_current_comm()` to get the executable name. I will learn how to enrich raw network bytes with process-level context, making debugging infinitely easier.
- [ ] Track connection lifecycles (connect, accept, close) to monitor active connections.
      _Note:_ Hooks into `tcp_v4_connect`, `inet_csk_accept`, and `tcp_close`. I will learn how to track stateful connections over time (gauges) rather than just counting packets (counters).

## Phase 3: TCP Internals and Telemetry

_Goal: Dive deep into the kernel TCP state machine to monitor network health and reliability._

- [ ] Hook into kernel tracepoints to monitor TCP state transitions (e.g., `ESTABLISHED`, `TIME_WAIT`).
      _Note:_ Tracepoints are stable API hooks in the kernel. I will learn the TCP state machine and how to reliably trace kernel events without relying on unstable kprobes.
- [ ] Track TCP retransmissions and packet drops to identify network congestion.
      _Note:_ Hooks into `tcp_retransmit_skb` or drop tracepoints. High retransmissions indicate bad network health. I will learn how to pinpoint network degradation at the kernel level before the application crashes.
- [ ] Calculate and export connection latency (time between SYN and ACK).
      _Note:_ Measures the exact time it takes to establish a TCP connection. I will learn how to store timestamps in eBPF maps on SYN and calculate deltas when the connection completes (ACK).
- [ ] Measure Round Trip Time (srtt) directly from the kernel's `tcp_sock` structure.
      _Note:_ The kernel constantly calculates Smoothed RTT (srtt) for every TCP connection. I will learn how to navigate complex, nested C structs (`struct tcp_sock`) in Rust to extract highly valuable performance metrics built directly into Linux.

## Phase 4: High-Performance Dataplane (XDP & TC)

_Goal: Move to Layer 2/3 packet processing for high-throughput routing and filtering (like GKE Dataplane V2)._

- [ ] Write an XDP program to parse raw Ethernet, IP, and TCP/UDP headers.
      _Note:_ eXpress Data Path (XDP) runs at the network driver level, before the kernel even allocates memory (`sk_buff`) for the packet. I will learn verifier-safe raw pointer arithmetic and byte parsing at the lowest possible level.
- [ ] Implement a fast-path packet dropper (e.g., basic DDoS mitigation or ACLs).
      _Note:_ Returns `XDP_DROP` for specific IPs or ports. I will learn how eBPF is used for high-performance firewalls, dropping malicious traffic at wire speed before it consumes CPU cycles.
- [ ] Attach an eBPF program to Traffic Control (TC) to inspect both ingress and egress traffic.
      _Note:_ TC runs slightly higher up the stack than XDP but works for both incoming and outgoing traffic. I will learn the critical differences between XDP (ingress only, driver level) and TC (ingress/egress, qdisc level).
- [ ] Benchmark and compare the performance trade-offs of XDP/TC versus socket-layer kprobes.
      _Note:_ I will learn architectural trade-offs: kprobes give you process context (PID, cgroup) easily, while XDP/TC give you raw speed but no process context.

## Phase 5: Production-Grade Node Agent

_Goal: Build a robust, observable, and safe Rust daemon suitable for infrastructure deployments._

- [ ] Implement graceful shutdown and signal handling for safe eBPF program detachment.
      _Note:_ Ensures the eBPF program doesn't get left running in the kernel if your Rust app crashes. I will learn Tokio's `select!` macro and Linux signal handling.
- [ ] Replace the simple HTTP endpoint with a structured Prometheus exporter (using histograms and gauges).
      _Note:_ Moves from basic text to an industry-standard metric format. I will learn how to represent latency distributions (Histograms) and active connection counts (Gauges).
- [ ] Support dynamic configuration reloading (e.g., updating watched PIDs without restarting the daemon).
      _Note:_ Uses channels and configuration files (`serde`). I will learn how to update an eBPF map's rules dynamically from user-space without dropping network traffic.
- [ ] Create integration tests using Linux network namespaces to simulate and verify multi-container traffic.
      _Note:_ Spins up virtual network environments (`ip netns`) in tests to send real traffic through your eBPF programs. I will learn how to test complex network software deterministically.
