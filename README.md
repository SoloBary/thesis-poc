# Kubernetes & Container Security Monitoring with Open Source Tools

> **Bachelor's Thesis — Proof of Concept**  
> A layered, production-grade security monitoring stack built on Kubernetes, using [kube-goat](https://github.com/madhuakula/kubernetes-goat) as the intentionally vulnerable attack target. Every layer catches what the previous one misses.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Security Layers](#security-layers)
- [Attack Scenarios & Detection](#attack-scenarios--detection)
- [Stack Components](#stack-components)
- [Installation Guide](#installation-guide)
- [Dashboard Access](#dashboard-access)
- [Repository Structure](#repository-structure)
- [Key Technical Decisions](#key-technical-decisions)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Lessons Learned](#lessons-learned)
- [Real-World Threat Context](#real-world-threat-context)
- [References](#references)

---

## Overview

This project demonstrates a complete **defense-in-depth** security architecture for Kubernetes environments. The stack spans four security layers — from image scanning before a container ever runs, through policy enforcement at admission time, network-level mutual TLS, and finally syscall-level runtime detection.

The target environment is [kube-goat](https://github.com/madhuakula/kubernetes-goat), a deliberately vulnerable Kubernetes application that ships with documented misconfigurations: containers running as root, exposed service account tokens, and untagged images. These misconfigurations serve as the attack surface against which all detection capabilities are validated.

The thesis argument is simple: **no single tool is sufficient**. A container can pass image scanning and still execute malicious syscalls at runtime. A policy engine can enforce admission rules and still miss lateral movement at the network layer. The value of this stack is in the combination — each layer providing visibility and control that the others cannot.

---

## Architecture

```
Kubernetes Cluster (kind v0.26.0 / k8s v1.32.0)
│
├── kube-goat (attack target)
│   ├── namespace: big-monolith        ← hunger-check, health-check, metadata-db
│   └── namespace: secure-middleware   ← cache-store
│
├── namespace: falco
│   ├── Falco DaemonSet         ← eBPF syscall interception (modern_ebpf / CO-RE)
│   ├── Falcosidekick           ← Event router to WebUI
│   └── Falcosidekick UI        ← Real-time alert dashboard
│
├── namespace: monitoring
│   ├── Prometheus              ← Scrapes falcosecurity_* metrics every 15s
│   ├── Grafana                 ← Custom Falco security dashboard
│   └── AlertManager            ← Alert routing and grouping
│
├── namespace: trivy-system
│   └── Trivy Operator          ← Continuous VulnerabilityReport CRDs per workload
│
├── namespace: kyverno
│   └── Kyverno                 ← Admission webhook / Policy engine
│
└── namespace: istio-system
    ├── Istiod                  ← Service mesh control plane
    ├── Istio Ingress/Egress    ← Traffic management
    └── Kiali                   ← Service graph and mTLS visualization
```

---

## Security Layers

### Layer 1 — Pre-Runtime: Trivy Operator

Trivy Operator runs as a Kubernetes controller and continuously scans every container image in the cluster against the NVD CVE database. It generates `VulnerabilityReport` custom resources per workload — structured, queryable with `kubectl`, and automatically refreshed when images change.

The key distinction from a one-shot scanner is continuity. When a new CVE is published and the database is updated, the Operator re-scans on its next cycle — without any manual intervention. Security posture is always current.

**Findings on kube-goat:**

| Image | Critical | High | Medium | Low |
|---|---|---|---|---|
| `k8s-goat-home` | 2 | 10 | 23 | 7 |
| `k8s-goat-hidden-in-layers` | 0 | 4 | 26 | 4 |

Notable CVEs detected before any attack was launched:
- `CVE-2025-15467` — OpenSSL **Remote Code Execution** via oversized IV in CMS parsing (**CRITICAL**)
- `CVE-2025-69419` — OpenSSL arbitrary code execution via out-of-bounds write in PKCS#12 (**CRITICAL**)
- `CVE-2024-6119` — OpenSSL denial of service via X.509 name checks (**HIGH**)
- `CVE-2023-42363/4/5/6` — busybox use-after-free in awk (**MEDIUM**)

Two CRITICAL RCE vulnerabilities existed in the kube-goat images before a single attack command was run. The pre-runtime layer provides the earliest possible detection point in the attack lifecycle.

```bash
# Full cluster vulnerability summary
kubectl get vulnerabilityreports -A -o custom-columns=\
"NAMESPACE:.metadata.namespace,\
NAME:.metadata.name,\
CRITICAL:.report.summary.criticalCount,\
HIGH:.report.summary.highCount,\
MEDIUM:.report.summary.mediumCount,\
LOW:.report.summary.lowCount"

# Detailed CVE list for a specific workload
kubectl describe vulnerabilityreport -n default <report-name> \
  | grep -E "Severity|Title|Vulnerability Id"
```

---

### Layer 2 — Admission Control: Kyverno

Kyverno operates as a Kubernetes admission webhook. Every resource creation or update — `kubectl apply`, Helm install, controller-generated pods — passes through Kyverno's validating and mutating webhooks before the API server accepts it. In `Enforce` mode, non-compliant resources are rejected outright. In `Audit` mode, violations are recorded as `PolicyReport` resources without blocking.

Policies are written as Kubernetes YAML using the same patterns as any other resource. There is no separate policy language or runtime to manage.

**Active policies:**

| Policy | Behavior | Rationale |
|---|---|---|
| `disallow-privileged-containers` | Reject `privileged: true` | Privileged containers share the host kernel namespace — a container escape gives full host access |
| `disallow-root-user` | Require `runAsNonRoot: true` | Root in a container maps to root on the host if namespace isolation fails |
| `disallow-latest-tag` | Reject `:latest` images | Untagged images are non-deterministic — the same deployment can pull different code on each restart |

**kube-goat violations caught:**

All three documented kube-goat misconfigurations are surfaced by Kyverno:
- `hunger-check` runs as root → `disallow-root-user` violation
- All kube-goat images use `:latest` → `disallow-latest-tag` violation
- No resource limits defined → `require-resource-limits` violation

The admission layer stops bad workloads from being scheduled in the first place. Runtime detection is not needed if the workload never runs.

```bash
kubectl get clusterpolicy
kubectl get policyreport -A
kubectl get clusterpolicyreport -A
```

---

### Layer 3 — Network: Istio + Kiali

Istio implements a service mesh by injecting an Envoy sidecar proxy into every pod. The sidecar intercepts all inbound and outbound traffic and enforces mesh-wide policies — including mutual TLS authentication between services.

With `PeerAuthentication` set to `STRICT` mode, plaintext traffic between pods in the mesh is rejected at the proxy level. Every service-to-service connection requires a valid X.509 certificate. An attacker with code execution in a pod cannot eavesdrop on inter-service communication, and cannot impersonate another service without a valid certificate.

Kiali consumes Istio telemetry and renders it as a real-time service dependency graph. Traffic flows, request rates, error rates, and mTLS status are visible per-connection — making lateral movement visible as it happens.

**mTLS enforced on:** `big-monolith`, `secure-middleware`, `default`

**What Kiali shows during an attack:**  
After triggering PoC attacks, the Kiali graph shows `hunger-check-deployment` → `metadata-db` traffic across namespace boundaries. This is lateral movement — visible, timestamped, attributed to specific workloads — without any manual log correlation.

```bash
# Verify mTLS policies are active
kubectl get peerauthentication -A

# In Kiali: Graph → Display → Security
# Lock icons on edges = mTLS enforced on that connection
```

---

### Layer 4 — Runtime: Falco + Prometheus + Grafana

Falco runs as a DaemonSet and uses Linux eBPF to intercept syscalls at the kernel level. Every `open()`, `execve()`, `connect()`, `write()` — Falco sees it all, evaluates it against a ruleset, and emits a structured alert if a rule matches. The detection happens in kernel space, before the syscall completes.

The `modern_ebpf` driver uses CO-RE (Compile Once, Run Everywhere) via BTF. No kernel headers, no prebuilt driver download, no compilation step. The driver loads directly into the running kernel via the BPF subsystem.

**Metrics pipeline:**
```
Falco (:8765/metrics)
    ↓  Prometheus ServiceMonitor (15s interval)
Prometheus
    ↓
Grafana

Exposed metrics:
  falcosecurity_falco_rules_matches_total   ← alert counter, labeled by rule
  falcosecurity_scap_n_evts_total           ← total syscall events processed
  falcosecurity_falco_cpu_usage_ratio       ← Falco process CPU overhead
  falcosecurity_falco_memory_rss_bytes      ← Falco memory footprint
  falcosecurity_scap_n_drops_buffer_total   ← dropped events by type (data quality)
```

**Alert pipeline:**
```
Falco (json_output → http_output → :2801)
    ↓
Falcosidekick (minimumpriority: warning)
    ↓
Falcosidekick UI (:2802)
  — event table with rule, priority, container, namespace, MITRE tags
```

**Custom rule tuning (`falco/custom-rules.yaml`):**  
The default Falco ruleset generates significant noise in a Kubernetes environment — kubelet mounting volumes, Prometheus scraping the API server, node-exporter reading host metrics. These are all legitimate and expected, but they trigger rules designed for general Linux environments.

The custom rules in this repo take a surgical approach: `known_drop_and_execute_containers` and `known_drop_and_execute_activities` macros are extended via `override: condition: append` to whitelist specific system images and namespaces. The kube-goat namespaces (`big-monolith`, `secure-middleware`) are deliberately never whitelisted — every event from the attack surface reaches the alert pipeline.

---

## Attack Scenarios & Detection

All attacks are executed against the `hunger-check` pod in the `big-monolith` namespace. After each command, the alert appears in Falcosidekick UI within seconds and the `falcosecurity_falco_rules_matches_total` counter increments in Grafana.

### PoC 1 — Sensitive File Access (MITRE T1555)
```bash
kubectl exec -n big-monolith \
  $(kubectl get pod -n big-monolith -o jsonpath='{.items[0].metadata.name}') \
  -- cat /etc/shadow
```
**Rule:** `Read sensitive file untrusted` — **Warning**  
**Syscall intercepted:** `openat("/etc/shadow")`  
**Context:** `proc.name=cat`, `user.name=root`, `k8s.ns.name=big-monolith`, `container.image.tag=latest`

---

### PoC 2 — Terminal Shell in Container (MITRE T1059)
```bash
kubectl exec -it -n big-monolith \
  $(kubectl get pod -n big-monolith -o jsonpath='{.items[0].metadata.name}') \
  -- /bin/bash
```
**Rule:** `Terminal shell in container` — **Notice**  
**Syscall intercepted:** `execve("/bin/bash")` with `proc.tty != 0`  
**Context:** Interactive terminal detected via TTY allocation

---

### PoC 3 — Fileless Malware via /dev/shm (MITRE T1620)
```bash
kubectl exec -n big-monolith \
  $(kubectl get pod -n big-monolith -o jsonpath='{.items[0].metadata.name}') \
  -- sh -c "cp /bin/sh /dev/shm/evil && /dev/shm/evil -c id"
```
**Rule:** `Execution from /dev/shm` — **Critical**  
**Syscall intercepted:** `execve("/dev/shm/evil")`  
**Why it matters:** `/dev/shm` is a memory-backed filesystem. Binaries written here leave no disk trace. This is the exact persistence pattern used by CanisterWorm (March 2026 Trivy supply chain attack).

---

### PoC 4 — Private Key Discovery (MITRE T1552)
```bash
kubectl exec -n big-monolith \
  $(kubectl get pod -n big-monolith -o jsonpath='{.items[0].metadata.name}') \
  -- find / -name "*.pem" -o -name "id_rsa" 2>/dev/null
```
**Rule:** `Search Private Keys or Passwords` — **Warning**  
**Syscall intercepted:** `openat()` on paths matching private key patterns

---

### PoC 5 — Log Clearing / Anti-Forensics (MITRE T1070)
```bash
kubectl exec -n big-monolith \
  $(kubectl get pod -n big-monolith -o jsonpath='{.items[0].metadata.name}') \
  -- sh -c "cat /dev/null > /var/log/dpkg.log"
```
**Rule:** `Clear Log Activities` — **Warning**  
**Syscall intercepted:** `openat("/var/log/dpkg.log", O_WRONLY|O_TRUNC)`

---

### PoC 6 — Netcat Bind Shell (MITRE T1059)
```bash
kubectl exec -n big-monolith \
  $(kubectl get pod -n big-monolith -o jsonpath='{.items[0].metadata.name}') \
  -- sh -c "nc -l 4444 &"
```
**Rule:** `Netcat Remote Code Execution in Container` — **Warning**  
**Syscall intercepted:** `socket()` + `bind()` from `nc` process inside container

---

## Stack Components

| Tool | Version | Namespace | Role |
|---|---|---|---|
| Kubernetes (kind) | v1.32.0 | — | Cluster |
| kube-goat | latest | big-monolith / secure-middleware | Attack target |
| Falco | 0.43.0 | falco | Syscall-level runtime detection |
| Falcosidekick | 2.32.0 | falco | Alert routing and fan-out |
| Falcosidekick UI | latest | falco | Real-time event dashboard |
| kube-prometheus-stack | v0.89.0 | monitoring | Prometheus + Grafana + AlertManager |
| Trivy Operator | 0.30.1 | trivy-system | Continuous image vulnerability scanning |
| Kyverno | v1.17.1 | kyverno | Admission control and policy enforcement |
| Istio | 1.24.0 | istio-system | Service mesh and mTLS enforcement |
| Kiali | latest | istio-system | Service graph and traffic visualization |

---

## Installation Guide

### Prerequisites

```bash
docker --version    # Docker 20+
kubectl version     # kubectl 1.30+
helm version        # Helm v3
kind version        # kind v0.26.0+
istioctl version    # Istio 1.24.0
```

### Step 1 — Create cluster

```bash
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.26.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind

cat > kind-config.yaml << 'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: thesis-lab
nodes:
- role: control-plane
  image: kindest/node:v1.32.0
  extraMounts:
  - hostPath: /proc
    containerPath: /host/proc
    readOnly: true
  - hostPath: /sys
    containerPath: /host/sys
    readOnly: true
  - hostPath: /
    containerPath: /host
    readOnly: true
    propagation: Bidirectional
  extraPortMappings:
  - containerPort: 30000
    hostPort: 30000
    protocol: TCP
EOF

kind create cluster --config kind-config.yaml
kubectl get nodes
```

The `/proc`, `/sys`, and `/` host mounts are required for Falco's eBPF probe to access kernel data structures. Without them, the probe loads but cannot instrument syscalls.

### Step 2 — Deploy kube-goat

```bash
git clone https://github.com/madhuakula/kubernetes-goat.git
cd kubernetes-goat
chmod +x setup-kubernetes-goat.sh
bash setup-kubernetes-goat.sh

# Wait for all pods to reach Running state
kubectl get pods -A | grep -v kube-system

# Optional: access kube-goat UI
bash access-kubernetes-goat.sh
# → http://127.0.0.1:1234
```

### Step 3 — Add Helm repos

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
```

### Step 4 — Deploy Falco

```bash
kubectl create namespace falco

helm install falco falcosecurity/falco \
  --namespace falco \
  --set driver.kind=modern_ebpf \
  --set falco.metrics.enabled=true \
  --set falco.metrics.interval=15s \
  --set falco.metrics.output_rule=false \
  --set falco.metrics.resource_utilization_enabled=true \
  --set falco.metrics.kernel_event_counters_enabled=true \
  --set falco.webserver.enabled=true \
  --set falco.webserver.prometheus_metrics_enabled=true \
  --set falco.webserver.listen_port=8765 \
  --set falco.json_output=true \
  --set falco.http_output.enabled=true \
  --set falco.http_output.url="http://falcosidekick:2801" \
  -f falco/custom-rules.yaml

kubectl rollout status daemonset/falco -n falco
# Verify metrics endpoint
kubectl port-forward -n falco pod/$(kubectl get pod -n falco -l app.kubernetes.io/name=falco \
  -o jsonpath='{.items[0].metadata.name}') 8765:8765 &
curl -s localhost:8765/metrics | grep "^falcosecurity" | head -5
```

### Step 5 — Deploy Prometheus + Grafana

```bash
kubectl create namespace monitoring

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --set grafana.adminPassword='admin' \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false

kubectl rollout status deployment/prometheus-grafana -n monitoring
kubectl get pods -n monitoring
```

### Step 6 — Falco Service + ServiceMonitor

```bash
# Expose Falco metrics as a headless Service
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: falco-metrics
  namespace: falco
  labels:
    app.kubernetes.io/name: falco
spec:
  selector:
    app.kubernetes.io/name: falco
  clusterIP: None
  ports:
    - name: metrics
      port: 8765
      targetPort: 8765
      protocol: TCP
EOF

# Register with Prometheus Operator
kubectl apply -f - << 'EOF'
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: falco-metrics
  namespace: monitoring
  labels:
    release: prometheus
spec:
  namespaceSelector:
    matchNames:
      - falco
  selector:
    matchLabels:
      app.kubernetes.io/name: falco
  endpoints:
    - port: metrics
      path: /metrics
      interval: 15s
EOF
```

### Step 7 — Deploy Falcosidekick

```bash
helm install falcosidekick falcosecurity/falcosidekick \
  --namespace falco \
  --set webui.enabled=true \
  --set webui.replicaCount=1 \
  --set config.minimumpriority=warning

kubectl rollout status deployment/falcosidekick -n falco
kubectl rollout status deployment/falcosidekick-ui -n falco
kubectl get pods -n falco
```

### Step 8 — Deploy Trivy Operator

```bash
helm install trivy-operator aquasecurity/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --set trivy.ignoreUnfixed=true

kubectl rollout status deployment/trivy-operator -n trivy-system

# Wait 3-5 minutes for initial scan cycle to complete
kubectl get vulnerabilityreports -A
```

### Step 9 — Deploy Kyverno

```bash
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --set features.policyExceptions.enabled=true \
  --set features.validatingAdmissionPolicyReports.enabled=true \
  --set admissionController.replicas=1

kubectl rollout status deployment/kyverno-admission-controller -n kyverno
kubectl get pods -n kyverno

# Apply policies
kubectl apply -f kyverno/policies/

# Verify policies are loaded and ready
kubectl get clusterpolicy
kubectl get policyreport -A
```

### Step 10 — Deploy Istio + Kiali

```bash
# Download and install Istio
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.24.0 sh -
cd istio-1.24.0 && export PATH=$PWD/bin:$PATH

istioctl install --set profile=demo -y
kubectl rollout status deployment/istiod -n istio-system

# Install Kiali and Prometheus addon
kubectl apply -f samples/addons/kiali.yaml
kubectl apply -f samples/addons/prometheus.yaml
kubectl rollout status deployment/kiali -n istio-system

# Enable automatic sidecar injection
kubectl label namespace big-monolith istio-injection=enabled
kubectl label namespace secure-middleware istio-injection=enabled
kubectl label namespace default istio-injection=enabled

# Restart existing pods to inject sidecars
kubectl rollout restart deployment -n big-monolith
kubectl rollout restart deployment -n secure-middleware
kubectl rollout restart deployment -n default

# Verify sidecar injection (should show 2/2 or 3/3)
kubectl get pods -n big-monolith

# Enforce mTLS STRICT mode
kubectl apply -f istio/mtls/peer-authentication.yaml
kubectl get peerauthentication -A
```

---

## Dashboard Access

```bash
# Kill stale port-forwards and start all at once
pkill -f "kubectl port-forward"

kubectl port-forward -n monitoring svc/prometheus-grafana 3001:80 &
kubectl port-forward -n falco svc/falcosidekick-ui 2802:2802 &
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090 &
kubectl port-forward -n istio-system svc/kiali 20001:20001 &
```

| Tool | URL | Credentials |
|---|---|---|
| Grafana | http://localhost:3001 | admin / admin |
| Falcosidekick UI | http://localhost:2802 | — |
| Prometheus | http://localhost:9090 | — |
| Kiali | http://localhost:20001 | — |

**Grafana dashboard import:**  
Dashboards → New → Import → Upload JSON → `grafana/falco-dashboard.json` → datasource: Prometheus → Import

**Useful PromQL queries:**
```promql
# Total security alerts fired
sum(falcosecurity_falco_rules_matches_total)

# Alerts per rule in the last 5 minutes
sum by (rule) (increase(falcosecurity_falco_rules_matches_total[5m]))

# Syscall ingestion rate
rate(falcosecurity_scap_n_evts_total[1m])

# Falco CPU overhead
falcosecurity_falco_cpu_usage_ratio * 100

# Event drops (data quality indicator)
sum by (drop) (rate(falcosecurity_scap_n_drops_buffer_total[1m]))
```

---

## Repository Structure

```
thesis-poc/
├── falco/
│   ├── custom-rules.yaml             # Rule overrides and noise reduction
│   └── screenshots/                  # Falcosidekick UI evidence
├── grafana/
│   ├── falco-dashboard.json          # Custom dashboard (falcosecurity_* metrics)
│   └── screenshots/
├── istio/
│   ├── mtls/
│   │   └── peer-authentication.yaml  # STRICT mTLS per namespace
│   └── screenshots/                  # Kiali service graph
├── kyverno/
│   ├── policies/
│   │   ├── disallow-privileged.yaml
│   │   ├── disallow-root.yaml
│   │   └── disallow-latest-tag.yaml
│   └── screenshots/
├── prometheus/
│   ├── falco-servicemonitor.yaml
│   └── screenshots/
├── trivy/
│   └── screenshots/                  # VulnerabilityReport findings
├── PoC.txt                           # Installation reference
└── README.md
```

---

## Key Technical Decisions

**`modern_ebpf` over `ebpf` driver**  
The cluster runs on kernel `6.8.0-100-generic`. No prebuilt Falco driver exists for this version, and kernel headers are unavailable inside kind nodes. `modern_ebpf` uses CO-RE (Compile Once, Run Everywhere) via BTF — the probe is compiled once against stable kernel interfaces and runs on any BTF-enabled kernel (5.8+) without recompilation. No init container, no driver download, no compilation step at startup.

**k8s v1.32.0 over v1.27**  
Kyverno v1.17+ integrates with the `ValidatingAdmissionPolicy` API, which became stable in k8s 1.30. Running on 1.32 enables both the Kyverno admission webhook and the native k8s enforcement mechanism in parallel. Earlier versions of the cluster (1.27) caused Kyverno's admission controller to crash on startup due to missing API resources.

**Kyverno over OPA/Gatekeeper**  
Kyverno uses native Kubernetes YAML for policy definitions — the same structure as any other resource. OPA/Gatekeeper requires Rego, a separate policy language with its own syntax and testing toolchain. For a thesis demonstrating admission control concepts, Kyverno produces the same enforcement behavior with significantly lower operational overhead. Both are CNCF projects and production-ready.

**Falco native metrics over falco-exporter**  
`falco-exporter` was officially deprecated starting with Falco 0.38. From that version onward, Falco exposes a Prometheus-compatible `/metrics` endpoint natively via its built-in webserver. The metric namespace changed from the legacy `falco_*` prefix to `falcosecurity_*` — making existing community dashboards (e.g. Grafana ID 11914) incompatible. The dashboard in this repo is built against the current `falcosecurity_*` metric names.

**Noise reduction via macro extension, not rule disabling**  
The default Falco ruleset fires on kubelet mount operations, Prometheus API calls, and node-exporter filesystem reads — all legitimate. Disabling these rules entirely would create blind spots. Instead, the `known_drop_and_execute_containers` list and `known_drop_and_execute_activities` macro are extended via `override: condition: append` to whitelist specific system images and namespaces. The kube-goat namespaces are never whitelisted — full detection coverage is preserved on the attack surface.

**mTLS STRICT over PERMISSIVE**  
PERMISSIVE mode allows both plaintext and encrypted traffic and is used for gradual migration. STRICT mode rejects plaintext connections — every communication in the mesh must present a valid X.509 certificate issued by the mesh CA. For a security demonstration, PERMISSIVE provides no enforcement value.

---

## MITRE ATT&CK Coverage

| Technique | ID | Detection / Prevention | Layer |
|---|---|---|---|
| Supply Chain Compromise | T1195.002 | Trivy | Pre-runtime |
| Exploitation for Initial Access | T1190 | Trivy | Pre-runtime |
| Exploitation of Remote Services | T1210 | Trivy | Pre-runtime |
| Escape to Host | T1611 | Kyverno (disallow-privileged) | Admission |
| Abuse Elevation Control Mechanism | T1548 | Kyverno (disallow-root-user) | Admission |
| Resource Hijacking | T1496 | Kyverno (require-resource-limits) | Admission |
| Container Implantation | T1525 | Kyverno (image policies) | Admission |
| Valid Accounts — service account token | T1078 | Kyverno | Admission |
| Credential Access — credentials from files | T1555 | Falco | Runtime |
| Execution — command and scripting interpreter | T1059 | Falco | Runtime |
| Defense Evasion — reflective code loading | T1620 | Falco | Runtime |
| Credential Access — unsecured credentials | T1552 | Falco | Runtime |
| Defense Evasion — indicator removal on host | T1070 | Falco | Runtime |
| Discovery — container and resource discovery | T1613 | Falco + Kiali | Runtime + Network |
| Lateral Movement — cross-namespace traffic | — | Istio / Kiali | Network |
| Command & Control — ingress tool transfer | T1105 | Falco | Runtime |

---

## Lessons Learned

**Falco rule `override: enabled: replace` requires the rule to exist in the loaded ruleset.**  
If the rule name does not match exactly — including capitalization and punctuation — Falco fails at startup with a validation error. Always verify the exact rule name with `grep "^- rule:" /etc/falco/falco_rules.yaml` before writing overrides. The colon in `Falco internal: metrics snapshot` must be quoted in YAML.

**Falco internal metrics snapshots bypass `minimumpriority`.**  
The `Falco internal: metrics snapshot` events are not emitted as standard rule matches — they bypass the priority filter in Falcosidekick and flood the UI. The correct fix is `--set falco.metrics.output_rule=false` at the Falco level, not a filter in Falcosidekick.

**kind nodes require explicit host mounts for eBPF.**  
Without mounting `/proc`, `/sys`, and `/` from the host into the control-plane node container, Falco's eBPF probe cannot access host kernel data. This is not documented prominently in the Falco kind quickstart.

**Kyverno namespace exceptions must cover all system tooling.**  
Applying policies to `kube-system`, `monitoring`, `falco`, `trivy-system`, `istio-system`, and `kyverno` itself is mandatory before switching any policy to `Enforce` mode. Without exceptions, Kyverno blocks its own DaemonSets and the entire security stack fails to start.

**Trivy DB mirror reliability.**  
`mirror.gcr.io` is periodically unavailable. The stable alternative is `public.ecr.aws/aquasecurity/trivy-db`. Set this as the DB repository in the Trivy Operator values if scans fail with download errors.

**The `falcosecurity_*` metric prefix is breaking.**  
Any Grafana dashboard, alert rule, or PromQL query using the legacy `falco_*` prefix will return no data against Falco 0.38+. The Grafana community dashboard ID 11914 is built against the old prefix and will show empty panels. The dashboard in this repo uses the correct current metric names.

---

## Real-World Threat Context

During the development of this thesis (March 2026), a real supply chain attack targeted the Trivy scanner itself. Threat actor **TeamPCP** published malicious versions of `trivy`, `trivy-action`, and `setup-trivy` to GitHub, containing a credential stealer paired with a self-propagating worm named **CanisterWorm**. The worm spread across 141 npm packages by harvesting npm authentication tokens and republishing infected versions autonomously.

The persistence mechanism used by CanisterWorm — dropping a binary to `/dev/shm` and executing it — is exactly what PoC 3 simulates. The Falco rule `Execution from /dev/shm` detects it in real time.

The incident illustrates a property of the layered architecture in this stack: the attack would have been caught at multiple layers simultaneously.

- **Trivy Operator** would flag the compromised `trivy` image as containing malicious code before deployment
- **Falco** would catch the `/dev/shm` execution at runtime regardless of how the binary arrived
- **Kiali** would surface any unexpected outbound connections to the C2 infrastructure

No single layer is sufficient. The combination is what provides resilience.

---

## References

- [Falco Documentation](https://falco.org/docs/)
- [Falco Rules Reference](https://falco.org/docs/reference/rules/)
- [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)
- [Kyverno Documentation](https://kyverno.io/docs/)
- [Trivy Operator](https://aquasecurity.github.io/trivy-operator/)
- [Istio Security Concepts](https://istio.io/latest/docs/concepts/security/)
- [Kiali Documentation](https://kiali.io/docs/)
- [kubernetes-goat](https://github.com/madhuakula/kubernetes-goat)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [CNCF Cloud Native Security Whitepaper v2](https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/CNCF_cloud-native-security-whitepaper-May2022-v2.pdf)
- [CanisterWorm — Aikido Security Analysis](https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise)
- [CanisterWorm — The Hacker News](https://thehackernews.com/2026/03/trivy-supply-chain-attack-triggers-self.html)

---

## Author

**Bary** — Threat Detection & Response Analyst, L2 SOC  
Bachelor's Thesis — Dept. of Informatics and Telecommunications  
GitHub: [@SoloBary](https://github.com/SoloBary)

---

*Falco · Kyverno · Trivy · Istio · Kiali · Prometheus · Grafana · kind · kube-goat*
