# Kubernetes & Container Security Monitoring with Open Source Tools

> **Bachelor's Thesis — Proof of Concept**  
> A layered security monitoring stack for Kubernetes, validated against [kube-goat](https://github.com/madhuakula/kubernetes-goat) as the intentionally vulnerable target. Each layer catches a distinct class of attack that the previous one cannot.

---

## Table of Contents

- [Overview](#overview)
- [Threat Model](#threat-model)
- [Architecture](#architecture)
- [Security Layers](#security-layers)
- [Attack Scenarios & Detection](#attack-scenarios--detection)
- [Stack Components](#stack-components)
- [Installation Guide](#installation-guide)
- [Dashboard Access](#dashboard-access)
- [Repository Structure](#repository-structure)
- [Key Technical Decisions](#key-technical-decisions)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
-[Performance & Security Metrics ](#performance-security-metrics)
- [Lessons Learned](#lessons-learned)
- [Real-World Threat Context](#real-world-threat-context)
- [References](#references)

---

## Overview

This project implements a **defense-in-depth** security architecture for Kubernetes, spanning four enforcement points: pre-runtime image scanning, admission-time policy enforcement, network-layer mTLS, and runtime syscall detection. Each layer is implemented with a different open source tool, and each is validated against a concrete attack scenario executed inside kube-goat.

The argument the PoC makes is that **no single tool is sufficient**. A vulnerable image can pass admission control and only become detectable at runtime. A misconfigured policy can be enforced at admission and still allow lateral movement at the network layer. Combining the four layers produces a security posture where every stage of the attack lifecycle has at least one detection or prevention mechanism behind it.

The full installation reference for this stack is in [`PoC.txt`](PoC.txt). Evidence (screenshots, vulnerability reports, alert outputs) for each layer lives inside its own directory in this repository.

---

## Threat Model

The protected asset is the kube-goat application — a deliberately misconfigured multi-namespace workload that ships with containers running as root, exposed service account tokens, and untagged images. These misconfigurations are not bugs to fix; they are the attack surface this stack is designed to detect and contain.

The assumed adversary has already achieved code execution inside one of the kube-goat pods — via an exploited CVE in a vulnerable base image, a misconfigured public-facing endpoint, or compromised credentials. From that initial foothold, the adversary attempts to escalate privileges, harvest credentials from the filesystem or the Kubernetes API, move laterally to other namespaces, and establish persistence. This is the attack lifecycle this PoC maps end-to-end.

The four security layers operate at different points in that lifecycle and with different enforcement semantics:

**Monitoring** (Trivy, Falco, Loki) — observes and records. Trivy surfaces vulnerable images before they run. Falco intercepts suspicious syscalls at runtime. Loki retains the full event log for forensic search. None of these layers block anything; they produce signal for investigation.

**Prevention** (Kyverno) — rejects non-compliant resources at admission time, before any workload is scheduled. A pod that violates policy never runs.

**Enforcement** (Istio mTLS STRICT) — rejects unencrypted service-to-service connections at the network proxy, regardless of what the application layer requests. An attacker with code execution in one pod cannot eavesdrop on or impersonate traffic from another service.

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
│   ├── AlertManager            ← Alert routing and grouping
│   └── Loki                    ← Falco JSON log aggregation
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

**Findings on kube-goat (full reports in [`trivy/`](trivy/)):**

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

Evidence: [`trivy/trivy-vulnerability-report-detail.png`](trivy/trivy-vulnerability-report-detail.png), [`trivy/trivy-vulnerability-reports-all-namespaces.png`](trivy/trivy-vulnerability-reports-all-namespaces.png), plus per-workload YAML extracts in the same directory.

```bash
kubectl get vulnerabilityreports -A -o custom-columns=\
"NAMESPACE:.metadata.namespace,\
NAME:.metadata.name,\
CRITICAL:.report.summary.criticalCount,\
HIGH:.report.summary.highCount,\
MEDIUM:.report.summary.mediumCount,\
LOW:.report.summary.lowCount"

kubectl describe vulnerabilityreport -n default <report-name> \
  | grep -E "Severity|Title|Vulnerability Id"
```

---

### Layer 2 — Admission Control: Kyverno

Kyverno operates as a Kubernetes admission webhook. Every resource creation or update — `kubectl apply`, Helm install, controller-generated pods — passes through Kyverno's validating and mutating webhooks before the API server accepts it. In `Enforce` mode, non-compliant resources are rejected outright. In `Audit` mode, violations are recorded as `PolicyReport` resources without blocking.

Policies are written as Kubernetes YAML using the same patterns as any other resource. There is no separate policy language or runtime to manage.

**Five policies are enforced (in [`kyverno/policies/`](kyverno/policies/)):**

| Policy | What it blocks | Rationale |
|---|---|---|
| `block-privileged.yaml` | Containers with `privileged: true` | Privileged containers share the host kernel namespace — escape gives full host access |
| `require-non-root.yaml` | Containers without `runAsNonRoot: true` | Root inside a container maps to root on host if namespace isolation fails |
| `block-latest-tag.yaml` | Images tagged `:latest` | Untagged images are non-deterministic across pulls |
| `block-host-namespaces.yaml` | Pods using `hostNetwork`, `hostPID`, `hostIPC` | Host namespace access bypasses container isolation |
| `require-resource-limits.yaml` | Pods without CPU/memory limits | Unbounded pods enable DoS and resource hijacking |

**kube-goat violations caught:**

Enforcement was validated by attempting to redeploy `hunger-check-deployment` into `big-monolith`. Kyverno blocked the deployment with the following errors:

```
admission webhook "validate.kyverno.svc-fail" denied the request:
require-non-root: autogen-require-non-root failed at path
  /spec/template/spec/containers/0/securityContext/
require-resource-limits: autogen-require-limits failed at path
  /spec/template/spec/containers/0/resources/limits/
```

All documented kube-goat misconfigurations are surfaced by Kyverno:
- `hunger-check` runs as root → `require-non-root` violation
- All kube-goat images use `:latest` → `block-latest-tag` violation
- No resource limits defined → `require-resource-limits` violation

Evidence: [`kyverno/kyverno-clusterpolicies-all-5-ready.png`](kyverno/kyverno-clusterpolicies-all-5-ready.png), [`kyverno/kyverno-policy-violation-events.png`](kyverno/kyverno-policy-violation-events.png), [`kyverno/kyverno-block-*.png`](kyverno/).

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

Evidence: [`istio/kiali-traffic-graph-service-mesh.png`](istio/kiali-traffic-graph-service-mesh.png), [`istio/kiali-mesh-view-control-plane.png`](istio/kiali-mesh-view-control-plane.png), [`istio/kiali-kubernetes-goat-home-envoy-metrics.png`](istio/kiali-kubernetes-goat-home-envoy-metrics.png).

```bash
kubectl get peerauthentication -A
# Kiali → Graph → Display → Security → lock icons = mTLS enforced
```

---

### Layer 4 — Runtime: Falco + Prometheus + Grafana + Loki

Falco runs as a DaemonSet and uses Linux eBPF to intercept syscalls at the kernel level. Every `open()`, `execve()`, `connect()`, `write()` — Falco sees it all, evaluates it against a ruleset, and emits a structured alert if a rule matches. The detection happens in kernel space, before the syscall completes.

The `modern_ebpf` driver uses CO-RE (Compile Once, Run Everywhere) via BTF. No kernel headers, no prebuilt driver download, no compilation step. The driver loads directly into the running kernel via the BPF subsystem.

**Metrics pipeline:**
```
Falco (:8765/metrics)
    ↓  Prometheus ServiceMonitor (15s interval)
Prometheus
    ↓
Grafana

Exposed metrics (falcosecurity_* prefix):
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

**Log aggregation pipeline:**
```
Falco JSON output → Loki → Grafana Explore (LogQL)
```

Useful LogQL queries:
```logql
{namespace="falco", container="falco"} |= "Warning"
{namespace="falco", container="falco"} |= "/etc/shadow"
```

Evidence: [`loki/loki-falco-warning-logs-explore.png`](loki/loki-falco-warning-logs-explore.png)

**Custom rule tuning ([`falco/helm-values.yaml`](falco/helm-values.yaml) + [`falco/custom-rules.yaml`](falco/custom-rules.yaml)):**

The configuration is split across two files:
- `helm-values.yaml` — driver config, metrics, webserver, http_output, and noise reduction rules (`known_drop_and_execute_containers`, `known_drop_and_execute_activities` macro extensions, disabled rules)
- `custom-rules.yaml` — detection rules for specific PoC scenarios (`Read Kubernetes Service Account Token`, `Detect curl or wget inside container`)

The kube-goat namespaces (`big-monolith`, `secure-middleware`) are deliberately never whitelisted — every event from the attack surface reaches the alert pipeline.

Evidence: [`falco/falco-attack*.png`](falco/), [`grafana/grafana-falco-dashboard-*.png`](grafana/), [`prometheus/prometheus-falco-rules-*.png`](prometheus/).

---

## Attack Scenarios & Detection

All attacks are executed against the `hunger-check` pod in the `big-monolith` namespace. After each command, the alert appears in Falcosidekick UI within seconds and the `falcosecurity_falco_rules_matches_total` counter increments in Grafana. Full attack documentation lives in [`falco/Attacks PoC.txt`](falco/Attacks%20PoC.txt).

### PoC 1 — Sensitive File Access (MITRE T1555)
```bash
kubectl exec -n big-monolith \
  $(kubectl get pod -n big-monolith -o jsonpath='{.items[0].metadata.name}') \
  -- cat /etc/shadow
```
**Rule:** `Read sensitive file untrusted` — **Warning**  
**Evidence:** [`falco/falco-attack2-sensitive-file-shadow.png`](falco/falco-attack2-sensitive-file-shadow.png)

---

### PoC 2 — Fileless Malware via /dev/shm (MITRE T1620)
```bash
kubectl exec -n big-monolith \
  $(kubectl get pod -n big-monolith -o jsonpath='{.items[0].metadata.name}') \
  -- sh -c "cp /bin/sh /dev/shm/evil && /dev/shm/evil -c id"
```
**Rule:** `Execution from /dev/shm` — **Critical**  
**Evidence:** [`falco/falco-attack1-devshm-execution.png`](falco/falco-attack1-devshm-execution.png)  
**Why it matters:** `/dev/shm` is a memory-backed filesystem — binaries written here leave no disk trace. This is the exact persistence pattern used by CanisterWorm (March 2026).

---

### PoC 3 — Service Account Token Access (MITRE T1528)
```bash
kubectl exec -n big-monolith \
  $(kubectl get pod -n big-monolith -o jsonpath='{.items[0].metadata.name}') \
  -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```
**Rule:** `Read Kubernetes Service Account Token` — **Warning**  
**Evidence:** [`falco/falco-attack3-serviceaccount-token.png`](falco/falco-attack3-serviceaccount-token.png)

---

### PoC 4 — C2 Outbound Connection (MITRE T1105)
```bash
kubectl exec -n big-monolith \
  $(kubectl get pod -n big-monolith -o jsonpath='{.items[0].metadata.name}') \
  -- curl -s http://example.com
```
**Rule:** `Detect curl or wget inside container` — **Warning**  
**Evidence:** [`falco/falco-attack4-curl-c2.png`](falco/falco-attack4-curl-c2.png)

---

### PoC 5 — K8s API Lateral Movement (MITRE T1613)
```bash
kubectl exec -n big-monolith \
  $(kubectl get pod -n big-monolith -o jsonpath='{.items[0].metadata.name}') \
  -- curl -k https://kubernetes.default.svc/api/v1/namespaces
```
**Rule:** `Contact K8S API Server From Container` — **Notice**  
**Evidence:** [`falco/falco-attack5-k8s-api-lateral-movement.png`](falco/falco-attack5-k8s-api-lateral-movement.png), [`istio/kiali-traffic-graph-service-mesh.png`](istio/kiali-traffic-graph-service-mesh.png)

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
| Loki Stack | v2.9.3 | monitoring | Log aggregation |
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

kubectl get pods -A | grep -v kube-system
bash access-kubernetes-goat.sh
# → http://127.0.0.1:1234
```

### Step 3 — Add Helm repos

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
```

### Step 4 — Deploy Falco

```bash
kubectl create namespace falco

helm install falco falcosecurity/falco \
  --namespace falco \
  -f falco/helm-values.yaml

kubectl rollout status daemonset/falco -n falco
```

### Step 5 — Deploy Prometheus + Grafana

```bash
kubectl create namespace monitoring

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  -f prometheus/helm-values.yaml

kubectl rollout status deployment/prometheus-grafana -n monitoring
```

### Step 6 — Falco Service + ServiceMonitor

```bash
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

kubectl apply -f prometheus/servicemonitors.yaml
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
```

### Step 8 — Deploy Loki

```bash
helm install loki grafana/loki-stack \
  --namespace monitoring \
  --set grafana.enabled=false \
  --set prometheus.enabled=false

kubectl get pods -n monitoring | grep loki
```

### Step 9 — Deploy Trivy Operator

```bash
helm install trivy-operator aquasecurity/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  -f trivy/helm-values.yaml

kubectl rollout status deployment/trivy-operator -n trivy-system
kubectl get vulnerabilityreports -A
```

### Step 10 — Deploy Kyverno

```bash
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  -f kyverno/helm-values.yaml

kubectl rollout status deployment/kyverno-admission-controller -n kyverno

kubectl apply -f kyverno/policies/

kubectl get clusterpolicy
kubectl get policyreport -A
```

### Step 11 — Deploy Istio + Kiali

```bash
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.24.0 sh -
cd istio-1.24.0 && export PATH=$PWD/bin:$PATH

istioctl install --set profile=demo -y
kubectl rollout status deployment/istiod -n istio-system

kubectl apply -f samples/addons/kiali.yaml
kubectl apply -f samples/addons/prometheus.yaml
kubectl rollout status deployment/kiali -n istio-system

kubectl label namespace big-monolith istio-injection=enabled
kubectl label namespace secure-middleware istio-injection=enabled
kubectl label namespace default istio-injection=enabled

kubectl rollout restart deployment -n big-monolith
kubectl rollout restart deployment -n secure-middleware
kubectl rollout restart deployment -n default

kubectl get pods -n big-monolith
kubectl get peerauthentication -A
```

---

## Dashboard Access

```bash
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
sum(falcosecurity_falco_rules_matches_total)
sum by (rule) (increase(falcosecurity_falco_rules_matches_total[5m]))
rate(falcosecurity_scap_n_evts_total[1m])
falcosecurity_falco_cpu_usage_ratio * 100
```

**Useful LogQL queries (Grafana Explore + Loki):**
```logql
{namespace="falco", container="falco"} |= "Warning"
{namespace="falco", container="falco"} |= "Critical"
{namespace="falco", container="falco"} | json | priority="Warning"
```

---

## Repository Structure

```
thesis-poc/
│
├── falco/
│   ├── helm-values.yaml              # Falco config + noise reduction rules
│   ├── custom-rules.yaml             # Detection rules (SA token, curl/wget)
│   ├── Attacks PoC.txt               # Attack documentation per PoC
│   ├── falco-attack1-devshm-execution.png
│   ├── falco-attack2-sensitive-file-shadow.png
│   ├── falco-attack3-serviceaccount-token.png
│   ├── falco-attack4-curl-c2.png
│   └── falco-attack5-k8s-api-lateral-movement.png
│
├── grafana/
│   ├── grafana-falco-dashboard-kernel-host.png
│   └── grafana-falco-dashboard-overview.png
│
├── istio/
│   ├── kiali-health-check-istio-validation-warning.png
│   ├── kiali-health-check-workload-overview.png
│   ├── kiali-kubernetes-goat-home-envoy-logs.png
│   ├── kiali-kubernetes-goat-home-inbound-metrics.png
│   ├── kiali-mesh-view-control-plane.png
│   └── kiali-traffic-graph-service-mesh.png
│
├── kyverno/
│   ├── helm-values.yaml
│   ├── policies/
│   │   ├── block-host-namespaces.yaml
│   │   ├── block-latest-tag.yaml
│   │   ├── block-privileged.yaml
│   │   ├── require-non-root.yaml
│   │   └── require-resource-limits.yaml
│   ├── kyverno-clusterpolicies-all-5-ready.png
│   ├── kyverno-hunger-check.png
│   ├── kyverno-policy-violation-events.png
│   └── test.txt
│
├── loki/
│   └── loki-falco-warning-logs-explore.png
│
├── prometheus/
│   ├── helm-values.yaml
│   ├── servicemonitors.yaml
│   ├── prometheus-falco-rules-rate-graph.png
│   ├── prometheus-falco-rules-total-graph.png
│   └── prometheus-falco-rules-total-table.png
│
├── trivy/
│   ├── helm-values.yaml
│   ├── default_replicaset-d59fd5d4c.txt
│   ├── default_replicaset-internal-proxy-deployment-789cdcf4f9-internal-api.txt
│   ├── default_replicaset-poor-registry-deployment-57597689b5-poor-registry.txt
│   ├── default_replicaset-system-monitor-deployment-576f894bc6-system-monitor.txt
│   ├── secure-middleware_replicaset-cache-store-deployment-77dd448588-cache-store.txt
│   ├── trivy-vulnerability-report-detail.png
│   └── trivy-vulnerability-reports-all-namespaces.png
│
├── PoC.txt
└── README.md
```

---

## Key Technical Decisions

**`modern_ebpf` over `ebpf` driver**  
Kernel `6.8.0-100-generic` has no prebuilt Falco driver, and kernel headers are unavailable inside kind nodes. `modern_ebpf` uses CO-RE via BTF — the probe runs on any BTF-enabled kernel (5.8+) without compilation, init container, or driver download.

**k8s v1.32.0 over v1.27**  
Kyverno v1.17+ integrates with the `ValidatingAdmissionPolicy` API, stable since k8s 1.30. Running on 1.32 enables both the Kyverno webhook and the native k8s enforcement mechanism in parallel. An earlier version of this lab (k8s 1.27) caused Kyverno's admission controller to crash on startup due to missing API resources — the cluster was rebuilt on 1.32 to resolve this.

**Kyverno over OPA/Gatekeeper**  
Kyverno uses native Kubernetes YAML for policies — no Rego required. It supports mutation and generation policies beyond validation. For a thesis demonstrating admission control, Kyverno produces equivalent enforcement with significantly lower operational overhead.

**Falco native metrics over falco-exporter**  
`falco-exporter` was deprecated starting with Falco 0.38. From 0.38+, Falco exposes Prometheus metrics natively at `:8765/metrics`. The metric prefix changed from legacy `falco_*` to `falcosecurity_*` — making existing community dashboards (e.g. Grafana ID 11914) incompatible. The dashboards in this repo use current metric names.

**Falco configuration split across two files**  
`helm-values.yaml` contains the full Falco deployment config including noise reduction rules and disabled rules for system components. `custom-rules.yaml` contains the detection rules written specifically for the PoC attack scenarios. This separation keeps noise reduction config distinct from detection logic.

**Loki for log aggregation alongside Prometheus metrics**  
Prometheus stores numeric counters — how many alerts fired. Loki stores the full JSON event payload — which file, which user, which container, at what time. Both are required: counters show that something happened, log search shows exactly what.

**Noise reduction via macro extension, not rule disabling**  
The default Falco ruleset fires on legitimate kubelet, Prometheus, and node-exporter activity. Rather than disabling rules entirely, this stack extends the `known_drop_and_execute_containers` list and `known_drop_and_execute_activities` macro with `override: condition: append` to whitelist specific system images and namespaces. The kube-goat namespaces are never whitelisted.

**mTLS STRICT over PERMISSIVE**  
PERMISSIVE allows plaintext for migration scenarios. STRICT enforces encryption and rejects unencrypted connections — every communication in the mesh requires a valid certificate from the mesh CA.

---

## MITRE ATT&CK Coverage

The table below lists only techniques **demonstrated with concrete evidence** in this PoC — alert screenshots, vulnerability reports, or Kiali service graph captures.

| Technique | ID | Detection / Prevention | Layer | Evidence |
|---|---|---|---|---|
| Supply Chain Compromise | T1195.002 | Trivy | Pre-runtime | `trivy/trivy-vulnerability-report-detail.png` — 2 CRITICAL + 10 HIGH CVEs |
| Valid Accounts — service account token exposure | T1078 | Kyverno | Admission | `kyverno/kyverno-policy-violation-events.png` — `hunger-check` violations |
| Credential Access — credentials from files | T1555 | Falco | Runtime | `falco/falco-attack2-sensitive-file-shadow.png` |
| Defense Evasion — reflective code loading (/dev/shm) | T1620 | Falco | Runtime | `falco/falco-attack1-devshm-execution.png` |
| Credential Access — steal application access token | T1528 | Falco | Runtime | `falco/falco-attack3-serviceaccount-token.png` |
| Command & Control — ingress tool transfer | T1105 | Falco | Runtime | `falco/falco-attack4-curl-c2.png` |
| Discovery — container and resource discovery | T1613 | Falco + Kiali | Runtime + Network | `falco/falco-attack5-k8s-api-lateral-movement.png` |
| Lateral Movement — cross-namespace service access | — | Istio / Kiali | Network | `istio/kiali-traffic-graph-service-mesh.png` |

---

## Performance & Security Metrics

The following measurements were collected from the live cluster during PoC execution.

### Runtime Detection Overhead (Falco)

| Metric | Value |
|---|---|
| CPU usage | 5.5% |
| Memory (RSS) | 158 MB |
| Syscall throughput | 8,823 events/sec |
| Event drop rate | 0% |

Falco processed over 8,800 syscalls per second with zero event drops, meaning no syscall
was missed during the observation window. The CPU and memory footprint remained within
acceptable bounds for a production DaemonSet.

### Alert Accuracy

After noise reduction tuning, only three rules produced alerts across the entire observation
period — all corresponding to deliberate PoC attack commands:

| Rule | Alerts |
|---|---|
| Read sensitive file untrusted | 11 |
| Execution from /dev/shm | 2 |
| Contact K8S API Server From Container | 1 |

Zero alerts were produced by legitimate system activity (kubelet, Prometheus, node-exporter),
confirming that the macro extension approach eliminated false positives without creating
blind spots on the attack surface.

### Vulnerability Surface (Trivy)

Trivy scanned all kube-goat workloads before any attack was launched:

| Image | Critical | High | Medium | Low |
|---|---|---|---|---|
| `metadata-db` | 89 | 930 | 942 | 86 |
| `build-code` | 20 | 101 | 90 | 8 |
| `batch-check` | 15 | 92 | 102 | 28 |
| `poor-registry` | 5 | 55 | 60 | 4 |
| `internal-api` | 2 | 37 | 29 | 40 |
| `k8s-goat-home` | 2 | 21 | 14 | 23 |
| `cache-store` | 0 | 4 | 16 | 14 |
| `hidden-in-layers` | 0 | 4 | 16 | 14 |
| `system-monitor` | 0 | 1 | 111 | 68 |
| **Total** | **133** | **1,245** | **1,380** | **279** |

133 CRITICAL and 1,245 HIGH CVEs were identified across kube-goat workloads before
a single attack command was executed.

### Policy Compliance (Kyverno)

| Namespace | Pass | Fail | Violation Rate |
|---|---|---|---|
| `default` (kube-goat) | 132 | 68 | 34% |
| `secure-middleware` (kube-goat) | 12 | 8 | 40% |
| `falco` | 24 | 0 | 0% |
| `kyverno` | 70 | 15 | 18% |
| `istio-system` | 57 | 18 | 24% |
| `monitoring` | 50 | 30 | 38% |
| `kube-system` | 28 | 32 | 53% |

The kube-goat namespaces show a 34-40% policy violation rate, confirming the intentional
misconfigurations. The `falco` namespace shows 0% violations, validating that namespace
exceptions are correctly configured.

### Network Enforcement (Istio)

| Namespace | PeerAuthentication | Mode |
|---|---|---|
| `default` | ✅ Active | STRICT |
| `big-monolith` | ✅ Active | STRICT |
| `secure-middleware` | ✅ Active | STRICT |

All kube-goat namespaces enforce mTLS STRICT mode — plaintext service-to-service
connections are rejected at the Envoy proxy level.

---

## Lessons Learned

**Falco rule `override: enabled: replace` requires the rule to exist in the loaded ruleset.**  
If the rule name does not match exactly — including capitalization and punctuation — Falco fails at startup with a validation error. Verify with `grep "^- rule:" /etc/falco/falco_rules.yaml` before writing overrides.

**kind nodes require explicit host mounts for eBPF.**  
Without mounting `/proc`, `/sys`, and `/` from the host, Falco's eBPF probe loads but cannot instrument syscalls.

**Kyverno namespace exceptions must cover all system tooling.**  
Before switching any policy to `Enforce`, add exceptions for `kube-system`, `monitoring`, `falco`, `trivy-system`, `istio-system`, and `kyverno`. Without them, Kyverno blocks its own DaemonSets.

**The `falcosecurity_*` metric prefix is breaking.**  
Any PromQL query or Grafana dashboard using the legacy `falco_*` prefix returns no data against Falco 0.38+. Grafana community dashboard ID 11914 is incompatible.

---

## Real-World Threat Context

During the development of this thesis (March 2026), a real supply chain attack targeted the Trivy scanner itself. Threat actor **TeamPCP** published malicious versions of `trivy`, `trivy-action`, and `setup-trivy` to GitHub, containing a credential stealer paired with a self-propagating worm named **CanisterWorm**. The worm spread across 141 npm packages by harvesting npm authentication tokens and republishing infected versions autonomously.

The persistence mechanism used by CanisterWorm — dropping a binary to `/dev/shm` and executing it — is exactly what PoC 2 simulates. The Falco rule `Execution from /dev/shm` detects it in real time.

The incident illustrates the value of layered defense:

- **Trivy Operator** would flag the compromised `trivy` image as containing malicious code before deployment
- **Falco** would catch the `/dev/shm` execution at runtime regardless of how the binary arrived
- **Kiali** would surface unexpected outbound connections to the C2 infrastructure

No single layer is sufficient. The combination is what provides resilience.

---

## References

- [Falco Documentation](https://falco.org/docs/)
- [Falco Rules Reference](https://falco.org/docs/reference/rules/)
- [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)
- [Loki Documentation](https://grafana.com/docs/loki/latest/)
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

*Falco · Kyverno · Trivy · Istio · Kiali · Prometheus · Grafana · Loki · kind · kube-goat*
