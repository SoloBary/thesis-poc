# Kubernetes & Container Security Monitoring with Open Source Tools

> **Master's Thesis — Proof of Concept**  
> A full, production-grade security monitoring stack deployed on a local Kubernetes cluster using exclusively open source tools, with [kube-goat](https://github.com/madhuakula/kubernetes-goat) as the intentionally vulnerable attack target.

---

## Overview

This repository contains all artifacts, configurations, and documentation for a layered Kubernetes security monitoring stack. The goal is to demonstrate that enterprise-grade threat detection, policy enforcement, and observability can be achieved entirely with open source tooling — at zero licensing cost.

The stack is organized around a **defense-in-depth** model with four distinct security layers, each catching what the previous one misses.

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1 — Pre-Runtime     Trivy Operator               │
│  Layer 2 — Admission       Kyverno                      │
│  Layer 3 — Network         Istio + Kiali                │
│  Layer 4 — Runtime         Falco + Prometheus + Grafana │
└─────────────────────────────────────────────────────────┘
```

---

## Architecture

```
Kubernetes Cluster (kind v0.26.0 / k8s v1.32.0)
│
├── kube-goat (attack target)
│   ├── namespace: big-monolith
│   └── namespace: secure-middleware
│
├── falco (namespace: falco)
│   ├── Falco DaemonSet         ← eBPF syscall detection (modern_ebpf)
│   ├── Falcosidekick           ← Event router
│   └── Falcosidekick UI        ← Real-time alert dashboard
│
├── monitoring (namespace: monitoring)
│   ├── Prometheus              ← Metrics scraping (falcosecurity_* metrics)
│   ├── Grafana                 ← Custom Falco dashboard
│   └── AlertManager            ← Alert routing
│
├── trivy-system (namespace: trivy-system)
│   └── Trivy Operator          ← Continuous image vulnerability scanning
│
├── kyverno (namespace: kyverno)
│   └── Kyverno                 ← Policy engine / Admission controller
│
└── istio-system (namespace: istio-system)
    ├── Istiod                  ← Service mesh control plane
    ├── Istio Ingress/Egress    ← Traffic management
    └── Kiali                   ← Service graph + mTLS visualization
```

---

## Security Layers

### Layer 1 — Pre-Runtime: Trivy Operator

Trivy Operator continuously scans all container images in the cluster for known CVEs before they pose a runtime threat. It generates `VulnerabilityReport` CRDs per workload.

**Key finding on kube-goat:**

| Image | Critical | High | Medium | Low |
|---|---|---|---|---|
| `k8s-goat-home` | 2 | 10 | 23 | 7 |
| `k8s-goat-hidden-in-layers` | 0 | 4 | 26 | 4 |

Notable CVEs found:
- `CVE-2025-15467` — OpenSSL Remote Code Execution via CMS parsing
- `CVE-2025-69419` — OpenSSL arbitrary code execution via PKCS#12 out-of-bounds write
- `CVE-2024-6119` — OpenSSL denial of service via X.509 name checks

### Layer 2 — Admission Control: Kyverno

Kyverno enforces security policies at the Kubernetes API level — before any workload is scheduled. Policies are defined as Kubernetes CRDs (`ClusterPolicy`).

**Active policies:**

| Policy | Action | Description |
|---|---|---|
| `disallow-privileged-containers` | Audit/Enforce | Block containers with `privileged: true` |
| `disallow-root-user` | Audit/Enforce | Require `runAsNonRoot: true` |
| `disallow-latest-tag` | Audit/Enforce | Block images tagged `:latest` |

**kube-goat violations detected:**
- `hunger-check` runs as root → violates `disallow-root-user`
- All kube-goat images use `:latest` tag → violates `disallow-latest-tag`
- No resource limits set → violates `require-resource-limits`

### Layer 3 — Network: Istio + Kiali

Istio provides mutual TLS (mTLS) encryption between all services in the mesh, enforced via `PeerAuthentication` policies in STRICT mode. Kiali provides real-time service graph visualization.

**mTLS enforced on:**
- `big-monolith` namespace
- `secure-middleware` namespace
- `default` namespace

**Demo scenario:** Kiali visualizes lateral movement — a compromised `hunger-check` pod attempting to reach `metadata-db` across namespace boundaries.

### Layer 4 — Runtime: Falco + Prometheus + Grafana

Falco uses Linux eBPF (`modern_ebpf` driver) to intercept syscalls and detect malicious behavior in real time. No kernel module compilation required — CO-RE based.

**Custom rules tuned for kube-goat:**
- Whitelist of known-good system images to reduce noise
- `Contact K8S API Server From Container` disabled for monitoring stack
- `Redirect STDOUT/STDIN to Network Connection` disabled for kubelet

**Prometheus metrics exposed:**
- `falcosecurity_falco_rules_matches_total` — alert counter per rule
- `falcosecurity_scap_n_evts_total` — syscall event rate
- `falcosecurity_falco_cpu_usage_ratio` — Falco resource usage

---

## Attack Scenarios & Detection

All attacks target the `hunger-check` pod in the `big-monolith` namespace.

### PoC 1 — Sensitive File Access (MITRE T1555)
```bash
kubectl exec -n big-monolith <pod> -- cat /etc/shadow
```
**Detected by:** Falco rule `Read sensitive file untrusted` (Warning)

### PoC 2 — Terminal Shell in Container (MITRE T1059)
```bash
kubectl exec -it -n big-monolith <pod> -- /bin/bash
```
**Detected by:** Falco rule `Terminal shell in container` (Notice)

### PoC 3 — Fileless Malware via /dev/shm (MITRE T1620)
```bash
kubectl exec -n big-monolith <pod> -- sh -c "cp /bin/sh /dev/shm/evil && /dev/shm/evil -c id"
```
**Detected by:** Falco rule `Execution from /dev/shm` (Critical)

### PoC 4 — Search for Private Keys (MITRE T1552)
```bash
kubectl exec -n big-monolith <pod> -- find / -name "*.pem" -o -name "id_rsa" 2>/dev/null
```
**Detected by:** Falco rule `Search Private Keys or Passwords` (Warning)

### PoC 5 — Log Clearing / Anti-Forensics (MITRE T1070)
```bash
kubectl exec -n big-monolith <pod> -- sh -c "cat /dev/null > /var/log/dpkg.log"
```
**Detected by:** Falco rule `Clear Log Activities` (Warning)

---

## Stack Components

| Component | Version | Namespace | Purpose |
|---|---|---|---|
| Kubernetes (kind) | v1.32.0 | — | Cluster |
| kube-goat | latest | big-monolith / secure-middleware | Vulnerable target |
| Falco | 0.43.0 | falco | Runtime detection (modern_ebpf) |
| Falcosidekick | 2.32.0 | falco | Event routing |
| Falcosidekick UI | latest | falco | Alert dashboard |
| Prometheus (kube-prometheus-stack) | v0.89.0 | monitoring | Metrics |
| Grafana | latest | monitoring | Dashboards |
| Trivy Operator | 0.30.1 | trivy-system | Image scanning |
| Kyverno | v1.17.1 | kyverno | Policy enforcement |
| Istio | 1.24.0 | istio-system | Service mesh / mTLS |
| Kiali | latest | istio-system | Service visualization |

---

## Quick Start

### Prerequisites
- Docker
- `kubectl`
- `helm` v3
- `kind` v0.26.0+
- `istioctl`

### 1. Create cluster
```bash
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
EOF

kind create cluster --config kind-config.yaml
```

### 2. Deploy kube-goat
```bash
git clone https://github.com/madhuakula/kubernetes-goat.git
cd kubernetes-goat
bash setup-kubernetes-goat.sh
```

### 3. Add Helm repos
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
```

### 4. Deploy Falco
```bash
kubectl create namespace falco

helm install falco falcosecurity/falco \
  --namespace falco \
  --set driver.kind=modern_ebpf \
  --set falco.metrics.enabled=true \
  --set falco.metrics.interval=15s \
  --set falco.metrics.output_rule=false \
  --set falco.webserver.enabled=true \
  --set falco.webserver.prometheus_metrics_enabled=true \
  --set falco.json_output=true \
  --set falco.http_output.enabled=true \
  --set falco.http_output.url="http://falcosidekick:2801" \
  -f falco/custom-rules.yaml
```

### 5. Deploy Prometheus + Grafana
```bash
kubectl create namespace monitoring

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --set grafana.adminPassword='admin' \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false
```

### 6. Deploy Falcosidekick
```bash
helm install falcosidekick falcosecurity/falcosidekick \
  --namespace falco \
  --set webui.enabled=true \
  --set config.minimumpriority=warning
```

### 7. Deploy Trivy Operator
```bash
helm install trivy-operator aquasecurity/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --set trivy.ignoreUnfixed=true
```

### 8. Deploy Kyverno
```bash
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --set features.policyExceptions.enabled=true \
  --set features.validatingAdmissionPolicyReports.enabled=true

kubectl apply -f kyverno/policies/
```

### 9. Deploy Istio + Kiali
```bash
istioctl install --set profile=demo -y

kubectl apply -f istio-1.24.0/samples/addons/kiali.yaml
kubectl apply -f istio-1.24.0/samples/addons/prometheus.yaml

kubectl label namespace big-monolith istio-injection=enabled
kubectl label namespace secure-middleware istio-injection=enabled
kubectl label namespace default istio-injection=enabled

kubectl rollout restart deployment -n big-monolith
kubectl rollout restart deployment -n secure-middleware

kubectl apply -f istio/mtls/peer-authentication.yaml
```

### 10. Access dashboards
```bash
pkill -f "kubectl port-forward"

kubectl port-forward -n monitoring svc/prometheus-grafana 3001:80 &
kubectl port-forward -n falco svc/falcosidekick-ui 2802:2802 &
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090 &
kubectl port-forward -n istio-system svc/kiali 20001:20001 &
```

| Dashboard | URL | Credentials |
|---|---|---|
| Grafana | http://localhost:3001 | admin / admin |
| Falcosidekick UI | http://localhost:2802 | — |
| Prometheus | http://localhost:9090 | — |
| Kiali | http://localhost:20001 | — |

---

## Repository Structure

```
thesis-poc/
├── falco/
│   ├── custom-rules.yaml       # Falco rule overrides & noise reduction
│   └── screenshots/            # PoC evidence
├── grafana/
│   ├── falco-dashboard.json    # Custom Grafana dashboard (falcosecurity_* metrics)
│   └── screenshots/
├── istio/
│   ├── mtls/
│   │   └── peer-authentication.yaml  # mTLS STRICT mode policies
│   └── screenshots/
├── kyverno/
│   ├── policies/
│   │   ├── disallow-privileged.yaml
│   │   ├── disallow-root.yaml
│   │   └── disallow-latest-tag.yaml
│   └── screenshots/
├── prometheus/
│   ├── servicemonitor.yaml     # Falco ServiceMonitor
│   └── screenshots/
├── trivy/
│   └── screenshots/
├── PoC.txt                     # Attack scenario documentation
└── README.md
```

---

## Key Technical Decisions

**Why `modern_ebpf` over `ebpf` driver?**
The cluster runs on kernel `6.8.0-100-generic`. No prebuilt driver exists for this kernel version on the Falco download server, and kernel headers are unavailable in the kind node image. `modern_ebpf` uses CO-RE (Compile Once, Run Everywhere) — no kernel headers or prebuilt driver needed.

**Why Kyverno over OPA/Gatekeeper?**
Kyverno uses native Kubernetes YAML syntax for policies — no Rego required. It also supports mutation and generation policies beyond just validation, making it more versatile for a thesis demonstrating multiple enforcement scenarios.

**Why Falco native metrics over falco-exporter?**
`falco-exporter` was officially deprecated with Falco 0.38. From 0.38 onward, Falco exposes Prometheus metrics natively at `/metrics` on port 8765 via the built-in webserver. The metric prefix changed to `falcosecurity_*`.

**Noise reduction strategy:**
Rather than disabling rules entirely, this stack uses Kyverno-style `override: condition: append` to whitelist known-good images and namespaces while preserving detection for the kube-goat attack surface. This demonstrates understanding of the threat model — exceptions are surgical, not blanket.

---

## MITRE ATT&CK Coverage

| Technique | ID | Detection Tool |
|---|---|---|
| Credential Access — Credential from Files | T1555 | Falco |
| Execution — Command and Scripting Interpreter | T1059 | Falco |
| Defense Evasion — Reflective Code Loading | T1620 | Falco |
| Credential Access — Unsecured Credentials | T1552 | Falco |
| Defense Evasion — Indicator Removal | T1070 | Falco |
| Discovery — Container and Resource Discovery | T1613 | Falco + Kiali |
| Lateral Movement — (cross-namespace) | — | Kiali / Istio |
| Initial Access — Supply Chain Compromise | T1195 | Trivy |

---

## References

- [Falco Documentation](https://falco.org/docs/)
- [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)
- [Kyverno Policies](https://kyverno.io/policies/)
- [Trivy Operator](https://aquasecurity.github.io/trivy-operator/)
- [Istio Security](https://istio.io/latest/docs/concepts/security/)
- [Kiali](https://kiali.io/)
- [kubernetes-goat](https://github.com/madhuakula/kubernetes-goat)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)

---

## Author

**Bary** — Threat Detection & Response Analyst (L2 SOC)  
Undergraduate Thesis — Dept. Computer Science and Communication Engineering (Samos, Greece)
GitHub: [@SoloBary](https://github.com/SoloBary)
