# Kubernetes & Container Runtime Security Auditor

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

🔍 Comprehensive security auditing tool for Kubernetes clusters and container workloads based on CIS Kubernetes Benchmark and Pod Security Standards.

> ⚠️ **LEGAL NOTICE**: This tool is for **AUTHORIZED** security auditing of clusters you own or have explicit permission to audit. Unauthorized scanning is illegal. Use at your own risk.

## ✨ Features

- 🔒 **Workload Security Auditing**
  - Privileged containers detection
  - Root user execution checks (`runAsNonRoot`)
  - Dangerous Linux capabilities (`SYS_ADMIN`, `NET_ADMIN`, etc.)
  - Host namespace escapes (`hostNetwork`, `hostPID`, `hostIPC`)
  - HostPath volume usage
  
- 👥 **RBAC Security Analysis**
  - Wildcard resource/verb detection in Roles & ClusterRoles
  - Over-privileged service accounts identification
  
- 🔑 **Secrets Management Audit**
  - Detection of secrets exposed via environment variables
  
- 🌐 **Network Policy Compliance**
  - Identification of namespaces without NetworkPolicies
  
- 🖥️ **Node-Level Checks** (Aggressive Mode)
  - Container runtime analysis
  
- 📊 **Professional Reporting**
  - Colorized terminal output with Rich
  - Compliance scoring system (0-100)
  - CIS Benchmark references for all findings
  - Pod Security Standards mapping (Baseline/Restricted)
  - Severity-based prioritization (Critical → Info)

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Valid `kubeconfig` with cluster access
- Appropriate RBAC permissions (read-only recommended)

### Installation

```bash
# Clone repository
git clone https://github.com/arkanzasfeziii/k8s-security-auditor.git
cd k8s-security-auditor

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/MacOS
# OR
venv\Scripts\activate     # Windows
```

Basic Usage

```bash
# Audit current context (default namespace)
python k8scontainerauditor.py --i-understand-legal-responsibilities

# Audit specific namespace
python k8scontainerauditor.py --namespace production --i-understand-legal-responsibilities

# Full cluster audit (all namespaces + aggressive checks)
python k8scontainerauditor.py --namespace all --aggressive --i-understand-legal-responsibilities

# Use custom kubeconfig
python k8scontainerauditor.py --kubeconfig ~/.kube/prod-config --i-understand-legal-responsibilities
```

Usage Examples

```bash
# Show all available options
python k8scontainerauditor.py --help

# Show practical examples
python k8scontainerauditor.py --examples

# Verbose output for debugging
python k8scontainerauditor.py --verbose --i-understand-legal-responsibilities
```

📋 Sample Output

```bash
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ⚠️  LEGAL WARNING ⚠️                               ║
╟──────────────────────────────────────────────────────────────────────────────╢
║ This tool requires VALID cluster access and is for AUTHORIZED auditing      ║
║ of YOUR OWN Kubernetes clusters ONLY.                                       ║
║                                                                              ║
║ Scanning without permission is ILLEGAL.                                     ║
║ Author (arkanzasfeziii) assumes NO liability for misuse.                    ║
║                                                                              ║
║ Use least-privilege credentials for auditing.                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

Do you have authorization to audit this cluster? (yes/no): yes

   __ __            __        __                      __          __   
  / // /_ ____     / /_____ _/ /_____ ___  ___  _____/ /_  ____  / /__ 
 / _  / // / _ \   / __/ __ `/ //_/ _ `__ \/ _ \/ ___/ __ \/ __ \/ //_/
/_//_/\_,_/_//_/   \__/\_,_/_/ /_/ /_/ /_/ .___/\___/_.__/\____/_/ (_) 
                                        /_/                             

Author: arkanzasfeziii

Cluster Version: v1.27.3

Auditing workload security... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
Auditing RBAC configuration... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
Auditing secrets management... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
Auditing network policies... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

================================================================================
Security Audit Summary
================================================================================

Compliance Score: 68.5/100

┌──────────────┬───────┐
│ Metric       │ Value │
├──────────────┼───────┤
│ Cluster      │ prod  │
│ Total Findings │ 14    │
└──────────────┴───────┘

Findings by Severity

┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ CRITICAL │ 2     │
│ HIGH     │ 7     │
│ MEDIUM   │ 4     │
│ LOW      │ 1     │
└──────────┴───────┘

Detailed Findings

┌──────────────────────────────────────────────────────────────────────────────┐
│ Finding #1: Privileged Container Detected                                    │
├──────────────────────────────────────────────────────────────────────────────┤
│ Category: Privileged Container                                               │
│ Severity: CRITICAL                                                           │
│ Affected: production/nginx-deployment-7df85ff87d-2xv9q                       │
│                                                                              │
│ Description:                                                                 │
│ Container 'nginx' in pod 'production/nginx-deployment-7df85ff87d-2xv9q' runs │
│ privileged                                                                   │
│                                                                              │
│ Recommendation:                                                              │
│ Remove privileged flag unless absolutely necessary. Use specific             │
│ capabilities instead.                                                        │
│                                                                              │
│ CIS Reference: CIS 5.2.1: Minimize privileged containers                     │
└──────────────────────────────────────────────────────────────────────────────┘
...
```

🔐 Security Considerations

✅ Least Privilege Principle: Tool only requires read-only access (get, list, watch verbs)

✅ No Modifications: Purely read-only auditor - makes zero changes to your cluster

✅ Local Execution: All analysis happens locally - no data leaves your machine

⚠️ Permission Requirements: Some checks require cluster-admin level permissions (e.g., node audits). Use --aggressive flag cautiously.

# Install dependencies

```bash
pip install -r requirements.txt
```

Recommended RBAC for Auditing

```bash
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-auditor
rules:
- apiGroups: ["", "apps", "batch", "networking.k8s.io", "rbac.authorization.k8s.io"]
  resources: ["*"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: security-auditor-binding
subjects:
- kind: ServiceAccount
  name: auditor
  namespace: security-audit
roleRef:
  kind: ClusterRole
  name: security-auditor
  apiGroup: rbac.authorization.k8s.io
```
