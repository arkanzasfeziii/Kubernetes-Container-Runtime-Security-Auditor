#!/usr/bin/env python3
"""
Kubernetes & Container Runtime Security Auditor
Comprehensive security auditing for Kubernetes clusters and container workloads.

Author: arkanzasfeziii
License: MIT
Version: 1.0.0
"""

# === Imports ===
import argparse
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from pydantic import BaseModel, ValidationError
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

try:
    import pyfiglet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False


# === Constants ===
VERSION = "1.0.0"
AUTHOR = "arkanzasfeziii"
DEFAULT_KUBECONFIG = Path.home() / ".kube" / "config"
DEFAULT_TIMEOUT = 30

LEGAL_WARNING = """
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
"""

# CIS Kubernetes Benchmark references
CIS_REFERENCES = {
    "anonymous_auth": "CIS 4.2.1: Ensure anonymous-auth is not enabled",
    "privileged": "CIS 5.2.1: Minimize privileged containers",
    "host_network": "CIS 5.2.4: Minimize host networking",
    "rbac_wildcards": "CIS 5.1.3: Minimize wildcard use in Roles and ClusterRoles",
    "secrets_env": "CIS 5.4.1: Prefer using secrets as files over env variables"
}


# === Enums ===
class SeverityLevel(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# === Data Models ===
@dataclass
class Finding:
    """Security audit finding."""
    category: str
    title: str
    description: str
    severity: SeverityLevel
    affected_resources: List[str]
    recommendation: str
    cis_reference: str = ""
    pod_security_standard: str = ""


@dataclass
class AuditResult:
    """Complete audit results."""
    cluster_name: str
    total_checks: int
    findings: List[Finding] = field(default_factory=list)
    compliance_score: float = 100.0
    statistics: Dict[str, Any] = field(default_factory=dict)


# === Utility Functions ===
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)]
    )
    return logging.getLogger("k8sauditor")


def calculate_compliance_score(findings: List[Finding]) -> float:
    """Calculate compliance score based on findings."""
    if not findings:
        return 100.0
    
    weights = {
        SeverityLevel.CRITICAL: 20,
        SeverityLevel.HIGH: 10,
        SeverityLevel.MEDIUM: 5,
        SeverityLevel.LOW: 2,
        SeverityLevel.INFO: 1
    }
    
    deductions = sum(weights.get(f.severity, 0) for f in findings)
    score = max(0, 100 - min(100, deductions))
    return round(score, 1)


# === Kubernetes Security Auditor ===
class KubernetesSecurityAuditor:
    """Main security auditor for Kubernetes clusters."""
    
    def __init__(self, kubeconfig: Optional[Path], context: Optional[str], 
                 namespace: str, aggressive: bool, timeout: int):
        """Initialize auditor."""
        self.kubeconfig = kubeconfig
        self.context = context
        self.namespace = namespace
        self.aggressive = aggressive
        self.timeout = timeout
        self.console = Console()
        self.logger = setup_logging(False)
        self.findings: List[Finding] = []
        
        # Initialize Kubernetes clients
        self._init_kubernetes_clients()
    
    def _init_kubernetes_clients(self) -> None:
        """Initialize Kubernetes API clients."""
        try:
            if self.kubeconfig:
                config.load_kube_config(config_file=str(self.kubeconfig), context=self.context)
            else:
                config.load_kube_config(context=self.context)
            
            self.core_v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.rbac_v1 = client.RbacAuthorizationV1Api()
            self.networking_v1 = client.NetworkingV1Api()
            
            # Get cluster info
            try:
                version = client.VersionApi().get_code()
                self.cluster_version = f"{version.major}.{version.minor}"
            except:
                self.cluster_version = "unknown"
            
        except Exception as e:
            self.console.print(f"[red]Failed to connect to cluster: {e}[/red]")
            sys.exit(1)
    
    def audit(self) -> AuditResult:
        """Run complete security audit."""
        self._print_banner()
        self.console.print(f"[cyan]Cluster Version:[/cyan] {self.cluster_version}\n")
        
        total_checks = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Workload security
            task = progress.add_task("Auditing workload security...", total=None)
            self._audit_workload_security()
            total_checks += 1
            progress.remove_task(task)
            
            # RBAC
            task = progress.add_task("Auditing RBAC configuration...", total=None)
            self._audit_rbac()
            total_checks += 1
            progress.remove_task(task)
            
            # Secrets
            task = progress.add_task("Auditing secrets management...", total=None)
            self._audit_secrets()
            total_checks += 1
            progress.remove_task(task)
            
            # Network policies
            task = progress.add_task("Auditing network policies...", total=None)
            self._audit_network_policies()
            total_checks += 1
            progress.remove_task(task)
            
            # Nodes (if aggressive)
            if self.aggressive:
                task = progress.add_task("Auditing node configuration...", total=None)
                self._audit_nodes()
                total_checks += 1
                progress.remove_task(task)
        
        # Calculate statistics and score
        stats = self._calculate_statistics()
        score = calculate_compliance_score(self.findings)
        
        return AuditResult(
            cluster_name=self.context or "current-context",
            total_checks=total_checks,
            findings=self.findings,
            compliance_score=score,
            statistics=stats
        )
    
    def _audit_workload_security(self) -> None:
        """Audit workload security configurations."""
        try:
            if self.namespace == "all":
                pods = self.core_v1.list_pod_for_all_namespaces(timeout_seconds=self.timeout)
            else:
                pods = self.core_v1.list_namespaced_pod(self.namespace, timeout_seconds=self.timeout)
            
            for pod in pods.items:
                self._check_pod_security(pod)
        
        except ApiException as e:
            if e.status == 403:
                self.logger.warning("Insufficient permissions to list pods")
            else:
                self.logger.error(f"Error auditing workloads: {e}")
    
    def _check_pod_security(self, pod) -> None:
        """Check individual pod security."""
        pod_name = f"{pod.metadata.namespace}/{pod.metadata.name}"
        
        if not pod.spec.containers:
            return
        
        for container in pod.spec.containers:
            security_context = container.security_context or {}
            
            # Check privileged
            if security_context.get('privileged'):
                self.findings.append(Finding(
                    category="Privileged Container",
                    title="Privileged Container Detected",
                    description=f"Container '{container.name}' in pod '{pod_name}' runs privileged",
                    severity=SeverityLevel.CRITICAL,
                    affected_resources=[pod_name],
                    recommendation="Remove privileged flag unless absolutely necessary. "
                                  "Use specific capabilities instead.",
                    cis_reference=CIS_REFERENCES["privileged"],
                    pod_security_standard="Restricted"
                ))
            
            # Check runAsNonRoot
            if not security_context.get('runAsNonRoot'):
                self.findings.append(Finding(
                    category="Root User",
                    title="Container Not Running as Non-Root",
                    description=f"Container '{container.name}' in pod '{pod_name}' may run as root",
                    severity=SeverityLevel.HIGH,
                    affected_resources=[pod_name],
                    recommendation="Set runAsNonRoot: true in securityContext",
                    cis_reference="CIS 5.2.6",
                    pod_security_standard="Restricted"
                ))
            
            # Check capabilities
            if security_context.get('capabilities', {}).get('add'):
                added_caps = security_context['capabilities']['add']
                dangerous_caps = {'SYS_ADMIN', 'NET_ADMIN', 'SYS_MODULE'}
                if any(cap in dangerous_caps for cap in added_caps):
                    self.findings.append(Finding(
                        category="Dangerous Capabilities",
                        title="Dangerous Linux Capabilities Added",
                        description=f"Container '{container.name}' in pod '{pod_name}' "
                                   f"adds dangerous capabilities: {added_caps}",
                        severity=SeverityLevel.HIGH,
                        affected_resources=[pod_name],
                        recommendation="Remove dangerous capabilities. Use minimal required caps.",
                        cis_reference="CIS 5.2.9",
                        pod_security_standard="Restricted"
                    ))
        
        # Check pod-level security
        pod_security = pod.spec.security_context or {}
        
        # Host namespaces
        if pod.spec.host_network:
            self.findings.append(Finding(
                category="Host Network",
                title="Pod Uses Host Network",
                description=f"Pod '{pod_name}' uses host network namespace",
                severity=SeverityLevel.HIGH,
                affected_resources=[pod_name],
                recommendation="Avoid hostNetwork unless required. Use NetworkPolicies instead.",
                cis_reference=CIS_REFERENCES["host_network"],
                pod_security_standard="Baseline"
            ))
        
        if pod.spec.host_pid:
            self.findings.append(Finding(
                category="Host PID",
                title="Pod Uses Host PID Namespace",
                description=f"Pod '{pod_name}' uses host PID namespace",
                severity=SeverityLevel.HIGH,
                affected_resources=[pod_name],
                recommendation="Remove hostPID unless absolutely necessary",
                cis_reference="CIS 5.2.2",
                pod_security_standard="Baseline"
            ))
        
        if pod.spec.host_ipc:
            self.findings.append(Finding(
                category="Host IPC",
                title="Pod Uses Host IPC Namespace",
                description=f"Pod '{pod_name}' uses host IPC namespace",
                severity=SeverityLevel.MEDIUM,
                affected_resources=[pod_name],
                recommendation="Remove hostIPC unless absolutely necessary",
                cis_reference="CIS 5.2.3",
                pod_security_standard="Baseline"
            ))
        
        # HostPath volumes
        if pod.spec.volumes:
            for volume in pod.spec.volumes:
                if volume.host_path:
                    self.findings.append(Finding(
                        category="HostPath Volume",
                        title="Pod Uses HostPath Volume",
                        description=f"Pod '{pod_name}' mounts host path: {volume.host_path.path}",
                        severity=SeverityLevel.HIGH,
                        affected_resources=[pod_name],
                        recommendation="Avoid hostPath volumes. Use PersistentVolumes instead.",
                        cis_reference="CIS 5.2.4",
                        pod_security_standard="Baseline"
                    ))
    
    def _audit_rbac(self) -> None:
        """Audit RBAC configurations."""
        try:
            # Check ClusterRoles
            cluster_roles = self.rbac_v1.list_cluster_role(timeout_seconds=self.timeout)
            
            for role in cluster_roles.items:
                if not role.rules:
                    continue
                
                for rule in role.rules:
                    # Check for wildcard resources
                    if rule.resources and '*' in rule.resources:
                        self.findings.append(Finding(
                            category="RBAC Wildcard",
                            title="Wildcard Resources in ClusterRole",
                            description=f"ClusterRole '{role.metadata.name}' uses wildcard resources",
                            severity=SeverityLevel.HIGH,
                            affected_resources=[role.metadata.name],
                            recommendation="Specify exact resources instead of wildcards",
                            cis_reference=CIS_REFERENCES["rbac_wildcards"]
                        ))
                    
                    # Check for wildcard verbs
                    if rule.verbs and '*' in rule.verbs:
                        self.findings.append(Finding(
                            category="RBAC Wildcard",
                            title="Wildcard Verbs in ClusterRole",
                            description=f"ClusterRole '{role.metadata.name}' uses wildcard verbs",
                            severity=SeverityLevel.HIGH,
                            affected_resources=[role.metadata.name],
                            recommendation="Specify exact verbs instead of wildcards",
                            cis_reference=CIS_REFERENCES["rbac_wildcards"]
                        ))
        
        except ApiException as e:
            if e.status == 403:
                self.logger.warning("Insufficient permissions to audit RBAC")
            else:
                self.logger.error(f"Error auditing RBAC: {e}")
    
    def _audit_secrets(self) -> None:
        """Audit secrets management."""
        try:
            if self.namespace == "all":
                pods = self.core_v1.list_pod_for_all_namespaces(timeout_seconds=self.timeout)
            else:
                pods = self.core_v1.list_namespaced_pod(self.namespace, timeout_seconds=self.timeout)
            
            for pod in pods.items:
                pod_name = f"{pod.metadata.namespace}/{pod.metadata.name}"
                
                # Check for secrets in environment variables
                if pod.spec.containers:
                    for container in pod.spec.containers:
                        if container.env:
                            for env_var in container.env:
                                if env_var.value_from and env_var.value_from.secret_key_ref:
                                    self.findings.append(Finding(
                                        category="Secrets Management",
                                        title="Secret Mounted as Environment Variable",
                                        description=f"Pod '{pod_name}' mounts secret via env var",
                                        severity=SeverityLevel.MEDIUM,
                                        affected_resources=[pod_name],
                                        recommendation="Mount secrets as files instead of env vars",
                                        cis_reference=CIS_REFERENCES["secrets_env"]
                                    ))
        
        except ApiException as e:
            if e.status == 403:
                self.logger.warning("Insufficient permissions to audit secrets")
    
    def _audit_network_policies(self) -> None:
        """Audit network policies."""
        try:
            if self.namespace == "all":
                policies = self.networking_v1.list_network_policy_for_all_namespaces(
                    timeout_seconds=self.timeout
                )
                namespaces = self.core_v1.list_namespace(timeout_seconds=self.timeout)
                namespace_names = {ns.metadata.name for ns in namespaces.items}
            else:
                policies = self.networking_v1.list_namespaced_network_policy(
                    self.namespace, timeout_seconds=self.timeout
                )
                namespace_names = {self.namespace}
            
            # Check for namespaces without policies
            namespaces_with_policies = {p.metadata.namespace for p in policies.items}
            namespaces_without = namespace_names - namespaces_with_policies - {'kube-system', 'kube-public', 'kube-node-lease'}
            
            if namespaces_without:
                self.findings.append(Finding(
                    category="Network Policies",
                    title="Namespaces Without Network Policies",
                    description=f"{len(namespaces_without)} namespaces lack NetworkPolicies",
                    severity=SeverityLevel.HIGH,
                    affected_resources=list(namespaces_without)[:5],
                    recommendation="Implement default-deny NetworkPolicies for all namespaces",
                    cis_reference="CIS 5.3.2"
                ))
        
        except ApiException as e:
            if e.status == 403:
                self.logger.warning("Insufficient permissions to audit NetworkPolicies")
    
    def _audit_nodes(self) -> None:
        """Audit node configurations (aggressive mode)."""
        try:
            nodes = self.core_v1.list_node(timeout_seconds=self.timeout)
            
            for node in nodes.items:
                # Check node info for runtime
                runtime = node.status.node_info.container_runtime_version
                if 'docker' in runtime.lower():
                    self.findings.append(Finding(
                        category="Container Runtime",
                        title="Docker Runtime Detected",
                        description=f"Node '{node.metadata.name}' uses Docker runtime",
                        severity=SeverityLevel.INFO,
                        affected_resources=[node.metadata.name],
                        recommendation="Consider migrating to containerd or CRI-O"
                    ))
        
        except ApiException as e:
            if e.status == 403:
                self.logger.warning("Insufficient permissions to audit nodes")
    
    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate audit statistics."""
        return {
            "total_findings": len(self.findings),
            "by_severity": {
                "critical": sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == SeverityLevel.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == SeverityLevel.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == SeverityLevel.LOW),
                "info": sum(1 for f in self.findings if f.severity == SeverityLevel.INFO)
            },
            "by_category": {}
        }
    
    def _print_banner(self) -> None:
        """Print application banner."""
        if PYFIGLET_AVAILABLE:
            banner = pyfiglet.figlet_format("K8s Security Auditor", font="slant")
            self.console.print(f"[bold cyan]{banner}[/bold cyan]")
        else:
            self.console.print("\n[bold cyan]" + "=" * 70 + "[/bold cyan]")
            self.console.print("[bold cyan]    Kubernetes & Container Runtime Security Auditor v" + VERSION + "[/bold cyan]")
            self.console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]\n")
        
        self.console.print(f"[dim]Author: {AUTHOR}[/dim]\n")


# === Reporting ===
class Reporter:
    """Generate audit reports."""
    
    def __init__(self, console: Console):
        """Initialize reporter."""
        self.console = console
    
    def print_summary(self, result: AuditResult) -> None:
        """Print audit summary."""
        self.console.print("\n" + "=" * 80)
        self.console.print("[bold cyan]Security Audit Summary[/bold cyan]")
        self.console.print("=" * 80 + "\n")
        
        # Compliance score
        score = result.compliance_score
        score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        self.console.print(f"[bold {score_color}]Compliance Score: {score}/100[/bold {score_color}]\n")
        
        # Statistics
        stats = Table(show_header=False, box=None)
        stats.add_column("Metric", style="cyan")
        stats.add_column("Value", style="white")
        
        stats.add_row("Cluster", result.cluster_name)
        stats.add_row("Total Findings", str(len(result.findings)))
        
        self.console.print(stats)
        
        # Findings by severity
        if result.findings:
            self.console.print("\n[bold cyan]Findings by Severity[/bold cyan]\n")
            
            sev_table = Table(show_header=True, header_style="bold magenta")
            sev_table.add_column("Severity")
            sev_table.add_column("Count", justify="right")
            
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = result.statistics["by_severity"][sev]
                if count > 0:
                    color = self._get_severity_color(SeverityLevel(sev))
                    sev_table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))
            
            self.console.print(sev_table)
            
            # Detailed findings
            self.console.print("\n[bold cyan]Detailed Findings[/bold cyan]\n")
            for i, finding in enumerate(sorted(result.findings, 
                                              key=lambda x: self._severity_rank(x.severity)), 1):
                self._print_finding(finding, i)
        else:
            self.console.print("\n[bold green]✓ No security issues detected[/bold green]\n")
        
        self.console.print("\n" + "=" * 80 + "\n")
    
    def _print_finding(self, finding: Finding, index: int) -> None:
        """Print individual finding."""
        color = self._get_severity_color(finding.severity)
        
        content = f"""[bold]Category:[/bold] {finding.category}
[bold]Severity:[/bold] [{color}]{finding.severity.value.upper()}[/{color}]
[bold]Affected:[/bold] {', '.join(finding.affected_resources[:3])}

[bold]Description:[/bold]
{finding.description}

[bold]Recommendation:[/bold]
{finding.recommendation}
"""
        
        if finding.cis_reference:
            content += f"\n[bold]CIS Reference:[/bold] {finding.cis_reference}"
        
        panel = Panel(content, title=f"[bold]Finding #{index}: {finding.title}[/bold]", border_style=color)
        self.console.print(panel)
        self.console.print()
    
    def _get_severity_color(self, severity: SeverityLevel) -> str:
        """Get color for severity."""
        colors = {
            SeverityLevel.CRITICAL: "bold red",
            SeverityLevel.HIGH: "red",
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "blue",
            SeverityLevel.INFO: "cyan"
        }
        return colors.get(severity, "white")
    
    def _severity_rank(self, severity: SeverityLevel) -> int:
        """Get rank for sorting."""
        ranks = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        return ranks.get(severity, 5)


# === CLI ===
def print_examples() -> None:
    """Print usage examples."""
    console = Console()
    
    examples = """
[bold cyan]Usage Examples:[/bold cyan]

[bold yellow]1. Audit current cluster context:[/bold yellow]
   [green]python k8scontainerauditor.py[/green]

[bold yellow]2. Audit specific context:[/bold yellow]
   [green]python k8scontainerauditor.py --context prod-cluster[/green]

[bold yellow]3. Audit specific namespace:[/bold yellow]
   [green]python k8scontainerauditor.py --namespace my-app[/green]

[bold yellow]4. Audit all namespaces (aggressive):[/bold yellow]
   [green]python k8scontainerauditor.py --namespace all --aggressive[/green]

[bold yellow]5. Use custom kubeconfig:[/bold yellow]
   [green]python k8scontainerauditor.py --kubeconfig /path/to/config[/green]
"""
    
    console.print(examples)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Kubernetes & Container Runtime Security Auditor",
        epilog=f"Author: {AUTHOR} | Version: {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--kubeconfig', type=Path, help='Path to kubeconfig file')
    parser.add_argument('--context', help='Kubernetes context to use')
    parser.add_argument('--namespace', default='default', help='Namespace to audit (or "all")')
    parser.add_argument('--aggressive', action='store_true', help='Enable aggressive checks')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help='API timeout (seconds)')
    parser.add_argument('--examples', action='store_true', help='Show examples and exit')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--i-understand-legal-responsibilities', action='store_true', 
                       help='Acknowledge legal warning')
    
    args = parser.parse_args()
    
    console = Console()
    
    if args.examples:
        print_examples()
        return 0
    
    # Display warning
    console.print(LEGAL_WARNING, style="bold yellow")
    
    if not args.i_understand_legal_responsibilities:
        response = console.input(
            "\n[bold yellow]Do you have authorization to audit this cluster? (yes/no):[/bold yellow] "
        )
        if response.lower() not in ['yes', 'y']:
            console.print("[red]Audit cancelled.[/red]")
            return 1
    
    try:
        auditor = KubernetesSecurityAuditor(
            kubeconfig=args.kubeconfig,
            context=args.context,
            namespace=args.namespace,
            aggressive=args.aggressive,
            timeout=args.timeout
        )
        
        result = auditor.audit()
        
        reporter = Reporter(console)
        reporter.print_summary(result)
        
        return 0 if result.compliance_score >= 70 else 1
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logging.exception("Fatal error")
        return 1


if __name__ == '__main__':
    sys.exit(main())
