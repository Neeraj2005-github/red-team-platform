import type { KnowledgeBaseEntry, MitreTechnique } from "./types"

export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {
  T1595: {
    id: "T1595",
    name: "Active Scanning",
    tactic: "Reconnaissance",
    description:
      "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
  },
  T1190: {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    description:
      "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
  },
  T1210: {
    id: "T1210",
    name: "Exploitation of Remote Services",
    tactic: "Lateral Movement",
    description:
      "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.",
  },
  T1068: {
    id: "T1068",
    name: "Exploitation for Privilege Escalation",
    tactic: "Privilege Escalation",
    description:
      "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
  },
  T1053: {
    id: "T1053",
    name: "Scheduled Task/Job",
    tactic: "Persistence",
    description:
      "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
  },
  T1547: {
    id: "T1547",
    name: "Boot or Logon Autostart Execution",
    tactic: "Persistence",
    description:
      "Adversaries may configure system settings to automatically execute a program during system boot or logon.",
  },
  T1021: {
    id: "T1021",
    name: "Remote Services",
    tactic: "Lateral Movement",
    description:
      "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections.",
  },
  T1078: {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Credential Access",
    description:
      "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining access.",
  },
  T1059: {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "Execution",
    description:
      "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
  },
}

export const KNOWLEDGE_BASE: KnowledgeBaseEntry[] = [
  {
    key: "445_windows7",
    technique: "T1210",
    exploit: "ms17_010_eternalblue",
    severity: "critical",
    cvss: 9.8,
    description:
      "SMBv1 vulnerability allowing remote code execution on Windows 7 systems via EternalBlue exploit.",
    mitreName: "Exploitation of Remote Services",
    mitreTactic: "Initial Access",
    mitreDescription:
      "Exploit SMBv1 vulnerability for remote code execution.",
  },
  {
    key: "80_apache_2.4.49",
    technique: "T1190",
    exploit: "apache_path_traversal_cve2021_41773",
    severity: "high",
    cvss: 7.5,
    description:
      "Apache HTTP Server 2.4.49 path traversal vulnerability allowing arbitrary file read and potential RCE.",
    mitreName: "Exploit Public-Facing Application",
    mitreTactic: "Initial Access",
    mitreDescription:
      "Path traversal in Apache allows unauthorized file access.",
  },
  {
    key: "22_openssh_7.2",
    technique: "T1078",
    exploit: "ssh_user_enumeration_cve2018_15473",
    severity: "medium",
    cvss: 5.3,
    description:
      "OpenSSH 7.2 user enumeration vulnerability allows attackers to identify valid usernames.",
    mitreName: "Valid Accounts",
    mitreTactic: "Credential Access",
    mitreDescription: "Enumerate valid SSH usernames for credential attacks.",
  },
  {
    key: "3306_mysql_5.7",
    technique: "T1190",
    exploit: "mysql_auth_bypass",
    severity: "high",
    cvss: 8.1,
    description:
      "MySQL 5.7 authentication bypass vulnerability allowing unauthorized database access.",
    mitreName: "Exploit Public-Facing Application",
    mitreTactic: "Initial Access",
    mitreDescription:
      "Bypass MySQL authentication to gain database access.",
  },
  {
    key: "8080_tomcat_9.0",
    technique: "T1190",
    exploit: "tomcat_ghostcat_cve2020_1938",
    severity: "critical",
    cvss: 9.8,
    description:
      "Apache Tomcat GhostCat vulnerability allows reading/writing files via AJP connector.",
    mitreName: "Exploit Public-Facing Application",
    mitreTactic: "Initial Access",
    mitreDescription:
      "Exploit AJP connector for file inclusion attacks.",
  },
  {
    key: "139_samba_4.5",
    technique: "T1210",
    exploit: "samba_rce_cve2017_7494",
    severity: "critical",
    cvss: 9.8,
    description:
      "Samba remote code execution via malicious shared library upload.",
    mitreName: "Exploitation of Remote Services",
    mitreTactic: "Initial Access",
    mitreDescription:
      "Upload malicious library to Samba share for RCE.",
  },
]

export const SERVICE_SCAN_RESULTS = [
  { port: 22, service: "ssh", version: "OpenSSH 7.2p2", state: "open" as const, protocol: "tcp" },
  { port: 80, service: "http", version: "Apache/2.4.49", state: "open" as const, protocol: "tcp" },
  { port: 139, service: "netbios-ssn", version: "Samba 4.5.16", state: "open" as const, protocol: "tcp" },
  { port: 445, service: "microsoft-ds", version: "Windows 7 SP1", state: "open" as const, protocol: "tcp" },
  { port: 3306, service: "mysql", version: "MySQL 5.7.34", state: "open" as const, protocol: "tcp" },
  { port: 8080, service: "http-proxy", version: "Apache Tomcat/9.0", state: "open" as const, protocol: "tcp" },
]

export const OS_DETECTION = {
  name: "Windows 7 SP1 / Linux 4.15",
  family: "Mixed (Dual-boot / VM)",
  accuracy: 94,
}
