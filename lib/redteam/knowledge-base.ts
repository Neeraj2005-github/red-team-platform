import type { KnowledgeBaseEntry, MitreTechnique, ScanResult, OSDetection } from "./types"

export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {
  T1595: { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance", description: "Adversaries may execute active reconnaissance scans to gather information." },
  T1190: { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", description: "Adversaries may exploit a weakness in an Internet-facing host." },
  T1210: { id: "T1210", name: "Exploitation of Remote Services", tactic: "Lateral Movement", description: "Adversaries may exploit remote services for unauthorized access." },
  T1068: { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation", description: "Adversaries may exploit software vulnerabilities to elevate privileges." },
  T1053: { id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence", description: "Adversaries may abuse task scheduling for recurring execution." },
  T1547: { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence", description: "Adversaries may configure system settings to auto-execute during boot." },
  T1021: { id: "T1021", name: "Remote Services", tactic: "Lateral Movement", description: "Adversaries may use valid accounts to log into remote services." },
  T1078: { id: "T1078", name: "Valid Accounts", tactic: "Credential Access", description: "Adversaries may obtain and abuse credentials of existing accounts." },
  T1059: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", description: "Adversaries may abuse command interpreters to execute commands." },
  T1133: { id: "T1133", name: "External Remote Services", tactic: "Initial Access", description: "Adversaries may leverage external-facing remote services for access." },
  T1505: { id: "T1505", name: "Server Software Component", tactic: "Persistence", description: "Adversaries may abuse server software to establish persistence." },
  T1046: { id: "T1046", name: "Network Service Discovery", tactic: "Discovery", description: "Adversaries may scan for services running on remote hosts." },
  T1110: { id: "T1110", name: "Brute Force", tactic: "Credential Access", description: "Adversaries may use brute force techniques to gain access." },
  T1003: { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", description: "Adversaries may dump credentials to obtain hashes or plaintext." },
  T1055: { id: "T1055", name: "Process Injection", tactic: "Defense Evasion", description: "Adversaries may inject code into processes to evade defenses." },
  T1071: { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", description: "Adversaries may communicate using application layer protocols." },
  T1562: { id: "T1562", name: "Impair Defenses", tactic: "Defense Evasion", description: "Adversaries may maliciously modify components to hinder defenses." },
  T1048: { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration", description: "Adversaries may steal data via a different protocol than the existing C2 channel." },
}

// --- MASSIVE SERVICE POOL ---
const ALL_SERVICES: { port: number; service: string; versions: string[]; protocol: string }[] = [
  { port: 21, service: "ftp", versions: ["vsftpd 2.3.4", "ProFTPD 1.3.5", "Pure-FTPd 1.0.49", "FileZilla 0.9.60"], protocol: "tcp" },
  { port: 22, service: "ssh", versions: ["OpenSSH 7.2p2", "OpenSSH 8.2p1", "OpenSSH 6.7p1", "OpenSSH 7.9p1", "Dropbear 2019.78"], protocol: "tcp" },
  { port: 23, service: "telnet", versions: ["Linux telnetd", "Cisco IOS telnetd", "BusyBox telnetd 1.22"], protocol: "tcp" },
  { port: 25, service: "smtp", versions: ["Postfix smtpd", "Exim 4.92", "Sendmail 8.15.2", "hMailServer 5.6.7"], protocol: "tcp" },
  { port: 53, service: "dns", versions: ["BIND 9.11.3", "BIND 9.16.1", "dnsmasq 2.79", "PowerDNS 4.3.0"], protocol: "udp" },
  { port: 80, service: "http", versions: ["Apache/2.4.49", "Apache/2.4.41", "nginx/1.18.0", "nginx/1.14.2", "IIS/10.0", "lighttpd/1.4.55"], protocol: "tcp" },
  { port: 110, service: "pop3", versions: ["Dovecot pop3d", "Courier pop3d", "popa3d"], protocol: "tcp" },
  { port: 111, service: "rpcbind", versions: ["rpcbind 2-4", "rpcbind 2"], protocol: "tcp" },
  { port: 135, service: "msrpc", versions: ["Microsoft Windows RPC"], protocol: "tcp" },
  { port: 139, service: "netbios-ssn", versions: ["Samba 4.5.16", "Samba 4.7.6", "Samba 3.6.25", "Windows Server 2016"], protocol: "tcp" },
  { port: 143, service: "imap", versions: ["Dovecot imapd 2.3.7", "Courier imapd"], protocol: "tcp" },
  { port: 443, service: "https", versions: ["Apache/2.4.49 (OpenSSL)", "nginx/1.18.0 (TLS)", "IIS/10.0 (TLS)"], protocol: "tcp" },
  { port: 445, service: "microsoft-ds", versions: ["Windows 7 SP1", "Windows 10 1903", "Windows Server 2019", "Samba 4.11"], protocol: "tcp" },
  { port: 512, service: "exec", versions: ["netkit-rsh rexecd"], protocol: "tcp" },
  { port: 513, service: "login", versions: ["OpenBSD or Solaris rlogind"], protocol: "tcp" },
  { port: 514, service: "shell", versions: ["Netkit rshd"], protocol: "tcp" },
  { port: 993, service: "imaps", versions: ["Dovecot imapd (TLS)"], protocol: "tcp" },
  { port: 995, service: "pop3s", versions: ["Dovecot pop3d (TLS)"], protocol: "tcp" },
  { port: 1099, service: "java-rmi", versions: ["Java RMI Registry"], protocol: "tcp" },
  { port: 1433, service: "ms-sql", versions: ["Microsoft SQL Server 2017", "MSSQL 2019", "MSSQL 2014"], protocol: "tcp" },
  { port: 1521, service: "oracle", versions: ["Oracle TNS Listener 12.2", "Oracle 19c"], protocol: "tcp" },
  { port: 2049, service: "nfs", versions: ["NFS 2-4", "NFS 3"], protocol: "tcp" },
  { port: 2121, service: "ftp", versions: ["ProFTPD 1.3.3c"], protocol: "tcp" },
  { port: 3306, service: "mysql", versions: ["MySQL 5.7.34", "MySQL 8.0.26", "MariaDB 10.5.12", "MariaDB 10.3.29"], protocol: "tcp" },
  { port: 3389, service: "ms-wbt-server", versions: ["Microsoft Terminal Services", "xrdp 0.9.12"], protocol: "tcp" },
  { port: 5432, service: "postgresql", versions: ["PostgreSQL 13.4", "PostgreSQL 12.8", "PostgreSQL 9.6.24"], protocol: "tcp" },
  { port: 5900, service: "vnc", versions: ["VNC (protocol 3.8)", "RealVNC 4.1", "TigerVNC 1.11"], protocol: "tcp" },
  { port: 5985, service: "wsman", versions: ["Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)"], protocol: "tcp" },
  { port: 6379, service: "redis", versions: ["Redis 6.2.5", "Redis 5.0.14", "Redis 4.0.14"], protocol: "tcp" },
  { port: 6667, service: "irc", versions: ["UnrealIRCd 3.2.8.1", "InspIRCd 3.0"], protocol: "tcp" },
  { port: 8080, service: "http-proxy", versions: ["Apache Tomcat/9.0", "Jetty 9.4.43", "Jenkins 2.303", "WildFly 24"], protocol: "tcp" },
  { port: 8443, service: "https-alt", versions: ["Apache Tomcat/9.0 (TLS)", "Jetty 9.4.43 (TLS)"], protocol: "tcp" },
  { port: 8888, service: "http", versions: ["Jupyter Notebook", "HFS 2.3m"], protocol: "tcp" },
  { port: 9090, service: "zeus-admin", versions: ["Prometheus", "Cockpit web service"], protocol: "tcp" },
  { port: 9200, service: "elasticsearch", versions: ["Elasticsearch 7.14", "Elasticsearch 6.8"], protocol: "tcp" },
  { port: 11211, service: "memcached", versions: ["Memcached 1.6.9", "Memcached 1.5.22"], protocol: "tcp" },
  { port: 27017, service: "mongodb", versions: ["MongoDB 4.4.8", "MongoDB 5.0.3", "MongoDB 3.6.23"], protocol: "tcp" },
]

// --- MASSIVE VULNERABILITY / EXPLOIT POOL ---
const ALL_KNOWLEDGE_BASE: KnowledgeBaseEntry[] = [
  // FTP
  { key: "21_ftp", technique: "T1190", exploit: "vsftpd_234_backdoor", severity: "critical", cvss: 9.8, description: "vsftpd 2.3.4 backdoor - attacker-inserted backdoor allows remote shell via port 6200.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Trigger backdoor in vsftpd 2.3.4." },
  { key: "21_ftp", technique: "T1110", exploit: "ftp_anonymous_access", severity: "high", cvss: 7.5, description: "FTP allows anonymous login with read/write access to sensitive directories.", mitreName: "Brute Force", mitreTactic: "Credential Access", mitreDescription: "Abuse anonymous FTP for data access." },
  { key: "21_ftp", technique: "T1078", exploit: "ftp_credential_bruteforce", severity: "medium", cvss: 5.9, description: "FTP service with weak credentials susceptible to dictionary attack.", mitreName: "Valid Accounts", mitreTactic: "Credential Access", mitreDescription: "Brute force FTP credentials." },
  // SSH
  { key: "22_ssh", technique: "T1078", exploit: "ssh_user_enumeration_cve2018_15473", severity: "medium", cvss: 5.3, description: "OpenSSH 7.2 user enumeration allows identifying valid usernames.", mitreName: "Valid Accounts", mitreTactic: "Credential Access", mitreDescription: "Enumerate SSH usernames." },
  { key: "22_ssh", technique: "T1110", exploit: "ssh_bruteforce_hydra", severity: "medium", cvss: 6.2, description: "SSH service vulnerable to brute force with common credential lists.", mitreName: "Brute Force", mitreTactic: "Credential Access", mitreDescription: "Brute force SSH login." },
  { key: "22_ssh", technique: "T1133", exploit: "ssh_authorized_keys_persistence", severity: "high", cvss: 7.8, description: "Writable .ssh/authorized_keys allows persistent backdoor access.", mitreName: "External Remote Services", mitreTactic: "Initial Access", mitreDescription: "Plant SSH key for persistence." },
  // Telnet
  { key: "23_telnet", technique: "T1078", exploit: "telnet_default_credentials", severity: "critical", cvss: 9.1, description: "Telnet with factory default credentials (admin/admin, root/root).", mitreName: "Valid Accounts", mitreTactic: "Credential Access", mitreDescription: "Login via default telnet creds." },
  // SMTP
  { key: "25_smtp", technique: "T1190", exploit: "exim_rce_cve2019_10149", severity: "critical", cvss: 9.8, description: "Exim 4.87-4.91 remote command execution via crafted recipient address.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "RCE via Exim mail server." },
  { key: "25_smtp", technique: "T1048", exploit: "smtp_open_relay", severity: "medium", cvss: 5.0, description: "Open SMTP relay allows data exfiltration via email.", mitreName: "Exfiltration Over Alternative Protocol", mitreTactic: "Exfiltration", mitreDescription: "Exfiltrate data via open mail relay." },
  // DNS
  { key: "53_dns", technique: "T1190", exploit: "bind_tsig_rce_cve2017_3143", severity: "high", cvss: 7.5, description: "BIND 9 TSIG authentication bypass allows unauthorized zone transfers.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Bypass BIND TSIG authentication." },
  // HTTP
  { key: "80_http", technique: "T1190", exploit: "apache_path_traversal_cve2021_41773", severity: "high", cvss: 7.5, description: "Apache 2.4.49 path traversal for arbitrary file read and potential RCE.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Path traversal in Apache for file access." },
  { key: "80_http", technique: "T1190", exploit: "nginx_off_by_slash_misconfiguration", severity: "medium", cvss: 5.3, description: "Nginx alias traversal misconfiguration leaks files outside web root.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Nginx alias misconfiguration." },
  { key: "80_http", technique: "T1059", exploit: "shellshock_cve2014_6271", severity: "critical", cvss: 9.8, description: "Bash Shellshock vulnerability via CGI allows remote command execution.", mitreName: "Command and Scripting Interpreter", mitreTactic: "Execution", mitreDescription: "RCE via Shellshock in CGI scripts." },
  { key: "80_http", technique: "T1505", exploit: "webshell_upload_unrestricted", severity: "critical", cvss: 9.1, description: "Unrestricted file upload allows web shell deployment for persistent access.", mitreName: "Server Software Component", mitreTactic: "Persistence", mitreDescription: "Upload web shell for persistent access." },
  // SMB/NetBIOS
  { key: "139_netbios-ssn", technique: "T1210", exploit: "samba_rce_cve2017_7494", severity: "critical", cvss: 9.8, description: "Samba remote code execution via malicious shared library upload.", mitreName: "Exploitation of Remote Services", mitreTactic: "Initial Access", mitreDescription: "Upload malicious library to Samba share." },
  { key: "445_microsoft-ds", technique: "T1210", exploit: "ms17_010_eternalblue", severity: "critical", cvss: 9.8, description: "SMBv1 EternalBlue vulnerability allows remote code execution.", mitreName: "Exploitation of Remote Services", mitreTactic: "Initial Access", mitreDescription: "Exploit SMBv1 for RCE." },
  { key: "445_microsoft-ds", technique: "T1210", exploit: "ms08_067_netapi", severity: "critical", cvss: 9.3, description: "Windows Server Service vulnerability allows remote code execution.", mitreName: "Exploitation of Remote Services", mitreTactic: "Initial Access", mitreDescription: "Exploit NetAPI for RCE." },
  { key: "445_microsoft-ds", technique: "T1021", exploit: "smb_relay_ntlm", severity: "high", cvss: 8.1, description: "NTLM relay attack to gain authenticated access to SMB shares.", mitreName: "Remote Services", mitreTactic: "Lateral Movement", mitreDescription: "Relay NTLM authentication." },
  // MSRPC
  { key: "135_msrpc", technique: "T1210", exploit: "dcom_rce_cve2003_0352", severity: "high", cvss: 7.5, description: "DCOM RPC buffer overflow allows remote code execution.", mitreName: "Exploitation of Remote Services", mitreTactic: "Initial Access", mitreDescription: "Buffer overflow in DCOM RPC." },
  // MySQL
  { key: "3306_mysql", technique: "T1190", exploit: "mysql_auth_bypass_cve2012_2122", severity: "high", cvss: 8.1, description: "MySQL authentication bypass allows unauthorized database access.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Bypass MySQL authentication." },
  { key: "3306_mysql", technique: "T1059", exploit: "mysql_udf_command_execution", severity: "critical", cvss: 9.0, description: "MySQL UDF injection for OS command execution with database privileges.", mitreName: "Command and Scripting Interpreter", mitreTactic: "Execution", mitreDescription: "Execute OS commands via MySQL UDF." },
  // PostgreSQL
  { key: "5432_postgresql", technique: "T1190", exploit: "postgresql_copy_rce", severity: "high", cvss: 8.8, description: "PostgreSQL COPY FROM PROGRAM allows command execution.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "RCE via PostgreSQL COPY command." },
  // MSSQL
  { key: "1433_ms-sql", technique: "T1059", exploit: "mssql_xp_cmdshell", severity: "critical", cvss: 9.0, description: "MSSQL xp_cmdshell allows arbitrary OS command execution.", mitreName: "Command and Scripting Interpreter", mitreTactic: "Execution", mitreDescription: "Execute OS commands via xp_cmdshell." },
  { key: "1433_ms-sql", technique: "T1078", exploit: "mssql_sa_bruteforce", severity: "high", cvss: 7.5, description: "MSSQL SA account with weak or default password.", mitreName: "Valid Accounts", mitreTactic: "Credential Access", mitreDescription: "Brute force MSSQL SA account." },
  // Oracle
  { key: "1521_oracle", technique: "T1190", exploit: "oracle_tns_poison_cve2012_1675", severity: "high", cvss: 7.5, description: "Oracle TNS Listener poisoning allows MitM attacks.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "TNS Listener poisoning attack." },
  // RDP
  { key: "3389_ms-wbt-server", technique: "T1210", exploit: "bluekeep_cve2019_0708", severity: "critical", cvss: 9.8, description: "BlueKeep RDP vulnerability allows remote code execution without authentication.", mitreName: "Exploitation of Remote Services", mitreTactic: "Initial Access", mitreDescription: "RCE via BlueKeep on RDP." },
  { key: "3389_ms-wbt-server", technique: "T1110", exploit: "rdp_credential_bruteforce", severity: "medium", cvss: 6.5, description: "RDP brute force with common enterprise credentials.", mitreName: "Brute Force", mitreTactic: "Credential Access", mitreDescription: "Brute force RDP login." },
  // VNC
  { key: "5900_vnc", technique: "T1021", exploit: "vnc_auth_bypass_cve2006_2369", severity: "high", cvss: 7.5, description: "RealVNC authentication bypass allows unauthenticated remote desktop access.", mitreName: "Remote Services", mitreTactic: "Lateral Movement", mitreDescription: "Bypass VNC authentication." },
  { key: "5900_vnc", technique: "T1110", exploit: "vnc_bruteforce", severity: "medium", cvss: 5.9, description: "VNC password brute force attack.", mitreName: "Brute Force", mitreTactic: "Credential Access", mitreDescription: "Brute force VNC password." },
  // Redis
  { key: "6379_redis", technique: "T1190", exploit: "redis_unauthenticated_rce", severity: "critical", cvss: 9.8, description: "Redis without authentication allows writing SSH keys and crontabs for RCE.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Unauthenticated Redis for RCE." },
  { key: "6379_redis", technique: "T1003", exploit: "redis_config_dump_credentials", severity: "high", cvss: 7.5, description: "Redis CONFIG GET allows dumping passwords and sensitive configuration.", mitreName: "OS Credential Dumping", mitreTactic: "Credential Access", mitreDescription: "Dump credentials from Redis config." },
  // IRC
  { key: "6667_irc", technique: "T1190", exploit: "unrealircd_backdoor_cve2010_2075", severity: "critical", cvss: 9.8, description: "UnrealIRCd 3.2.8.1 contains a backdoor allowing remote code execution.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Trigger UnrealIRCd backdoor." },
  // Tomcat / 8080
  { key: "8080_http-proxy", technique: "T1190", exploit: "tomcat_ghostcat_cve2020_1938", severity: "critical", cvss: 9.8, description: "Apache Tomcat GhostCat AJP connector file read/inclusion.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Exploit AJP connector for file inclusion." },
  { key: "8080_http-proxy", technique: "T1078", exploit: "tomcat_manager_default_creds", severity: "high", cvss: 8.5, description: "Tomcat Manager with default credentials (tomcat/tomcat) allows WAR deployment.", mitreName: "Valid Accounts", mitreTactic: "Credential Access", mitreDescription: "Login to Tomcat Manager with defaults." },
  { key: "8080_http-proxy", technique: "T1190", exploit: "jenkins_script_console_rce", severity: "critical", cvss: 9.8, description: "Jenkins Script Console allows Groovy script execution for RCE.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "RCE via Jenkins Groovy console." },
  // Elasticsearch
  { key: "9200_elasticsearch", technique: "T1190", exploit: "elasticsearch_rce_cve2015_1427", severity: "critical", cvss: 9.8, description: "Elasticsearch Groovy scripting engine allows remote code execution.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "RCE via Elasticsearch scripting." },
  { key: "9200_elasticsearch", technique: "T1003", exploit: "elasticsearch_indices_dump", severity: "high", cvss: 7.5, description: "Unauthenticated Elasticsearch allows dumping all indices and data.", mitreName: "OS Credential Dumping", mitreTactic: "Credential Access", mitreDescription: "Dump sensitive data from Elasticsearch." },
  // MongoDB
  { key: "27017_mongodb", technique: "T1190", exploit: "mongodb_unauthenticated_access", severity: "critical", cvss: 9.1, description: "MongoDB without authentication allows full database access.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Unauthenticated MongoDB access." },
  { key: "27017_mongodb", technique: "T1003", exploit: "mongodb_credential_dump", severity: "high", cvss: 7.5, description: "Dump user credentials from MongoDB admin database.", mitreName: "OS Credential Dumping", mitreTactic: "Credential Access", mitreDescription: "Dump MongoDB credentials." },
  // Memcached
  { key: "11211_memcached", technique: "T1190", exploit: "memcached_data_exfiltration", severity: "high", cvss: 7.5, description: "Unauthenticated Memcached allows reading cached sensitive data.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Read cached data from Memcached." },
  // NFS
  { key: "2049_nfs", technique: "T1021", exploit: "nfs_no_root_squash_exploit", severity: "high", cvss: 8.1, description: "NFS export with no_root_squash allows SUID binary creation for root.", mitreName: "Remote Services", mitreTactic: "Lateral Movement", mitreDescription: "Exploit NFS no_root_squash." },
  // Java RMI
  { key: "1099_java-rmi", technique: "T1190", exploit: "java_rmi_deserialization_rce", severity: "critical", cvss: 9.8, description: "Java RMI deserialization vulnerability allows remote code execution.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "RCE via Java RMI deserialization." },
  // WinRM
  { key: "5985_wsman", technique: "T1021", exploit: "winrm_credential_reuse", severity: "high", cvss: 8.1, description: "WinRM with reused/stolen credentials allows remote PowerShell execution.", mitreName: "Remote Services", mitreTactic: "Lateral Movement", mitreDescription: "Execute PowerShell via WinRM." },
  // HTTPS
  { key: "443_https", technique: "T1190", exploit: "heartbleed_cve2014_0160", severity: "high", cvss: 7.5, description: "OpenSSL Heartbleed allows leaking memory contents including private keys.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Leak memory via Heartbleed." },
  { key: "443_https", technique: "T1190", exploit: "ssl_poodle_cve2014_3566", severity: "medium", cvss: 5.9, description: "SSLv3 POODLE vulnerability allows decrypting secure connections.", mitreName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", mitreDescription: "Downgrade attack via POODLE." },
  // rpcbind
  { key: "111_rpcbind", technique: "T1046", exploit: "rpcbind_service_enumeration", severity: "low", cvss: 3.5, description: "rpcbind exposes registered RPC services for enumeration.", mitreName: "Network Service Discovery", mitreTactic: "Discovery", mitreDescription: "Enumerate RPC services." },
  // r-services
  { key: "512_exec", technique: "T1021", exploit: "rexec_trust_exploitation", severity: "high", cvss: 8.1, description: "Remote exec allows command execution with .rhosts trust.", mitreName: "Remote Services", mitreTactic: "Lateral Movement", mitreDescription: "Exploit rexec trust relationships." },
  { key: "513_login", technique: "T1078", exploit: "rlogin_rhosts_bypass", severity: "high", cvss: 8.1, description: "rlogin with .rhosts trust allows passwordless remote login.", mitreName: "Valid Accounts", mitreTactic: "Credential Access", mitreDescription: "Bypass auth via .rhosts trust." },
]

// --- MASSIVE OS PROFILES ---
const OS_PROFILES: OSDetection[] = [
  { name: "Ubuntu 18.04 LTS (Bionic)", family: "Linux", accuracy: 96 },
  { name: "Ubuntu 20.04 LTS (Focal)", family: "Linux", accuracy: 94 },
  { name: "Ubuntu 22.04 LTS (Jammy)", family: "Linux", accuracy: 95 },
  { name: "Debian 10 (Buster)", family: "Linux", accuracy: 93 },
  { name: "Debian 11 (Bullseye)", family: "Linux", accuracy: 94 },
  { name: "CentOS 7.9", family: "Linux", accuracy: 92 },
  { name: "CentOS Stream 8", family: "Linux", accuracy: 91 },
  { name: "Red Hat Enterprise Linux 8.5", family: "Linux", accuracy: 90 },
  { name: "Fedora 35", family: "Linux", accuracy: 89 },
  { name: "Arch Linux (rolling)", family: "Linux", accuracy: 85 },
  { name: "Kali Linux 2022.1", family: "Linux", accuracy: 92 },
  { name: "Alpine Linux 3.15", family: "Linux", accuracy: 88 },
  { name: "Windows 7 SP1", family: "Windows", accuracy: 97 },
  { name: "Windows 10 Pro 21H2", family: "Windows", accuracy: 96 },
  { name: "Windows 10 Enterprise 20H2", family: "Windows", accuracy: 95 },
  { name: "Windows Server 2012 R2", family: "Windows", accuracy: 94 },
  { name: "Windows Server 2016", family: "Windows", accuracy: 93 },
  { name: "Windows Server 2019", family: "Windows", accuracy: 95 },
  { name: "Windows Server 2022", family: "Windows", accuracy: 91 },
  { name: "FreeBSD 13.0", family: "BSD", accuracy: 87 },
  { name: "OpenBSD 7.0", family: "BSD", accuracy: 86 },
]

// --- SEEDED RANDOM GENERATOR (IP-based) ---
function ipSeed(ip: string): number {
  const cleaned = ip.replace(/\/\d+$/, "")
  let hash = 0
  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned.charCodeAt(i)
    hash = ((hash << 5) - hash) + ch
    hash |= 0
  }
  return Math.abs(hash)
}

class SeededRandom {
  private seed: number
  constructor(seed: number) {
    this.seed = seed
  }
  next(): number {
    this.seed = (this.seed * 1664525 + 1013904223) & 0x7fffffff
    return this.seed / 0x7fffffff
  }
  pick<T>(arr: T[]): T {
    return arr[Math.floor(this.next() * arr.length)]
  }
  shuffle<T>(arr: T[]): T[] {
    const copy = [...arr]
    for (let i = copy.length - 1; i > 0; i--) {
      const j = Math.floor(this.next() * (i + 1));
      [copy[i], copy[j]] = [copy[j], copy[i]]
    }
    return copy
  }
  chance(probability: number): boolean {
    return this.next() < probability
  }
}

// --- PUBLIC: Generate dynamic, IP-specific scan results ---
export function generateScanResults(target: string): ScanResult[] {
  const rng = new SeededRandom(ipSeed(target))
  const shuffled = rng.shuffle(ALL_SERVICES)
  const portCount = 3 + Math.floor(rng.next() * 6) // 3-8 ports
  const selected = shuffled.slice(0, portCount)

  return selected.map((svc) => ({
    port: svc.port,
    service: svc.service,
    version: rng.pick(svc.versions),
    state: rng.chance(0.9) ? ("open" as const) : ("filtered" as const),
    protocol: svc.protocol,
  })).sort((a, b) => a.port - b.port)
}

// --- PUBLIC: Generate dynamic, IP-specific OS detection ---
export function generateOSDetection(target: string): OSDetection {
  const rng = new SeededRandom(ipSeed(target) + 7)
  return rng.pick(OS_PROFILES)
}

// --- PUBLIC: Match vulnerabilities to discovered services ---
export function matchVulnerabilities(ports: ScanResult[]): KnowledgeBaseEntry[] {
  const matched: KnowledgeBaseEntry[] = []
  for (const port of ports) {
    if (port.state !== "open") continue
    const key = `${port.port}_${port.service}`
    const entries = ALL_KNOWLEDGE_BASE.filter((e) => e.key === key)
    // Not all vulns always present -- random subset
    entries.forEach((entry) => {
      if (Math.random() < 0.7) {
        matched.push(entry)
      }
    })
  }
  return matched
}

// Re-export MITRE_TECHNIQUES for backward compat
export { ALL_KNOWLEDGE_BASE as KNOWLEDGE_BASE }
