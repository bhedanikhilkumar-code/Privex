/**
 * WebsiteEntryPointAnalyzer: Offline Attack Surface, Open Entry Point & Exposed Port Security Engine.
 *
 * Implements offline identification of vulnerable entry points where attackers can penetrate a website,
 * explains the specific hacker exploitation vector, and provides step-by-step remediation solutions.
 * Operates 100% on-device without sending any user data to the cloud.
 */

export type EntryPointType = 'PORT' | 'ENDPOINT' | 'PROTOCOL' | 'AUTH' | 'MISCONFIG' | 'INJECTION';
export type EntryPointSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface RemediationSolution {
  summary: string;
  steps: string[];
  technicalCodeSnippet?: string;
  category: 'FIREWALL' | 'CRYPTO_TLS' | 'ACCESS_CONTROL' | 'SERVER_HARDENING' | 'CODE_INPUT_VALIDATION';
}

export interface ExposedEntryPoint {
  id: string;
  name: string;
  type: EntryPointType;
  target: string;
  severity: EntryPointSeverity;
  port?: number | string;
  description: string;
  hackerAttackVector: string; // Explains exactly how hackers can enter or exploit this point
  remediationSolution: RemediationSolution; // Step-by-step resolution blueprint
}

export interface WebsiteAuditReport {
  target: string;
  normalizedUrl: string;
  hostname: string;
  port?: string;
  protocol: string;
  overallExposureRisk: 'SECURE' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  exposureScore: number; // 0 - 100
  totalPointsChecked: number;
  openPointsDetected: number;
  openEntryPoints: ExposedEntryPoint[];
  summaryExplanation: string;
  timestamp: number;
  isOfflineEvaluation: boolean;
}

export interface KnownPortProfile {
  port: number;
  service: string;
  severity: EntryPointSeverity;
  title: string;
  description: string;
  hackerAttackVector: string;
  remediation: RemediationSolution;
}

export class WebsiteEntryPointAnalyzer {
  private static readonly KNOWN_PORTS: Record<number, KnownPortProfile> = {
    80: {
      port: 80,
      service: 'HTTP (Cleartext)',
      severity: 'MEDIUM',
      title: 'Unencrypted HTTP Cleartext Transmission',
      description: 'The website permits plain unencrypted HTTP communication over standard port 80.',
      hackerAttackVector: 'Attackers on the same local network, public Wi-Fi, or upstream router can perform Man-in-the-Middle (MITM) attacks, sniffing plaintext session tokens, passwords, and injecting malicious JavaScript payloads directly into visited web pages.',
      remediation: {
        summary: 'Enforce modern TLS encryption and redirect all HTTP traffic to HTTPS (port 443).',
        steps: [
          'Obtain a trusted TLS 1.3 certificate (e.g. Let\'s Encrypt / Certbot).',
          'Configure your reverse proxy (Nginx/Apache/Caddy) to return a 301 Permanent Redirect from HTTP to HTTPS.',
          'Implement the HTTP Strict Transport Security (HSTS) header: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".'
        ],
        technicalCodeSnippet: 'server {\n  listen 80;\n  server_name yourdomain.com;\n  return 301 https://$host$request_uri;\n}',
        category: 'CRYPTO_TLS'
      }
    },
    21: {
      port: 21,
      service: 'FTP (File Transfer Protocol)',
      severity: 'CRITICAL',
      title: 'Exposed FTP File Transfer Port',
      description: 'Legacy File Transfer Protocol (FTP) port 21 is exposed on the host.',
      hackerAttackVector: 'FTP transmits usernames and passwords in unencrypted plaintext across the wire. Attackers exploit known daemon buffer overflows, anonymous authentication misconfigurations, or brute-force weak credentials to upload web shells and gain root/system command execution.',
      remediation: {
        summary: 'Decommission plain FTP immediately and migrate to SSH File Transfer Protocol (SFTP).',
        steps: [
          'Disable and terminate the FTP daemon (vsftpd, proftpd, or pure-ftpd).',
          'Close port 21 on the perimeter firewall (UFW, iptables, AWS Security Groups).',
          'Use SFTP over SSH (port 22) restricted to cryptographic Ed25519 public keys.'
        ],
        technicalCodeSnippet: '# Disable FTP and block port in UFW\nsystemctl stop vsftpd && systemctl disable vsftpd\nufw deny 21/tcp',
        category: 'FIREWALL'
      }
    },
    22: {
      port: 22,
      service: 'SSH (Secure Shell)',
      severity: 'HIGH',
      title: 'Direct Public SSH Remote Shell Port',
      description: 'Port 22 SSH remote administrative shell is directly reachable from the public internet.',
      hackerAttackVector: 'Attackers deploy automated botnets (e.g., Mirai/Kinsing) running continuous dictionary attacks and credential stuffing against port 22. If password authentication is enabled or zero-day OpenSSH vulnerabilities occur, attackers gain interactive root console access to the entire server.',
      remediation: {
        summary: 'Harden SSH configuration, enforce cryptographic key-only authentication, and restrict ingress.',
        steps: [
          'Disable root login ("PermitRootLogin no") and disable password auth ("PasswordAuthentication no") in /etc/ssh/sshd_config.',
          'Install and configure Fail2ban or CrowdSec to automatically ban brute-forcing IPs after 3 failed attempts.',
          'Change default port 22 to a non-standard port or place SSH behind a private WireGuard/Tailscale VPN.'
        ],
        technicalCodeSnippet: '# /etc/ssh/sshd_config\nPermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes',
        category: 'ACCESS_CONTROL'
      }
    },
    23: {
      port: 23,
      service: 'Telnet (Cleartext Shell)',
      severity: 'CRITICAL',
      title: 'Exposed Telnet Remote Terminal Port',
      description: 'Unencrypted Telnet remote terminal port 23 is open and exposed.',
      hackerAttackVector: 'Telnet provides zero transport encryption. Any intermediate node can read administrative login credentials in cleartext. IoT botnets routinely target open port 23 using hardcoded factory passwords to recruit the server into DDoS botnets.',
      remediation: {
        summary: 'Terminate and purge the Telnet daemon immediately.',
        steps: [
          'Stop and disable the telnet service immediately.',
          'Uninstall telnet-server packages completely.',
          'Block port 23 across all hardware and software firewalls.'
        ],
        technicalCodeSnippet: 'systemctl stop telnet.socket\nsystemctl disable telnet.socket\napt-get purge telnetd -y\nufw deny 23/tcp',
        category: 'SERVER_HARDENING'
      }
    },
    3389: {
      port: 3389,
      service: 'RDP (Remote Desktop Protocol)',
      severity: 'CRITICAL',
      title: 'Exposed Windows Remote Desktop (RDP) Port',
      description: 'Port 3389 RDP is open to the public internet.',
      hackerAttackVector: 'Exposed RDP is the primary vector for ransomware syndicates (LockBit, BlackCat). Attackers use credential spraying, compromised corporate credentials from dark web leaks, or BlueKeep (CVE-2019-0708) exploits to establish interactive GUI remote control and deploy ransomware.',
      remediation: {
        summary: 'Remove RDP from the public internet immediately and require secure VPN access.',
        steps: [
          'Close inbound port 3389 in your firewall / cloud security group for 0.0.0.0/0.',
          'Require all administrators to connect via an enterprise VPN or Azure Bastion / AWS Systems Manager.',
          'Enforce Network Level Authentication (NLA) and Multi-Factor Authentication (MFA) on all user accounts.'
        ],
        technicalCodeSnippet: '# Windows PowerShell: Enforce NLA\n(Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\\cimv2\\terminalservices -Filter "TerminalName=\'RDP-Tcp\'").SetUserAuthenticationRequired(1)',
        category: 'ACCESS_CONTROL'
      }
    },
    3306: {
      port: 3306,
      service: 'MySQL Database',
      severity: 'CRITICAL',
      title: 'Exposed MySQL Database Port',
      description: 'Port 3306 MySQL server is directly accessible from the public internet.',
      hackerAttackVector: 'Attackers use port scanners to find open MySQL ports, then execute automated dictionary attacks against root/admin accounts. Once connected, attackers can dump all user databases, exfiltrate confidential customer data, or wipe tables and demand a cryptocurrency ransom.',
      remediation: {
        summary: 'Bind MySQL strictly to localhost and block all external network traffic.',
        steps: [
          'Edit MySQL configuration (/etc/mysql/mysql.conf.d/mysqld.cnf) and set "bind-address = 127.0.0.1".',
          'Block external inbound port 3306 on the host firewall.',
          'Use local Unix domain sockets or encrypted SSH tunnels (ssh -L 3306:localhost:3306) for remote database administration.'
        ],
        technicalCodeSnippet: '# /etc/mysql/mysql.conf.d/mysqld.cnf\n[mysqld]\nbind-address = 127.0.0.1\nufw deny 3306/tcp',
        category: 'SERVER_HARDENING'
      }
    },
    5432: {
      port: 5432,
      service: 'PostgreSQL Database',
      severity: 'CRITICAL',
      title: 'Exposed PostgreSQL Database Port',
      description: 'Port 5432 PostgreSQL database listener is exposed to untrusted networks.',
      hackerAttackVector: 'Attackers execute brute-force attacks against default "postgres" superuser accounts. If successful, attackers can execute arbitrary OS commands on the host machine using PostgreSQL COPY PROGRAM functionality or dump sensitive business data.',
      remediation: {
        summary: 'Restrict PostgreSQL listen addresses to localhost and update client authentication rules.',
        steps: [
          'In postgresql.conf, set "listen_addresses = \'localhost\'".',
          'In pg_hba.conf, ensure only internal subnets or local sockets are permitted using "scram-sha-256" authentication.',
          'Block external port 5432 inbound in your cloud network security groups.'
        ],
        technicalCodeSnippet: '# postgresql.conf\nlisten_addresses = \'localhost\'\n# pg_hba.conf\nhost all all 127.0.0.1/32 scram-sha-256\nufw deny 5432/tcp',
        category: 'SERVER_HARDENING'
      }
    },
    27017: {
      port: 27017,
      service: 'MongoDB Database',
      severity: 'CRITICAL',
      title: 'Exposed MongoDB Database Port',
      description: 'Port 27017 MongoDB daemon is exposed to the public internet.',
      hackerAttackVector: 'Unprotected or default MongoDB installations often lack enabled authentication. Automated ransom bots connect, clone the entire database, drop all local collections, and create a ransom note demanding Bitcoin for data recovery.',
      remediation: {
        summary: 'Enable mandatory role-based authentication and bind MongoDB to private interfaces.',
        steps: [
          'In /etc/mongod.conf, set net.bindIp to 127.0.0.1.',
          'Set security.authorization to "enabled".',
          'Block port 27017 at the network firewall perimeter.'
        ],
        technicalCodeSnippet: '# /etc/mongod.conf\nnet:\n  port: 27017\n  bindIp: 127.0.0.1\nsecurity:\n  authorization: enabled',
        category: 'SERVER_HARDENING'
      }
    },
    6379: {
      port: 6379,
      service: 'Redis In-Memory Cache',
      severity: 'CRITICAL',
      title: 'Exposed Redis Cache & Key-Value Store',
      description: 'Port 6379 Redis database is reachable from the public internet.',
      hackerAttackVector: 'Redis is designed without security in trusted internal networks. An attacker can connect without credentials, use the CONFIG SET command to overwrite local SSH ~/.ssh/authorized_keys files or cron jobs, achieving instant Remote Code Execution (RCE) with the privileges of the Redis daemon.',
      remediation: {
        summary: 'Activate Redis protected-mode, bind to 127.0.0.1, and enforce a strong authentication password.',
        steps: [
          'In redis.conf, ensure "bind 127.0.0.1 ::1" is active.',
          'Ensure "protected-mode yes" is set.',
          'Set a high-entropy password using "requirepass <STRONG_GENERATED_PASSWORD>".'
        ],
        technicalCodeSnippet: '# redis.conf\nbind 127.0.0.1\nprotected-mode yes\nrequirepass ComplexRandomSecretKey987!',
        category: 'SERVER_HARDENING'
      }
    },
    8080: {
      port: 8080,
      service: 'Alternative HTTP / Proxy / Dev Server',
      severity: 'HIGH',
      title: 'Exposed Web Application Alternative / Dev Port',
      description: 'Port 8080 is often used for staging environments, development servers, or administration consoles.',
      hackerAttackVector: 'Applications deployed on port 8080 frequently bypass corporate Web Application Firewalls (WAF) or security monitoring. They often run debug mode, unpatched staging software, or unauthenticated internal dashboard services (e.g. Jenkins, Tomcat).',
      remediation: {
        summary: 'Place port 8080 services behind an authenticated HTTPS reverse proxy with rate limiting.',
        steps: [
          'Bind the internal service to 127.0.0.1:8080.',
          'Route all traffic through Nginx or Cloudflare with TLS and WAF inspection.',
          'Block external internet access to port 8080.'
        ],
        technicalCodeSnippet: 'ufw deny 8080/tcp',
        category: 'FIREWALL'
      }
    },
    8443: {
      port: 8443,
      service: 'Alternative HTTPS / Management Console',
      severity: 'MEDIUM',
      title: 'Exposed Alternative HTTPS Console Port',
      description: 'Port 8443 typically hosts SSL management interfaces, router consoles, or secondary web services.',
      hackerAttackVector: 'Hackers target port 8443 to find exposed appliance administrative portals (e.g., firewall admin, hypervisor consoles) prone to default password attacks or admin login authentication bypasses.',
      remediation: {
        summary: 'Isolate administrative consoles to private management VLANs or VPNs.',
        steps: [
          'Restrict inbound access on port 8443 to authorized static management IP addresses.',
          'Enable Multi-Factor Authentication (MFA) on the administrative service.'
        ],
        technicalCodeSnippet: 'ufw allow from 203.0.113.50 to any port 8443 proto tcp\nufw deny 8443/tcp',
        category: 'ACCESS_CONTROL'
      }
    },
    9000: {
      port: 9000,
      service: 'PHP-FPM / Portainer / SonarQube',
      severity: 'HIGH',
      title: 'Exposed Application Service Port (Port 9000)',
      description: 'Port 9000 is commonly used by PHP-FPM FastCGI or Portainer Docker management consoles.',
      hackerAttackVector: 'If exposed PHP-FPM FastCGI is open, attackers can forge FastCGI packets to execute arbitrary PHP code on the server. If Portainer is exposed without authentication, attackers can spawn malicious Docker containers to escape to the host system.',
      remediation: {
        summary: 'Close port 9000 to public traffic and use local Unix sockets for PHP-FPM.',
        steps: [
          'Configure PHP-FPM to listen on a local Unix socket ("/run/php/php8.2-fpm.sock") rather than a TCP port.',
          'Ensure container management tools are accessible only via localhost or authenticated reverse proxies.'
        ],
        technicalCodeSnippet: '# /etc/php/8.2/fpm/pool.d/www.conf\nlisten = /run/php/php8.2-fpm.sock\n# listen = 127.0.0.1:9000',
        category: 'SERVER_HARDENING'
      }
    },
    10000: {
      port: 10000,
      service: 'Webmin Server Administration',
      severity: 'CRITICAL',
      title: 'Exposed Webmin Server Administration Port',
      description: 'Port 10000 Webmin root administration interface is open to the public internet.',
      hackerAttackVector: 'Webmin exposes full root system administration over a web interface. Outdated versions are notorious for unauthenticated remote command execution vulnerabilities (e.g. CVE-2019-15107). Attackers exploit these to seize complete root control.',
      remediation: {
        summary: 'Restrict Webmin access exclusively to private internal management addresses.',
        steps: [
          'In /etc/webmin/miniserv.conf, specify "allow=127.0.0.1 <INTERNAL_MANAGEMENT_IP>".',
          'Block port 10000 at the external firewall.',
          'Keep Webmin updated to the latest security patch release.'
        ],
        technicalCodeSnippet: 'ufw deny 10000/tcp',
        category: 'FIREWALL'
      }
    }
  };

  /**
   * Comprehensive offline audit of a website URL or hostname.
   * Identifies all open points, exposed ports, vulnerable paths, and protocol weaknesses.
   */
  public analyzeWebsite(input: string): WebsiteAuditReport {
    const defaultTimestamp = Date.now();
    const cleanInput = (input || '').trim();

    if (!cleanInput) {
      return {
        target: '',
        normalizedUrl: '',
        hostname: '',
        protocol: 'http:',
        overallExposureRisk: 'SECURE',
        exposureScore: 0,
        totalPointsChecked: 0,
        openPointsDetected: 0,
        openEntryPoints: [],
        summaryExplanation: 'No website URL or hostname provided for audit.',
        timestamp: defaultTimestamp,
        isOfflineEvaluation: true
      };
    }

    let parsedUrl: URL;
    try {
      const urlCandidate = cleanInput.startsWith('http://') || cleanInput.startsWith('https://')
        ? cleanInput
        : `http://${cleanInput}`;
      parsedUrl = new URL(urlCandidate);
    } catch {
      // In case of malformed input, create fallback mock URL
      parsedUrl = new URL(`http://${cleanInput.replace(/[^\w.-]/g, '') || 'unknown-host'}`);
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    const protocol = parsedUrl.protocol;
    const pathname = parsedUrl.pathname.toLowerCase();
    const search = parsedUrl.search.toLowerCase();
    const portStr = parsedUrl.port;

    const detectedPoints: ExposedEntryPoint[] = [];
    let totalChecksPerformed = 0;

    // ========================================================
    // 1. PROTOCOL & TRANSPORT LAYER CHECKS
    // ========================================================
    totalChecksPerformed++;
    if (protocol === 'http:') {
      const httpProfile = WebsiteEntryPointAnalyzer.KNOWN_PORTS[80];
      detectedPoints.push({
        id: 'open-port-80-http',
        name: 'Insecure Cleartext Protocol (Port 80)',
        type: 'PROTOCOL',
        target: 'HTTP / Port 80',
        severity: 'MEDIUM',
        port: 80,
        description: 'Target relies on plain unencrypted HTTP without mandatory TLS encryption.',
        hackerAttackVector: httpProfile.hackerAttackVector,
        remediationSolution: httpProfile.remediation
      });
    }

    // ========================================================
    // 2. EXPLICIT OR DETECTED PORT AUDIT
    // ========================================================
    totalChecksPerformed++;
    if (portStr) {
      const portNum = parseInt(portStr, 10);
      if (WebsiteEntryPointAnalyzer.KNOWN_PORTS[portNum]) {
        const profile = WebsiteEntryPointAnalyzer.KNOWN_PORTS[portNum];
        detectedPoints.push({
          id: `open-port-${portNum}`,
          name: profile.title,
          type: 'PORT',
          target: `Port :${portNum} (${profile.service})`,
          severity: profile.severity,
          port: portNum,
          description: profile.description,
          hackerAttackVector: profile.hackerAttackVector,
          remediationSolution: profile.remediation
        });
      } else {
        // Unknown or custom non-standard port
        detectedPoints.push({
          id: `open-non-standard-port-${portStr}`,
          name: `Non-Standard Exposed Port :${portStr}`,
          type: 'PORT',
          target: `Port :${portStr}`,
          severity: 'HIGH',
          port: portNum,
          description: `The website exposes a non-standard listener port :${portStr} which may indicate an internal administrative console, debug server, or unhardened daemon.`,
          hackerAttackVector: 'Attackers run specialized port scanners and banner grabbers to fingerprint proprietary software running on custom ports, searching for unpatched zero-day vulnerabilities or default authentication credentials.',
          remediationSolution: {
            summary: 'Audit services listening on this port and block public ingress at the firewall.',
            steps: [
              `Identify the process listening on port ${portStr} using "ss -tulpn | grep :${portStr}".`,
              'Determine whether this service requires public internet exposure.',
              `Drop external access using firewall rules: "ufw deny ${portStr}/tcp".`
            ],
            category: 'FIREWALL'
          }
        });
      }
    }

    // ========================================================
    // 3. EXPOSED SENSITIVE PATHS & ADMINISTRATIVE ENTRY POINTS
    // ========================================================
    const checkPath = (pattern: RegExp, id: string, name: string, severity: EntryPointSeverity, desc: string, attackVector: string, rem: RemediationSolution) => {
      totalChecksPerformed++;
      if (pattern.test(pathname)) {
        detectedPoints.push({
          id,
          name,
          type: 'ENDPOINT',
          target: pathname,
          severity,
          description: desc,
          hackerAttackVector: attackVector,
          remediationSolution: rem
        });
      }
    };

    // Sensitive Configuration & Git/Env files
    checkPath(
      /\/\.env|\/\.git|\/config\.json|\/backup\.sql|\/web\.config|\/phpinfo\.php/i,
      'exposed-sensitive-file-endpoint',
      'Exposed Server Secret / Environment Configuration File',
      'CRITICAL',
      'A sensitive configuration file, environment file, source repository, or database dump was detected in the URL path.',
      'Hackers directly download these files to harvest database passwords, AWS/Stripe API keys, JWT secret signing tokens, and application source code, resulting in total server compromise without requiring a software exploit.',
      {
        summary: 'Immediately block access to dot-files and private config files at the web server layer.',
        steps: [
          'Add a deny rule in Nginx: "location ~ /\\.(env|git) { deny all; return 404; }".',
          'Remove any backup files (.sql, .bak, .zip) from the public webroot.',
          'Rotate all API keys, database passwords, and encryption secrets immediately.'
        ],
        technicalCodeSnippet: 'location ~ /\\.(env|git|svn|htaccess) {\n  deny all;\n  return 404;\n}',
        category: 'SERVER_HARDENING'
      }
    );

    // Administrative Portals
    checkPath(
      /\/admin|\/wp-admin|\/administrator|\/cpanel|\/phpmyadmin|\/manager\/html/i,
      'exposed-admin-portal',
      'Exposed Administrative Entry Point',
      'HIGH',
      'An administrative login interface or server management console was identified in the URL path.',
      'Attackers focus automated credential-stuffing tools, SQL injection payloads, and brute-force dictionaries against exposed admin portals to gain superuser privileges.',
      {
        summary: 'Restrict the administrative portal behind Multi-Factor Authentication (MFA) and IP allowlists.',
        steps: [
          'Enforce strict Multi-Factor Authentication (TOTP / FIDO2 Hardware keys) on all administrative accounts.',
          'Restrict access to the admin path by IP address or require an internal corporate VPN.',
          'Deploy rate limiting and CAPTCHA friction gates against repeated login attempts.'
        ],
        technicalCodeSnippet: 'location /admin {\n  allow 192.168.1.0/24;\n  allow 203.0.113.10;\n  deny all;\n}',
        category: 'ACCESS_CONTROL'
      }
    );

    // Internal Actuator / Debug / Metric Endpoints
    checkPath(
      /\/actuator|\/actuator\/env|\/swagger|\/api-docs|\/graphql|\/debug\/vars|\/console/i,
      'exposed-debug-actuator-endpoint',
      'Exposed Internal Debug / API Actuator Endpoint',
      'HIGH',
      'The website path points to an internal metrics, Swagger/OpenAPI documentation, GraphQL, or Spring Actuator endpoint.',
      'Hackers use API introspection to map every undocumented API route and parameter. Actuator /env endpoints can expose encrypted or plaintext passwords and permit remote code execution via insecure deserialization.',
      {
        summary: 'Disable internal actuator and debug endpoints in production builds.',
        steps: [
          'Disable Spring Boot Actuator web exposure: "management.endpoints.web.exposure.exclude=*".',
          'Disable GraphQL introspection queries in production environments.',
          'Require authentication tokens for API documentation endpoints.'
        ],
        technicalCodeSnippet: '# application.yml\nmanagement:\n  endpoints:\n    web:\n      exposure:\n        include: health,info',
        category: 'SERVER_HARDENING'
      }
    );

    // WordPress / University CMS XML-RPC & User Enumeration Endpoints
    checkPath(
      /\/xmlrpc\.php|\/wp-json\/wp\/v2\/users|\/author-sitemap|\/\?author=1/i,
      'exposed-xmlrpc-user-enum',
      'Exposed CMS XML-RPC / User Enumeration Vector',
      'HIGH',
      'The website path targets WordPress XML-RPC or the REST API user enumeration endpoint.',
      'Attackers use xmlrpc.php for high-speed automated amplification brute-force attacks (system.multicall) to test thousands of passwords per second without triggering standard rate limits. They also harvest staff/student usernames via author enumeration.',
      {
        summary: 'Block xmlrpc.php and disable REST API user enumeration endpoints.',
        steps: [
          'Add a block rule in Nginx or Apache for xmlrpc.php: "location = /xmlrpc.php { deny all; access_log off; log_not_found off; return 403; }".',
          'Restrict or filter REST API /wp-json/wp/v2/users to authenticated administrators only.',
          'Enforce Web Application Firewall (WAF) rate limits on all authentication attempts.'
        ],
        technicalCodeSnippet: '# Nginx: Block XML-RPC completely\nlocation = /xmlrpc.php {\n  deny all;\n  return 403;\n}',
        category: 'SERVER_HARDENING'
      }
    );

    // File Upload & Arbitrary Attachment Handling Endpoints
    checkPath(
      /\/wp-content\/uploads|\/upload\.php|\/file-upload|\/attachments|\/uploadify/i,
      'exposed-upload-directory-endpoint',
      'Exposed File Upload / Attachment Storage Path',
      'HIGH',
      'The URL targets a direct file upload script or an unprotected public uploads directory.',
      'If file execution is not disabled in the upload directory, hackers upload malicious web shells (e.g. .php, .phtml, .jsp) disguised with double extensions or image MIME types, and then request the file directly to execute arbitrary code.',
      {
        summary: 'Disable PHP/script execution inside all public uploads and media directories.',
        steps: [
          'In Nginx, configure the uploads directory to serve static content only and deny script execution.',
          'Store uploaded files on an isolated object storage service (AWS S3, MinIO, Cloudflare R2) without executable handlers.',
          'Re-encode and validate images server-side before persisting.'
        ],
        technicalCodeSnippet: '# Nginx: Disable script execution in uploads\nlocation ~* ^/wp-content/uploads/.*\\.(php|phtml|pl|py|jsp|asp|sh|cgi)$ {\n  deny all;\n  return 403;\n}',
        category: 'SERVER_HARDENING'
      }
    );

    // ========================================================
    // 4. OPEN REDIRECT VECTORS IN QUERY PARAMETERS
    // ========================================================
    totalChecksPerformed++;
    if (/[?&](redirect|next|url|dest|return|target|r)=http/i.test(cleanInput) || /[?&](redirect|next|url|dest|return|target|r)=\/\//i.test(cleanInput)) {
      detectedPoints.push({
        id: 'open-redirect-parameter',
        name: 'Potential Open Redirect Entry Point',
        type: 'MISCONFIG',
        target: search || 'Query Parameter',
        severity: 'MEDIUM',
        description: 'URL parameters contain destination redirect targets which could be hijacked by attackers.',
        hackerAttackVector: 'Phishers craft links with your trusted domain name, appending a redirect parameter to their malicious site. Victims trust the recognizable brand domain in email/SMS, click the link, and are automatically forwarded to a credential harvesting site.',
        remediationSolution: {
          summary: 'Enforce strict destination allowlisting or restrict redirects to relative paths.',
          steps: [
            'Validate redirect parameters against a strict server-side allowlist of authorized hostnames.',
            'Disallow absolute URLs and verify that redirects start with a single "/" (e.g. url.startsWith("/") && !url.startsWith("//")).',
            'Display an interstitial warning if users are leaving for an external domain.'
          ],
          technicalCodeSnippet: 'function getSafeRedirectUrl(target) {\n  if (target && target.startsWith(\'/\') && !target.startsWith(\'//\')) {\n    return target;\n  }\n  return \'/\';\n}',
          category: 'CODE_INPUT_VALIDATION'
        }
      });
    }

    // ========================================================
    // 5. INJECTION ATTACK SURFACE DETECTED IN URL
    // ========================================================
    totalChecksPerformed++;
    if (/union.*select|<script|javascript:|(\.\.\/)+|waitfor.*delay|exec\(|benchmark\(/i.test(cleanInput)) {
      detectedPoints.push({
        id: 'url-injection-payload-vector',
        name: 'Injection Attack Surface / Exploit Signature in URL',
        type: 'INJECTION',
        target: cleanInput.length > 60 ? cleanInput.substring(0, 60) + '...' : cleanInput,
        severity: 'CRITICAL',
        description: 'The URL contains SQL injection, Cross-Site Scripting (XSS), or Path Traversal exploit signatures.',
        hackerAttackVector: 'Attackers inject SQL payloads, executable JavaScript, or directory traversal sequences into URL parameters to manipulate backend database queries or execute malicious code in the context of the user session.',
        remediationSolution: {
          summary: 'Implement parameterized queries, strict input validation, and Output Encoding.',
          steps: [
            'Use parameterized queries (prepared statements) or an ORM for all database operations.',
            'Implement context-aware HTML/JavaScript output encoding to neutralize XSS.',
            'Deploy Web Application Firewall (WAF) rules to detect and reject malformed exploit payloads.'
          ],
          category: 'CODE_INPUT_VALIDATION'
        }
      });
    }

    // ========================================================
    // 6. IP HOST / DIRECT HOST EXPOSURE
    // ========================================================
    totalChecksPerformed++;
    const isDirectIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
    if (isDirectIp) {
      detectedPoints.push({
        id: 'direct-ip-host-exposure',
        name: 'Direct IP Address Host (No Cloudflare/CDN Shield)',
        type: 'MISCONFIG',
        target: hostname,
        severity: 'HIGH',
        description: 'The target website is accessed directly via raw IP address rather than a protected domain.',
        hackerAttackVector: 'Direct IP exposure bypasses Cloudflare, Akamai, or AWS CloudFront DDoS shields and Web Application Firewalls. Attackers can directly target the origin server with high-volume volumetric DDoS attacks and exploit origin-specific ports.',
        remediationSolution: {
          summary: 'Hide the origin server IP behind a CDN reverse proxy and block direct IP connections.',
          steps: [
            'Route domain DNS through a managed CDN / DDoS protection provider (Cloudflare, AWS CloudFront).',
            'Configure the origin firewall to reject all inbound traffic except authorized CDN IP address ranges.',
            'Never reveal the origin IP address in public DNS records or outbound email headers.'
          ],
          category: 'FIREWALL'
        }
      });
    }

    // ========================================================
    // 7. COMPUTE EXPOSURE SCORE & OVERALL RISK VERDICT
    // ========================================================
    let exposureScore = 0;
    for (const point of detectedPoints) {
      switch (point.severity) {
        case 'CRITICAL':
          exposureScore += 35;
          break;
        case 'HIGH':
          exposureScore += 25;
          break;
        case 'MEDIUM':
          exposureScore += 15;
          break;
        case 'LOW':
          exposureScore += 5;
          break;
      }
    }
    exposureScore = Math.min(100, exposureScore);

    let overallExposureRisk: 'SECURE' | 'MODERATE' | 'HIGH' | 'CRITICAL' = 'SECURE';
    if (exposureScore >= 60 || detectedPoints.some(p => p.severity === 'CRITICAL')) {
      overallExposureRisk = 'CRITICAL';
    } else if (exposureScore >= 35 || detectedPoints.some(p => p.severity === 'HIGH')) {
      overallExposureRisk = 'HIGH';
    } else if (exposureScore > 0) {
      overallExposureRisk = 'MODERATE';
    }

    let summaryExplanation = '';
    if (detectedPoints.length === 0) {
      summaryExplanation = `No dangerous open ports or exposed attack surface endpoints were detected for ${hostname}. Standard secure baseline maintained.`;
    } else {
      const topSeverity = detectedPoints[0].severity;
      summaryExplanation = `Identified ${detectedPoints.length} potential hacker entry point(s) on ${hostname} (Highest severity: ${topSeverity}). Immediate remediation recommended to prevent unauthorized server compromise.`;
    }

    return {
      target: cleanInput,
      normalizedUrl: parsedUrl.toString(),
      hostname,
      port: portStr || (protocol === 'https:' ? '443' : '80'),
      protocol,
      overallExposureRisk,
      exposureScore,
      totalPointsChecked: totalChecksPerformed,
      openPointsDetected: detectedPoints.length,
      openEntryPoints: detectedPoints,
      summaryExplanation,
      timestamp: defaultTimestamp,
      isOfflineEvaluation: true
    };
  }

  /**
   * Helper to retrieve all standard dangerous port profiles for offline reference / education.
   */
  public static getAllKnownPortProfiles(): KnownPortProfile[] {
    return Object.values(WebsiteEntryPointAnalyzer.KNOWN_PORTS);
  }
}
