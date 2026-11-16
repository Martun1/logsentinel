-- title: Known scanner / attack tool user-agents
-- severity: MEDIUM
-- mitre: T1595.002 Active Scanning: Vulnerability Scanning
-- description: User-Agent strings of common offensive tools.
SELECT src_ip AS source,
       CASE WHEN LOWER(user_agent) LIKE '%sqlmap%'  THEN 'sqlmap'
            WHEN LOWER(user_agent) LIKE '%nikto%'   THEN 'Nikto'
            WHEN LOWER(user_agent) LIKE '%gobuster%' THEN 'Gobuster'
            WHEN LOWER(user_agent) LIKE '%nmap%'    THEN 'Nmap NSE'
            WHEN LOWER(user_agent) LIKE '%wpscan%'  THEN 'WPScan'
            WHEN LOWER(user_agent) LIKE '%hydra%'   THEN 'Hydra'
            ELSE 'other' END AS tool,
       COUNT(*) AS requests
FROM web_requests
WHERE LOWER(user_agent) GLOB '*sqlmap*' OR LOWER(user_agent) GLOB '*nikto*'
   OR LOWER(user_agent) GLOB '*gobuster*' OR LOWER(user_agent) GLOB '*nmap*'
   OR LOWER(user_agent) GLOB '*wpscan*' OR LOWER(user_agent) GLOB '*hydra*'
GROUP BY source, tool
ORDER BY requests DESC;
