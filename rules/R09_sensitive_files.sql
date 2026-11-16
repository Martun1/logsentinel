-- title: Sensitive file exposure (successful)
-- severity: CRITICAL
-- mitre: T1552.001 Unsecured Credentials: Credentials In Files
-- description: Sensitive files (.env, .git, backups) served with HTTP 200.
SELECT src_ip AS source, path, status, bytes, ts AS time
FROM web_requests
WHERE status = 200
  AND (path LIKE '%/.env%' OR path LIKE '%/.git/%' OR path LIKE '%.sql' OR path LIKE '%.bak'
       OR path LIKE '%wp-config.php~%' OR path LIKE '%/backup%.zip');
