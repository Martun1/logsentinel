-- title: SQL injection attempts
-- severity: HIGH
-- mitre: T1190 Exploit Public-Facing Application
-- description: Request paths containing classic SQLi payloads.
SELECT src_ip AS source,
       COUNT(*) AS requests,
       SUM(CASE WHEN status = 200 THEN 1 ELSE 0 END) AS got_200,
       SUBSTR(MIN(path), 1, 70) AS example
FROM web_requests
WHERE LOWER(path) LIKE '%union%select%'
   OR LOWER(path) LIKE '%''%or%1=1%'
   OR LOWER(path) LIKE '%sleep(%'
   OR LOWER(path) LIKE '%information_schema%'
   OR LOWER(path) LIKE '%--%'
GROUP BY src_ip
ORDER BY requests DESC;
