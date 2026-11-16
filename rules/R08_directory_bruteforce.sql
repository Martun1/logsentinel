-- title: Directory brute forcing (404 flood)
-- severity: LOW
-- mitre: T1083 File and Directory Discovery
-- description: 30+ requests returning 404 from one IP.
SELECT src_ip AS source,
       COUNT(*) AS not_found,
       COUNT(DISTINCT path) AS unique_paths,
       MIN(ts) AS first_seen,
       MAX(ts) AS last_seen
FROM web_requests
WHERE status = 404
GROUP BY src_ip
HAVING COUNT(*) >= 30
ORDER BY not_found DESC;
