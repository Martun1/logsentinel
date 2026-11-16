-- title: SSH brute force
-- severity: HIGH
-- mitre: T1110.001 Brute Force: Password Guessing
-- description: A single IP produced 10 or more failed SSH logins.
SELECT src_ip                       AS source,
       COUNT(*)                     AS failures,
       COUNT(DISTINCT username)     AS users_tried,
       MIN(ts)                      AS first_seen,
       MAX(ts)                      AS last_seen
FROM auth_events
WHERE event IN ('FAILED', 'INVALID_USER')
GROUP BY src_ip
HAVING COUNT(*) >= 10
ORDER BY failures DESC;
