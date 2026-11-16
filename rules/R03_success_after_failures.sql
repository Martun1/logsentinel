-- title: Successful login after brute force (possible compromise)
-- severity: CRITICAL
-- mitre: T1078 Valid Accounts
-- description: An IP with 5+ failures later logged in successfully.
WITH fails AS (
    SELECT src_ip, COUNT(*) AS n, MAX(ts) AS last_fail
    FROM auth_events
    WHERE event IN ('FAILED', 'INVALID_USER')
    GROUP BY src_ip
    HAVING COUNT(*) >= 5
)
SELECT a.src_ip    AS source,
       a.username  AS account,
       f.n         AS prior_failures,
       a.ts        AS success_time,
       a.method    AS auth_method
FROM auth_events a
JOIN fails f ON f.src_ip = a.src_ip
WHERE a.event = 'ACCEPTED'
  AND a.ts > (SELECT MIN(ts) FROM auth_events x WHERE x.src_ip = a.src_ip AND x.event IN ('FAILED','INVALID_USER'))
ORDER BY a.ts;
