-- title: Password spraying
-- severity: HIGH
-- mitre: T1110.003 Brute Force: Password Spraying
-- description: One IP tried 5 or more different usernames with only a few attempts per user.
SELECT src_ip                                   AS source,
       COUNT(DISTINCT username)                 AS distinct_users,
       ROUND(COUNT(*) * 1.0 / COUNT(DISTINCT username), 1) AS attempts_per_user,
       GROUP_CONCAT(DISTINCT username)          AS usernames
FROM auth_events
WHERE event IN ('FAILED', 'INVALID_USER')
GROUP BY src_ip
HAVING COUNT(DISTINCT username) >= 5
   AND COUNT(*) * 1.0 / COUNT(DISTINCT username) <= 5;
