-- title: Direct root login over SSH
-- severity: MEDIUM
-- mitre: T1078.003 Valid Accounts: Local Accounts
-- description: Successful SSH authentication as root (PermitRootLogin should be 'no').
SELECT src_ip AS source, ts AS time, method AS auth_method
FROM auth_events
WHERE event = 'ACCEPTED' AND username = 'root';
