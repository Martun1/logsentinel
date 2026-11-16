-- title: Path traversal / XSS / LFI probes
-- severity: MEDIUM
-- mitre: T1190 Exploit Public-Facing Application
-- description: Requests trying to escape the web root or inject script tags.
SELECT src_ip AS source,
       CASE WHEN path LIKE '%../%' OR LOWER(path) LIKE '%etc/passwd%' THEN 'traversal/LFI'
            ELSE 'XSS' END AS technique,
       COUNT(*) AS requests,
       SUBSTR(MIN(path), 1, 70) AS example
FROM web_requests
WHERE path LIKE '%../%' OR LOWER(path) LIKE '%etc/passwd%'
   OR LOWER(path) LIKE '%<script%' OR LOWER(path) LIKE '%3cscript%'
GROUP BY src_ip, technique;
