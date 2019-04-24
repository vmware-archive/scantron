SELECT substr(h.name, 1, instr(h.name, '/') - 1) AS host, pr.name AS process, po.number AS port
FROM hosts h
  JOIN processes pr ON pr.host_id = h.id
  JOIN ports po ON po.process_id = pr.id
WHERE po.state = "LISTEN" -- just listening ports
  AND po.address != "127.0.0.1" -- ignore processes just listening on localhost
  AND po.address NOT LIKE "169.254%" -- ignore processes listening on link-local addresses
  AND po.protocol = "tcp" -- only consider tcp connections (we don't do TLS over UDP)
  AND po.id NOT IN (SELECT port_id FROM tls_informations) -- find ports which don't have associated TLS information
  AND NOT (pr.name = "sshd" AND po.number = 22) -- ignore SSH
  AND NOT (pr.name = "rpcbind" AND po.number = 111) -- ignore NFS
  AND NOT (pr.name = "ssh-proxy" AND po.number = 2222) -- ignore SSH
ORDER BY h.name, pr.name
