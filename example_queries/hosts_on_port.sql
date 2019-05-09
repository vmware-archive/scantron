SELECT hosts.NAME
FROM ports
  JOIN processes
    ON ports.process_id = processes.id
  JOIN hosts
    ON processes.host_id = hosts.id
WHERE ports.number = 6061
  AND upper(ports.state) = "LISTEN"