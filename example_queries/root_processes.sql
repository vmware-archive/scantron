.width 20 80
.mode csv

SELECT DISTINCT substr(h.name, 1, instr(h.name, '/') - 1) AS host, pr.cmdline AS cmd
FROM hosts h
  JOIN processes pr ON pr.host_id = h.id
WHERE pr.user = "root"
  -- kernel services
  AND pr.cmdline != ""
  -- iaas services (gcp)
  AND pr.cmdline NOT LIKE "%google_network_daemon%"
  AND pr.cmdline NOT LIKE "%google_accounts_daemon%"
  AND pr.cmdline NOT LIKE "%google_clock_skew_daemon%"
  -- iaas services (vsphere)
  AND pr.cmdline NOT LIKE "%vmtoolsd%"
  AND pr.cmdline NOT LIKE "%VGAuthService%"
  -- scanner tool
  AND pr.cmdline NOT LIKE "%proc_scan%"
  -- os services
  AND pr.cmdline NOT LIKE "%/sbin/init%"
  AND pr.cmdline NOT LIKE "%systemd-journald%"
  AND pr.cmdline NOT LIKE "%systemd-logind%"
  AND pr.cmdline NOT LIKE "%systemd-udevd%"
  AND pr.cmdline NOT LIKE "%svlogd%"
  AND pr.cmdline NOT LIKE "%sshd%"
  AND pr.cmdline NOT LIKE "%audispd%"
  AND pr.cmdline NOT LIKE "%auditd%"
  AND pr.cmdline NOT LIKE "%agetty%"
  AND pr.cmdline NOT LIKE "%systemd/systemd%"
  AND pr.cmdline NOT LIKE "%cron%"
  AND pr.cmdline NOT LIKE "%dhclient%"
  -- bosh services
  AND pr.cmdline NOT LIKE "%runsv agent%"
  AND pr.cmdline NOT LIKE "%runsv monit%"
  AND pr.cmdline NOT LIKE "%monit%"
  AND pr.cmdline NOT LIKE "%runsvdir%"
  AND pr.cmdline NOT LIKE "%bosh-agent%"
  AND pr.cmdline NOT LIKE "%bosh-dns-nameserverconfig%"
  -- addon services
  AND pr.cmdline NOT LIKE "%clamd%"
  AND pr.cmdline NOT LIKE "%ipsec/starter%"
  AND pr.cmdline NOT LIKE "%filesnitch%"
ORDER BY h.name, pr.name
