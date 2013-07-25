Fat-Finger
==========

Extends the original finger.nse and attempts to enumerate current logged on
users through a full match of the username and a partial match of the GECOS
field in /etc/passwd

Example output:

```
@output
PORT   STATE SERVICE
79/tcp open  finger
| fat-finger: finger: admin: no such user.
| finger: unix: no such user.
| finger: dba: no such user.
| finger: oracle: no such user.
| finger: sybase: no such user.
| finger: ingres: no such user.
| finger: db: no such user.
| finger: help: no such user.
| finger: IT: no such user.
| finger: test: no such user.
| Login: root                                   Name: root
| Directory: /root                      Shell: /bin/bash
| Last login Thu Nov 26 16:05 2009 (GMT) on pts/1 from 192.168.226.1
| No mail.
| No Plan.
|
| Login: mysql                                  Name: MySQL Server
| Directory: /var/lib/mysql             Shell: /bin/false
| Never logged in.
| No mail.
| No Plan.
|
| Login: ftp                                    Name: ftp daemon
| Directory: /srv/ftp                   Shell: /bin/false
| Never logged in.
| No mail.
| No Plan.
|
| Login: hplip                                  Name: HPLIP system user
| Directory: /var/run/hplip             Shell: /bin/false
| Never logged in.
| No mail.
| No Plan.
|
| Login: gnats                                  Name: Gnats Bug-Reporting System (admin)
| Directory: /var/lib/gnats             Shell: /bin/sh
| Never logged in.
| No mail.
|_No Plan.


portrule = shortport.port_or_service(79, "finger")

action = function(host, port)
	local try = nmap.new_try()

	return try(comm.exchange(host, port, "root admin system unix dba oracle mysql sybase ingres db ftp help IT user test\r\n",
        	{lines=100, proto=port.protocol, timeout=5000}))
end
```
