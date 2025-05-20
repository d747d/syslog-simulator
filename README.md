# Send UDP syslog messages to localhost:514 at 100 messages per second
$ sysloggen -p udp -d 127.0.0.1:514 -r 100

# Send TCP syslog messages with TLS 1.2 from 5 simulated hosts at 50 messages per second
$ sysloggen -p tcp -d syslog.example.com:6514 -h 5 -r 50 -t v1_2

# Send 1KB-sized messages at 10 per second using facility=local0 (16) and severity=warning (4)
$ sysloggen -p udp -d 192.168.1.100:514 -s 1024 -r 10 -f 16 -v 4
