# LogAnalysis
# Parse security log to write firewall rules to block server attacks

Example to use in production:

1) clone in your server;

2) customize variable deny_command and apply_command
to adapt to your firewall...

3) Comment / uncomment line for begin testing or production
pl = LogAnalysis(False, True, True)
pl = LogAnalysis(True, True, False)

4) enable to execute
chmod +x LogAnalysis.pl

5) begin parsing log :)
tail -f /var/log/secure | ./LogAnalysis.py

