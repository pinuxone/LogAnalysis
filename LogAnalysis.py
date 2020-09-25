#!/bin/python3

__author__ = "Giuseppe Latini"
__copyright__ = "Copyright 2020"
__credits__ = "Giuseppe Latini"
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Giuseppe Latini"
__email__ = "giuseppe.latini@gmail.com"
__status__ = "Testing"

from datetime import datetime
import re
import subprocess
import shlex
import sys
import threading


class LogAnalysis:
    # Numero massimo di failure consentiti
    max_fails = 2
    execute = False
    # comando per inserire la regola di blocco
    deny_command = "firewall-cmd --add-rich-rule='rule family=ipv4 source address=XINDIPX reject' --permanent"
    apply_command = "firewall-cmd --reload"
    # Espressione regolare per match IPv4
    re_ipv4 = "([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    # Elenco delle espressioni regolari
    d0 = {
        're1': ".* Invalid user [a-zA-Z0-9]+ from " + re_ipv4 + " port [0-9]+",
        're2': ".* user denied [a-zA-Z0-9]+ from " + re_ipv4 + " .*",
        're3': ".* Connection closed by " + re_ipv4 + " port [0-9]+ \[preauth\]",
        're4': ".* Disconnected from " + re_ipv4 + " port [0-9]+ \[preauth\]",
        're5': ".* Received disconnect from " + re_ipv4 + " port [0-9]+:[0-9]+: Client disconnecting normally \[preauth\]",
        're6': ".* Bad protocol version identification .* from " + re_ipv4 + " port [0-9]+",
        're7': ".* phpMyAdmin\[[0-9]+\]: user denied: .* \(mysql-denied\) from " + re_ipv4
    }


    # Conterrà gli IP da blacklistare
    d1 = None
    delflag = False
    applyflag = False
    show = True
    simula = None

    def __init__(self,
                 execute=False,
                 show=True,
                 simula=True,
                 max_fails=2,
                 ip_blacklist={}):

        self.d1 = ip_blacklist
        self.execute = execute
        self.show = show
        self.simula = simula
        self.max_fails = max_fails

    def analisys(self, riga_log):
        # riga_log rappresenta una riga di log da analizzare!
        datetimeobj = datetime.now()
        timestampstr = datetimeobj.strftime("%d-%b-%Y (%H:%M:%S) => ")
        # timestampstr = datetimeobj.strftime("%d-%b-%Y (%H:%M:%S.%f)")
        for re_index, re_x in self.d0.items():
            # print(riga_log)
            # print(re_x)
            matches = re.findall(re_x, riga_log)
            if matches:
                ip_x = matches[0]
                # cerco ip_x come chiave nel dictionary d1,
                # se c'è incremento il rispettivo valore
                # se non c'è lo inserisco come chiave e la imposto ad 1
                if ip_x in self.d1:
                    self.d1[ip_x] = self.d1[ip_x] + 1
                else:
                    self.d1[ip_x] = 1
                if self.show:
                    mostrare = timestampstr + "match: " + re_index + ", ip: " + ip_x + ", times: " + str(self.d1[ip_x])
                    print(mostrare)

                # mi scorro il dictionary degli IP, e per ciacuno
                # che ha superato max_fails, eseguo la regola di blocco nel firewall
                for ip, num in self.d1.items():
                    if num > self.max_fails:
                        # rimuovo indirizzo dal dizionario
                        # anzi registro l'indirizzo per eliminarlo fuori dal ciclo
                        self.delflag = ip
                        # esegui blocco
                        strstop = self.deny_command.replace("XINDIPX", str(ip))
                        if self.show:
                            print(strstop)

                        if self.execute:
                            self.applyflag = True
                            subprocess_cmd = shlex.split(strstop)
                            subprocess.call(subprocess_cmd)

                if self.delflag:
                    del self.d1[self.delflag]
                    self.delflag = False

    def leggilog(self):
        j = 0
        k = 0
        try:
            for line in sys.stdin:
                k = k + 1
                line = line.rstrip("\n")
                self.analisys(line)

        except KeyboardInterrupt:
           sys.stdout.flush()
           pass

    def apply(self):
        threading.Timer(60.0, self.apply).start()
        if self.applyflag:
            # resetto il flag
            self.applyflag = False
            if self.show:
                print("Applico nuovi blocchi!")

            subprocess_cmd = shlex.split(self.apply_command)
            subprocess.call(subprocess_cmd)

    def simulazione(self):
        pl.analisys('bla bla Invalid user ppp2 from 1.1.1.1 port 11111')
        pl.analisys('Sep 19 04:54:44 Devel01-Smart phpMyAdmin[5244]: user denied: pluto (mysql-denied) from 1.1.1.1')


# pl = LogAnalysis(False, True, True)
pl = LogAnalysis(True, True, False)

if pl.simula:
    pl.simulazione()

else:
    pl.apply()
    pl.leggilog()
