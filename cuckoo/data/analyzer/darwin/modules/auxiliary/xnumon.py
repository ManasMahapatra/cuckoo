from __future__ import print_function
from lib.common.process import TRACKED_PROCESSES
import subprocess
import socket
import json
import logging
import signal
import sys
import os

logger = logging.getLogger(__name__)

class InitiateMonitor(object):
    def __init__(self, config):
        self.PID_PATH = '/private/var/run/xnumon.pid'
        self.RELEVANT_EVENTCODES = (2,3,4)
        self.XNUMON_PATH = '/usr/local/sbin'
        #store configurations
        self.config = config

    def _run(self):
        # kill existing xnumon instance
        self._kill_existing()
        # initiate logging
        self._log()

    def _kill_existing(self):
        if os.path.isfile(self.PID_PATH):
            os.remove(self.PID_PATH)

    def _execute(self,cmd):
        popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
        for stdout_line in iter(popen.stdout.readline,""):
            yield stdout_line
        popen.stdout.close()
        return_code = popen.wait()
        if return_code:
            raise subprocess.CalledProcessError(return_code, cmd)

    def _check_relevance(self,log):
        json_string = json.loads(log)
        if json_string["eventcode"] in self.RELEVANT_EVENTCODES:
            if json_string["subject"]["pid"] in TRACKED_PROCESSES or json_string["subject"]["image"]["exec_pid"] in TRACKED_PROCESSES:
                return True
            elif json_string["subject"]["ancestors"]:
                for ancestor in json_string["subject"]["ancestors"]:
                    if ancestor["exec_pid"] in TRACKED_PROCESSES:
                        TRACKED_PROCESSES.append(json_string["subject"]["pid"])
                        return True
                    else:
                        return False
            else:
                return False
        else:
            return False

    def _log(self):
        buffer = []
        iteration_control = True
        socket_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_host.connect((self.config.ip, self.config.port))
        socket_host.send("JSON\n")
        socket_host.send("XNUMON\n")
        for log in self._execute(["sudo", "/usr/local/sbin/xnumon", "-d"]):
            if TRACKED_PROCESSES:
                if iteration_control:
                    for buf in buffer:
                        if self._check_relevance(buf):
                            socket_host.send(buf.encode())
                    iteration_control = False
                if self._check_relevance(log):
                    socket_host.send(log.encode())
            else:
                buffer.append(log)
