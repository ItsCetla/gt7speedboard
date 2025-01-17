from datetime import datetime as dt
from datetime import timedelta as td
from sb.helpers import logPrint
import socket
import sys
import struct
import threading
import queue
import time
from sb.crypt import salsa20_dec

class GT7TelemetryReceiver:

    def __init__(self, ip):
        # ports for send and receive data
        self.SendPort = 33739
        self.ReceivePort = 33740
        self.ip = ip
        self.prevlap = -1
        self.pktid = 0
        self.pknt = time.perf_counter()
        self.s = None
        self.running = False
        self.queue = None
        self.record = None
        self.startRec = False
        self.stopRec = False
        self.ignorePktId = False
        self.reconnect_delay = 1  # Initial reconnect delay in seconds
        self.max_reconnect_delay = 30  # Maximum reconnect delay in seconds

    def setQueue(self, q):
        self.queue = q

    def setIgnorePktId(self, b):
        self.ignorePktId = b

    def setup_socket(self):
        try:
            if self.s:
                self.s.close()
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bindTries = 10
            while bindTries > 0:
                try:
                    self.s.bind(("0.0.0.0", self.ReceivePort))
                    bindTries = 0
                except:
                    self.ReceivePort += 1
                    bindTries -= 1
                    if bindTries == 0:
                        raise
            self.s.settimeout(2)
            return True
        except Exception as e:
            logPrint(f'Failed to setup socket: {e}')
            return False

    # send heartbeat
    def send_hb(self):
        try:
            send_data = 'A'
            self.s.sendto(send_data.encode('utf-8'), (self.ip, self.SendPort))
            return True
        except Exception as e:
            logPrint(f'Failed to send heartbeat: {e}')
            return False

    def startRecording(self, sessionName):
        logPrint("Start recording")
        self.startRec = True
        self.sessionName = sessionName

    def stopRecording(self):
        logPrint("Stop recording")
        self.startRec = False
        self.stopRec = True

    def runTelemetryReceiver(self):
        if not self.setup_socket():
            logPrint("Failed to initialize socket")
            return

        # start by sending heartbeat
        self.send_hb()

        self.running = True
        while self.running:
            try:
                if self.startRec:
                    fn = self.sessionName + "recording-" + dt.now().strftime("%Y-%m-%d_%H-%M-%S") + ".gt7"
                    logPrint("record to", fn)
                    self.record = open(fn, "wb")
                    self.startRec = False
                if self.stopRec:
                    self.stopRec = False
                    self.record.close()
                    self.record = None

                data, address = self.s.recvfrom(4096)
                if not address[0] == self.ip:
                    continue

                if not self.record is None:
                    self.record.write(data)
                
                ddata = salsa20_dec(data)
                newPktId = struct.unpack('i', ddata[0x70:0x70+4])[0]
                if len(ddata) > 0 and newPktId < self.pktid:
                    logPrint("Time travel or new recording")
                    self.pktid = newPktId-1
                    
                if len(ddata) > 0 and (self.ignorePktId or newPktId > self.pktid):
                    if self.pktid != newPktId-1:
                        logPrint("Packet loss:", newPktId-self.pktid-1)
                    self.pktid = newPktId

                    if not self.queue is None:
                        self.queue.put((ddata, data))

                newPknt = time.perf_counter()
                if newPknt - self.pknt > 5:
                    if not self.send_hb():
                        raise Exception("Failed to send heartbeat")
                    self.pknt = time.perf_counter()

                # Reset reconnect delay on successful communication
                self.reconnect_delay = 1

            except socket.timeout:
                logPrint('Connection timed out, attempting to reconnect...')
                if not self.send_hb():
                    # If heartbeat fails, try to reconnect
                    if not self.setup_socket():
                        time.sleep(self.reconnect_delay)
                        # Exponential backoff for reconnect delay
                        self.reconnect_delay = min(self.reconnect_delay * 2, self.max_reconnect_delay)
                    else:
                        self.send_hb()
                self.pknt = time.perf_counter()

            except Exception as e:
                logPrint(f'Exception in telemetry receiver: {e}')
                # Try to reconnect on any other error
                if not self.setup_socket():
                    time.sleep(self.reconnect_delay)
                    # Exponential backoff for reconnect delay
                    self.reconnect_delay = min(self.reconnect_delay * 2, self.max_reconnect_delay)
                else:
                    self.send_hb()
                self.pknt = time.perf_counter()

        if self.s:
            self.s.close()

