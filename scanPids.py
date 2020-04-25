from queue import Queue
import threading
import yara
from sys import argv
from time import sleep
# max pid (BSD) 99999, centos 32768, debian 65536
from pathlib import Path
# todo: install psutil

yara.set_config(max_strings_per_rule=20000, stack_size=32768)
MALWARE_RULES = 'Rules/index.yar'
lock = threading.Lock()
#rules = yara.compile(filepath=MALWARE_RULES, includes=False)
PIDsQueue = Queue()
COUNTER = 0
THREADS = 6

class Scanner(threading.Thread):
	def mycallback(self, data):
		print('[+] Rule: {}, PID: {}, Strings: {}'.format(data.get('rule'), self._pid, data.get('strings')))

	def __init__(self):
		threading.Thread.__init__(self)
		self.rules = yara.compile(filepath=MALWARE_RULES, includes=True)

	def run(self):
		while True:
			self._pid = PIDsQueue.get()
			self.scan(self._pid)
			PIDsQueue.task_done()
			with lock:
				global COUNTER
				COUNTER += 1

	def scan(self, _pid):
		try:
			self.rules.match(pid=_pid, callback=self.mycallback, which_callbacks=yara.CALLBACK_MATCHES)
		except yara.Error:
			pass # process dead
		

for x in Path('/proc').iterdir():
    if x.is_dir() and x.name.isdigit():
        PIDsQueue.put(int(x.name))


for i in range(THREADS):
	t = Scanner()
	t.setDaemon(True)
	t.start()

print('[!] {} PIDs loaded\n[!] Wait starting threads...'.format(PIDsQueue.qsize()))
sleep(10)

while not PIDsQueue.empty():
	print('[%] Scanned: {} | Queue size: {} | Active threads: {}'.format(COUNTER, PIDsQueue.qsize(), threading.active_count()))
	sleep(30)

PIDsQueue.join()

# killmeforthiscode


