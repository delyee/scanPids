'''
Внедрить данный функционал в yara_agent и создать рабочий билд Client-Server архитектуры. 

Вернуться к разработке async-yara-backend, удалить лишнее и вытащить из private, а так же:
1. упростить первый билд и:
- сделать вывод на сервере в консоль 
- тестить на "low load" - хватит 1-3 клиентов
2. переписать механизм обновления правил:
- Server делает git fetch && git pull каждые 15 минут
- Server отдает по https и при наличии token скомпилированные правила yara: таким образом agent 
требуется выкачать всего лишь 1 файл при старте
'''

### Закончить вышеописанное до внесения любых изменений (need backup) - вывод в agent идет только в файл и
## prettytable там не требуется


'''
Динамический "дополняющийся" вывод в prettytable: hack из-за multithread
1. создаем отдельный array OUTPUT при старте main для последующей многократной отрисовки в table
2. Переделать существующий lock треда для оптимизации ввода/вывода:
- убираем COUNTER
- наполняем существующими данными из mycallback array OUTPUT 
- старый вывод из mycallback направляем в файл для "устойчивого" output юзверю
3. добавляем row в object prettytable при каждой итерации While
4. найти метод в lib prettytable для "очистки" экрана или взять вызов clear из os.system
5. в итерации While заново отрисовываем table
'''


'''
- Написать функцию для парсинга cmdline
- Добавить в file-output и table username (cwd, вроде) и cmdline найденого PID
- Ограничить вывод Strings - мусор на экране
'''

### Закончить вышеописанное до рабочего билда v3 


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

print('[!] {} PIDs loaded\n[!] Wait starting threads...'.format(PIDsQueue.qsize()))

for _ in range(THREADS):
	_ = Scanner()
	_.setDaemon(True)
	_.start()

sleep(3)

while not PIDsQueue.empty():
	print('[%] Scanned: {} | Queue size: {} | Active threads: {}'.format(COUNTER, PIDsQueue.qsize(), threading.active_count()-1))
	sleep(15)

PIDsQueue.join()

# killmeforthiscode


