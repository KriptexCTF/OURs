import asyncio
import asyncssh
from asyncio import Semaphore
from lib.nmap import base32_decode
from lib.config_reader import threads_count, passwords, users

MAX_CONCURRENT_TASKS = threads_count  # Ограничение количества потоков
semaphore = Semaphore(MAX_CONCURRENT_TASKS)
found = asyncio.Event()  # Флаг для остановки сканирования при успешном входе

class Good_Pass:
	def __init__(self):
		self.password = None
	def set_pass(self,test):
		self.password = test
true_password = None

class Paths():
	def __init__(self, passwords_path=passwords, usernames_path=users):
		self.usernames = usernames_path
		self.passwords = passwords_path
get_path = Paths()

#-----------Wordlist-----------
def get_list_from_file(path):
	with open(path, 'r', encoding="utf-8", errors="replace") as file:
		list = [line.strip() for line in file if line.strip()]
	return list
password_list = get_list_from_file(get_path.passwords)
username_list = get_list_from_file(get_path.usernames)
#------------------------------

def help_json(user_pass):
	data_list = []
	for username, password in user_pass:
		data = {
			"username": username,
			"password": password
		}
		data_list.append(data)
	return data_list
def create_json(input_data):
	data_list = []
	for arm in input_data:
		data = {
			"id": arm[0],
			"users": help_json(arm[1])
		}
		data_list.append(data)
	return data_list
async def exec_command_ssh(session, command):
	try:
		result = await session.run(command, check=True)
		output = f"[+] {command} -- {str(result.stdout.strip())}\n"
		return output
	except Exception:
		output = f"[+] {command} -- Error\n"
		return output
async def ssh_bruteforce(host, username, password, retry=10):
	async with semaphore:
		for attempt in range(retry):
			if found.is_set():  # Останавливаем проверку, если уже нашли пароль
				return False
			try:
				async with asyncssh.connect(host, username=username, password=password, known_hosts=None) as conn:
					true_password.set_pass(password)
					print(f"[+] SSH login successful on {host} with username {username} and password {password}")
					found.set()  # Устанавливаем флаг, чтобы остановить подбор
					return True
			except asyncssh.PermissionDenied as e:
				#print(f"[-] SSH Permissinon Denied {password} {e}")
				return False
			except OSError as e:
				if (e.errno == 61):
					print(f"[-] ERROR Host is unavailable: {e}")
					found.set()
					return True
				else:
					print(f"[-] SSH connection reset ({password}), retrying ({attempt+1}/{retry})... {e}")
					await asyncio.sleep(1)
			except Exception as e:
				print(f"[-] SSH connection reset ({password}), retrying ({attempt+1}/{retry})... {e}")
				await asyncio.sleep(1)
		return False

async def start_scan(host, username):
	global true_password
	true_password = Good_Pass()
	tasks = set()
	for password in password_list:
		if found.is_set():  # Останавливаем подбор, если нашли пароль
			break
		if len(tasks) >= MAX_CONCURRENT_TASKS:
			_done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
		tasks.add(asyncio.create_task(ssh_bruteforce(host, username, password)))
	await asyncio.wait(tasks)
	if tasks:
		await asyncio.wait(tasks)
	print("[+] SSH brute force completed")
	found.clear()
	text = f"[?] Password: {true_password.password}"
	if true_password.password is not None:
		print("\033[32m{}\033[0m".format(text))
	else:
		print("\033[38;5;208m{}\033[0m".format(text))
	return true_password.password

async def initiation_scan(hosts_ip):
	main_res = []
	for host_ip in hosts_ip:
		host = base32_decode(host_ip)
		result = []
		for username in username_list:
			print(f"[*] Info {base32_decode(host_ip)} => {username}")
			user_password = await start_scan(host, username)
			result.append([username,user_password])
		main_res.append([host_ip,result])
	return create_json(main_res)