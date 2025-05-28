import asyncio
import asyncssh
from asyncio import Semaphore
from lib.nmap import base32_decode
from lib.config_reader import threads_count, passwords, users
from lib.progress_bar import ScanState

# Инициализация состояния сканирования
scan_state_ssh = ScanState()
ssh_port = 22
# Ограничение количества одновременных задач
MAX_CONCURRENT_TASKS = threads_count
semaphore = Semaphore(MAX_CONCURRENT_TASKS)
found = asyncio.Event()  # Флаг для остановки сканирования при успешном входе

class Good_Pass:
    def __init__(self):
        self.password = None

    def set_pass(self, test):
        self.password = test

true_password = None

class Paths:
    def __init__(self, passwords_path=passwords, usernames_path=users):
        self.usernames = usernames_path
        self.passwords = passwords_path

get_path = Paths()

# -----------Wordlist-----------
def get_list_from_file(path):
    with open(path, 'r', encoding="utf-8", errors="replace") as file:
        return [line.strip() for line in file if line.strip()]

password_list = get_list_from_file(get_path.passwords)
username_list = get_list_from_file(get_path.usernames)
# ------------------------------

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

# Проверка доступности порта
async def check_port(host, port=ssh_port, timeout=3):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        #print(f"[DEBUG] Port {port} is open on {host}")
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
        print(f"[DEBUG] Port {port} is closed or unreachable on {host}: {e}")
        return False

async def ssh_bruteforce(host, username, password, retry=10, connect_timeout=3):
    async with semaphore:
        scan_state_ssh.next()
        # Проверяем, открыт ли порт SSH
        if not await check_port(host, ssh_port, timeout=connect_timeout):
            print(f"[-] SSH port {ssh_port} is closed on {host}, skipping brute force")
            found.set()
            return False
        for attempt in range(retry):
            if found.is_set():
                return False
            try:
                async with asyncssh.connect(
                    host,
                    username=username,
                    password=password,
                    known_hosts=None,
                    connect_timeout=connect_timeout
                ) as conn:
                    true_password.set_pass(password)
                    print(f"[+] SSH login successful on {host} with username {username} and password {password}")
                    found.set()
                    return True
            except asyncssh.PermissionDenied:
                #print(f"[-] SSH Permission Denied for {username}:{password} on {host}")
                return False
            except ConnectionRefusedError:
                print(f"[-] SSH connection refused on {host}, port likely closed")
                found.set()
                return False
            except (asyncio.TimeoutError, asyncssh.misc.ConnectionLost):
                print(f"[-] SSH connection timed out for {username}:{password} on {host} ({attempt+1}/{retry})")
                await asyncio.sleep(1)
            except OSError as e:
                if e.errno == 61:
                    print(f"[-] ERROR Host is unavailable: {e}")
                    found.set()
                    return False
                else:
                    print(f"[-] SSH connection error for {username}:{password} on {host} ({attempt+1}/{retry}) - {e}")
                    await asyncio.sleep(1)
            except Exception as e:
                print(f"[-] SSH connection error for {username}:{password} on {host} ({attempt+1}/{retry}) - {e}")
                await asyncio.sleep(1)
        return False

async def start_scan(host, username):
    global true_password
    true_password = Good_Pass()
    tasks = set()
    for password in password_list:
        if found.is_set():
            scan_state_ssh.progress += (len(password_list) - password_list.index(password) + 1) - 1
            scan_state_ssh.next()
            break
        if len(tasks) >= MAX_CONCURRENT_TASKS:
            _done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        tasks.add(asyncio.create_task(ssh_bruteforce(host, username, password, connect_timeout=3)))
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
    scan_state_ssh.total = len(password_list) * len(username_list) * len(hosts_ip)
    if scan_state_ssh.total == 0:
        print("[-] No tasks to process (empty hosts or lists).")
        return create_json([])
    scan_state_ssh.is_scanning = True
    scan_state_ssh.progress = 0
    print(f"[*] Total tasks: {scan_state_ssh.total}")
    main_res = []
    for host_ip in hosts_ip:
        host = base32_decode(host_ip)
        result = []
        print(f"[*] Scanning {host}:{ssh_port}")
        for username in username_list:
            print(f"[*] Info {host} => {username}")
            user_password = await start_scan(host, username)
            result.append([username, user_password])
        main_res.append([host_ip, result])
    scan_state_ssh.is_scanning = False
    return create_json(main_res)