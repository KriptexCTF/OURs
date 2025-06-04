import asyncio
import aiohttp
import urllib.parse
import random
import logging
import validators
from asyncio import Semaphore
from lib.nmap import base32_decode
from lib.config_reader import threads_count, dir_wordlist
from lib.progress_bar import ScanState
import base64
import re
from typing import List, Dict, Optional

# Инициализация состояния сканирования
scan_state_fuzz = ScanState()

# Ограничение количества одновременных задач
MAX_CONCURRENT_TASKS = threads_count
semaphore = Semaphore(MAX_CONCURRENT_TASKS)

# Путь к wordlist (можно настроить в config_reader.py)
WORDLIST_PATH = dir_wordlist

def parse_creds(creds_b64: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if not creds_b64:
        return None, None
    try:
        creds_str = base64.b64decode(creds_b64).decode("utf-8")
        match = re.match(r"login:([^&]+)&&password:(.+)", creds_str)
        if not match:
            return None, None
        username, password = match.groups()
        return username, password
    except Exception as e:
        return None, None

def load_wordlist(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            words = [line.strip() for line in f if line.strip()]
        if not words:
            return []
        return words
    except FileNotFoundError:
        return []
    except Exception as e:
        return []

async def fuzz_directory(url: str, word: str, username: Optional[str] = None, password: Optional[str] = None, timeout: float = 5) -> Optional[Dict]:
    async with semaphore:
        scan_state_fuzz.next()
        target_url = urllib.parse.urljoin(url, word)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        }
        auth = aiohttp.BasicAuth(username, password) if username and password else None

        try:
            async with aiohttp.ClientSession() as session:
                await asyncio.sleep(random.uniform(0.1, 0.5))  # Случайная задержка
                async with session.get(target_url, headers=headers, auth=auth, timeout=timeout, allow_redirects=False) as response:
                    status = response.status
                    if status in [200,302]:
                        result = {"url": target_url, "status": status}
                        return result
                    return None
        except aiohttp.ClientError as e:
            return None
        except asyncio.TimeoutError:
            return None

def create_json(input_data: List) -> List[Dict]:
    data_list = []
    for host_id, results in input_data:
        data = {
            "id": host_id,
            "results": [r for r in results if r]
        }
        data_list.append(data)
    return data_list

async def initiation_scan(hosts_ip: List[str], creds: Optional[str] = None):
    words = load_wordlist(WORDLIST_PATH)
    if not words:
        return create_json([(host_ip, []) for host_ip in hosts_ip])

    scan_state_fuzz.total = len(words) * len(hosts_ip)
    scan_state_fuzz.is_scanning = True
    scan_state_fuzz.progress = 0

    username, password = parse_creds(creds)
    main_res = []
    for host_ip in hosts_ip:
        host = base32_decode(host_ip)
        if not validators.url(f"http://{host}"):
            for _ in range(len(words)):
                scan_state_fuzz.next()
            main_res.append([host_ip, []])
            continue

        url = f"http://{host}/"
        results = []
        tasks = [fuzz_directory(url, word, username, password) for word in words]
        for i in range(0, len(tasks), MAX_CONCURRENT_TASKS):
            batch = tasks[i:i + MAX_CONCURRENT_TASKS]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            results.extend([r for r in batch_results if not isinstance(r, Exception)])

        main_res.append([host_ip, results])

    scan_state_fuzz.is_scanning = False
    scan_state_fuzz.procent = None
    return create_json(main_res)