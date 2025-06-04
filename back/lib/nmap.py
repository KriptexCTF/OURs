import asyncio
from base64 import b32decode
import nmap
from fastapi import FastAPI
from asyncio import Semaphore
from lib.config_reader import threads_count

app = FastAPI()
SEMAPHORE_LIMIT = min(threads_count, 20)  # Ограничение сверху
semaphore = Semaphore(SEMAPHORE_LIMIT)

def create_json(input):
    return [{"id": id, "ports": ports} for id, ports in input]

def base32_decode(input):
    return b32decode(input.encode("utf-8")).decode("utf-8")

async def scan_ports(target, port_min, port_max):
    nm = nmap.PortScanner()
    open_ports_with_services = []
    try:
        result = await asyncio.to_thread(
<<<<<<< HEAD
            nm.scan, target, None, arguments="-sV -T5" #f"{port_min}-{port_max}"
=======
            nm.scan, target, f"{port_min}-{port_max}", arguments="-sS -T5"
>>>>>>> 508e365d55abd0c2466174c7c4cc6f7ec8f32986
        )
        tcp_data = result["scan"].get(target, {}).get("tcp", {})
        for port, port_data in tcp_data.items():
            if port_data.get("state") == "open":
                service_name = port_data.get("name", "Неизвестный сервис")
                open_ports_with_services.append({"port": port, "service": service_name})
        return open_ports_with_services
    except nmap.PortScannerError as e:
        print(f"PortScannerError for {target}: {e}")
        return []

async def async_scan(target, port_min, port_max):
    async with semaphore:
        decoded_target = base32_decode(target)
        try:
            ports = await scan_ports(decoded_target, port_min, port_max)
            return target, ports
        except Exception as e:
            print(f"Ошибка в async_scan {target}: {e}", flush=True)
            return target, []

async def nmap_start(targets):
    port_min, port_max = 1, 1000  # Уменьшен диапазон
    tasks = [async_scan(target, port_min, port_max) for target in targets]
    try:
        results = []
        for i in range(0, len(tasks), SEMAPHORE_LIMIT):
            batch = tasks[i:i + SEMAPHORE_LIMIT]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            results.extend(batch_results)
        valid_results = [(target, ports) for target, ports in results if not isinstance(ports, Exception)]
    except Exception as e:
        print(f"Ошибка в nmap_start: {e}", flush=True)
        return []
    return create_json(valid_results)
