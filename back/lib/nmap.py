import asyncio
from base64 import b32decode
import nmap

def create_json(input):
    return [{"id": id, "ports": ports} for id, ports in input]

def base32_decode(input):
    return (b32decode(input.encode("utf-8"))).decode("utf-8")

def scan_ports(target, port_min, port_max):
    nm = nmap.PortScanner()
    open_ports_with_services = []
    try:
        result = nm.scan(target, f"{port_min}-{port_max}", arguments="-T4", timeout=30)
        for port in range(port_min, port_max + 1):
            try:
                port_data = result["scan"].get(target, {}).get("tcp", {}).get(port, {})
            except Exception as e:
                print(e)
                return 0
            if port_data.get("state") == "open":
                service_name = port_data.get("name", "Unknown service")
                open_ports_with_services.append({"port": port, "service": service_name})
                print(f"Target: {target}, Port: {port}, Service: {service_name}") 
        return open_ports_with_services
    except Exception as e:
        print(f"Ошибка сканирования {target}: {e}")
        return []

async def async_scan(target, port_min, port_max):
    return target, await asyncio.to_thread(scan_ports, base32_decode(target), port_min, port_max)


async def nmap_start(targets):
    port_min, port_max = 1, 10000  # 1-65535
    tasks = [async_scan(target, port_min, port_max) for target in targets]
    try:
        scan_results = await asyncio.gather(*tasks)
    except Exception as e:
        print(e)
        return 0
    return create_json(scan_results)
