import subprocess
import json
import os
from typing import List, Dict

def search_exploits(service: str, version: str = "") -> List[Dict]:
    """
    Выполняет поиск эксплойтов через searchsploit для указанного сервиса и версии.
    Возвращает список словарей с информацией об эксплойтах.
    """
    print(f"[DEBUG] Searching exploits for: {service} {version}")
    try:
        cmd = ["searchsploit", "--json", f"{service} {version}".strip()]
        print(f"[DEBUG] Running command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        print(f"[DEBUG] Searchsploit output: {result.stdout}")
        exploits = json.loads(result.stdout).get("RESULTS_EXPLOIT", [])
        formatted_exploits = [
            {
                "title": exploit.get("Title", "Unknown"),
                "edb_id": exploit.get("EDB-ID", "Unknown"),
                "path": exploit.get("Path", "Unknown"),
                "date": exploit.get("Date", None),  # Безопасное получение Date
                "author": exploit.get("Author", "Unknown"),
                "platform": exploit.get("Platform", "Unknown"),
                "type": exploit.get("Type", "Unknown")
            }
            for exploit in exploits
        ]
        print(f"[DEBUG] Found {len(formatted_exploits)} exploits")
        return formatted_exploits
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Searchsploit failed: {e}, stderr: {e.stderr}")
        return []
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON decode error: {e}")
        return []

def search_exploits_for_host(host_data: Dict) -> Dict:
    """
    Ищет эксплойты для всех сервисов и версий, найденных на хосте.
    """
    host_ip = host_data["ip"]
    print(f"[DEBUG] Processing host: {host_ip}")
    results = {"ip": host_ip, "exploits": []}
    for port_data in host_data.get("ports", []):
        service = port_data["service"]
        version = port_data["version"]
        if service == "unknown" or version == "unknown":
            print(f"[DEBUG] Skipping unknown service/version: {service} {version}")
            continue
        exploits = search_exploits(service, version)
        if exploits:
            results["exploits"].append({
                "port": port_data["port"],
                "service": service,
                "version": version,
                "exploits": exploits
            })
    return results

def search_exploits_from_db(host_ip: str = None) -> List[Dict]:
    """
    Ищет эксплойты для всех хостов или конкретного хоста из scan_results.json.
    """
    db_file = "scan_results.json"
    print(f"[DEBUG] Loading database: {db_file}")
    if not os.path.exists(db_file):
        print(f"[ERROR] Database file {db_file} not found")
        return []

    with open(db_file, 'r', encoding='utf-8') as f:
        db_data = json.load(f)
    print(f"[DEBUG] Database loaded, hosts: {list(db_data['hosts'].keys())}")

    results = []
    for ip, host_data in db_data["hosts"].items():
        if host_ip and ip != host_ip:
            continue
        exploit_results = search_exploits_for_host(host_data)
        if exploit_results["exploits"]:
            results.append(exploit_results)
    print(f"[DEBUG] Returning {len(results)} results")
    return results