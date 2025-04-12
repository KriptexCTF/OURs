from asyncio import gather, Semaphore
from getmac import get_mac_address
from ipaddress import ip_network
from icmplib import async_ping
from base64 import b32encode
from json import loads
from socket import gethostbyaddr
from lib.config_reader import threads_count, ouifile_path

#-----------vendors_list
filename_path = ouifile_path
vendors_json = (loads(open(filename_path, 'r', encoding="utf-8", errors="replace").read()))
#-----------

SEMAPHORE_LIMIT = threads_count
semaphore = Semaphore(SEMAPHORE_LIMIT)

class ScanState:
	def __init__(self):
		self.total = 0
		self.progress = 0
		self.is_scanning = False
		self.procent = None
	def next(self):
		if self.progress < self.total:
			self.progress += 1
			self.procent = f"{((self.progress / self.total) * 100):.2f}%"    
scan_state = ScanState()

async def scan_ip(ip: str):
	async with semaphore:
		scan_state.next()
		try:
			result = await async_ping(str(ip), count=2, interval=0.5, timeout=0.1)
			mac = get_mac_address(ip=str(ip))
			vendor = find_vendor(mac)
			return ip, result.is_alive, mac, vendor
		except Exception as e:
			print(e)
			return ip, False, None, None
async def start_scan(range_ip: str):
	scan_state.total = addr_count((range_ip.split('/'))[1])
	scan_state.is_scanning = True
	scan_state.progress = 0   
	ip_list = network_list(range_ip)
	tasks = [scan_ip(ip) for ip in ip_list]  
	results = []
	for i in range(0, len(tasks), SEMAPHORE_LIMIT): # Semaphore limit
		batch = tasks[i:i + SEMAPHORE_LIMIT]
		results.extend(await gather(*batch))
	scan_state.is_scanning = False
	return results

def get_hostname(ip):
	try:
		hostname = gethostbyaddr(ip)[0]
	except:
		hostname = None
	return hostname
def addr_count(mask_cidr: int):
	return 2**(32-int(mask_cidr))-2
def network_list(ip_range: str):
	network = ip_network(ip_range, strict=False)
	return network.hosts()
def create_json(array):
	data_list = []
	for address, status, mac, vendor in array:
		address = str(address)
		if(status):
			data = {
				"id": (b32encode(address.encode()).decode()),
				"ip": address,
				"mac": mac,
				"hostname": get_hostname(address),
				"vendor": vendor
			}
			data_list.append(data)
	return data_list
def find_vendor(mac):
	if mac is not None:
		mac = ("".join(mac.split(":")[:3])).upper()
		try:
			return vendors_json[mac]
		except Exception as e:
			return None
	return None