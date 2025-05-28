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