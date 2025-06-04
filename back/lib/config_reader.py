from configparser import ConfigParser
config = ConfigParser()
config.read("./config.ini")

log_mode = config['General']['debug']
host = config['General']['host']
port = config.getint('General','port')
threads_count = config.getint('General','threads')

ouifile_path = config['Path']['oui_file']
passwords = config['Path']['password_list']
users = config['Path']['username_list']

dir_wordlist = config['Web']['dir_fuzz_list']
