import psutil
import sys
import os
import win32evtlog
import win32evtlogutil
import re
import time
import socket
import ctypes
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


# Ensure the script runs as administrator
if not is_admin():
    print("Skript administrator olaraq işə salınacaq...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, '"{}"'.format(" ".join(sys.argv)), None, 1)
    sys.exit()


def get_local_ip():
    """Komputerin yerli IP ünvanını tapmaq üçün funksiyanı təyin edir."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip


def check_ports(host, ports, protocol="TCP"):
    """Verilən portları yoxlayıb açıq olanları qaytarır."""
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports


host = get_local_ip()
ports = [22, 80, 443, 8080]
open_ports = check_ports(host, ports)

if open_ports:
    print(f"Açıq portlar: {open_ports}")
else:
    print("Açıq port tapılmadı.")


def get_event_logs():
    server = 'localhost'
    log_type = 'Security'
    logs = []
    try:
        log_handle = win32evtlog.OpenEventLog(server, log_type)
        total_records = win32evtlog.GetNumberOfEventLogRecords(log_handle)
        print(f"Total records: {total_records}")

        events = win32evtlog.ReadEventLog(log_handle, win32evtlog.EVENTLOG_FORWARDS_READ, 0)
        if not events:
            print("Event logları tapılmadı.")
            return []
        
        for event in events:
            event_id = event.EventID
            timestamp = event.TimeGenerated
            description = win32evtlogutil.SafeFormatMessage(event, log_type)
            logs.append(f"Event ID: {event_id}, Timestamp: {timestamp}, Description: {description}")

        return logs
    except Exception as e:
        print(f"Logları oxumaqda xəta baş verdi: {str(e)}")
        return []


def check_suspicious_processes():
    suspicious_keywords = ["virus", "malware", "ransomware", "trojan", "keylogger", "backdoor", "exploit", "bot", "worm"]
    suspicious_processes = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = proc.info['name']
            exe = proc.info['exe']
            cmdline = proc.info['cmdline']

            if exe and name:
                if cmdline:
                    for keyword in suspicious_keywords:
                        if re.search(keyword, name.lower()) or any(re.search(keyword, part.lower()) for part in cmdline):
                            suspicious_processes.append({
                                "pid": proc.info['pid'],
                                "name": name,
                                "exe": exe,
                                "cmdline": cmdline,
                            })
                else:
                    for keyword in suspicious_keywords:
                        if re.search(keyword, name.lower()):
                            suspicious_processes.append({
                                "pid": proc.info['pid'],
                                "name": name,
                                "exe": exe,
                                "cmdline": cmdline,
                            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return suspicious_processes


def check_suspicious_files():
    suspicious_keywords = ["virus", "malware", "ransomware", "trojan"]
    suspicious_files = []
    temp_paths = [r"C:\Windows\Temp", r"C:\Users\Raul\AppData\Local\Temp"]

    for path in temp_paths:
        for root, dirs, files in os.walk(path):
            for file in files:
                if any(keyword in file.lower() for keyword in suspicious_keywords):
                    suspicious_files.append(os.path.join(root, file))

    return suspicious_files


def check_firewall_status():
    result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True)
    return result.stdout


def check_system_resources():
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent

    if cpu_usage > 90 or memory_usage > 90 or disk_usage > 90:
        print("Warning: High resource usage detected.")


def check_security_updates():
    result = subprocess.run(['powershell', '-Command', 'Get-WindowsUpdate'], capture_output=True, text=True)
    return result.stdout


def check_ports_multithreaded(host, ports, protocol="TCP"):
    def check_port(port):
        # Use the check_ports function to get the open ports for a specific port
        return check_ports(host, [port], protocol)
    
    with ThreadPoolExecutor() as executor:
        results = executor.map(check_port, ports)
    
    # Flatten the list of open ports and avoid duplicates
    open_ports = [port for result in results for port in result]
    
    return open_ports


def generate_security_report():
    print("Sistem Təhlükəsizlik Nəzarəti...")

    # Event Logları
    print("\nEvent Logları:")
    logs = get_event_logs()
    if logs:
        for log in logs:
            print(log)
    else:
        print("Event logları tapılmadı.")

    # Şübhəli Proseslər
    print("\nŞübhəli Proseslər:")
    processes = check_suspicious_processes()
    if processes:
        for process in processes:
            print(process)
    else:
        print("Şübhəli proses tapılmadı.")
    
    # Şübhəli Fayllar
    print("\nŞübhəli Fayllar:")
    files = check_suspicious_files()
    if files:
        for file in files:
            print(file)
    else:
        print("Şübhəli fayl tapılmadı.")
    
    # Hesabatı faylda qeyd etmək
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_filename = f"security_report_{timestamp}.txt"
    
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write("Təhlükəsizlik Hesabatı\n")
        f.write(f"Yaradılma vaxtı: {timestamp}\n\n")

        f.write("Event Logları:\n")
        for log in logs:
            f.write(log + "\n")
        
        f.write("\nŞübhəli Proseslər:\n")
        for process in processes:
            f.write(str(process) + "\n")
        
        f.write("\nŞübhəli Fayllar:\n")
        for file in files:
            f.write(file + "\n")
    
    print(f"\nHesabat '{report_filename}' faylında yaradıldı.")


if __name__ == "__main__":
    generate_security_report()
