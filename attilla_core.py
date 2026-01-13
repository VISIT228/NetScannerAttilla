import nmap
import datetime

def attilla_scan(target):
    nm = nmap.PortScanner()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_name = "scan_report.txt"

    print(f"[{timestamp}] Запуск NetScannerAttilla для: {target}...")
    
    # Виконуємо сканування
    nm.scan(target, arguments='-sV -O --script vuln')

    with open(report_name, "a") as f:
        f.write(f"\n--- Звіт за {timestamp} ---\n")
        
        for host in nm.all_hosts():
            res = f"\n[+] ХОСТ: {host} ({nm[host].hostname()})\n[*] СТАТУС: {nm[host].state()}\n"
            print(res)
            f.write(res)

            # БЕЗПЕЧНЕ визначення ОС
            if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
                os_info = f"[*] ОС: {nm[host]['osmatch'][0]['name']}\n"
            else:
                os_info = "[*] ОС: Не вдалося визначити (пристрій захищений або недостатньо даних)\n"
            
            print(os_info)
            f.write(os_info)

            # Порти та сервіси
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    service = nm[host][proto][port]['name']
                    product = nm[host][proto][port].get('product', '')
                    port_info = f"    - Порт {port}: {service} {product}\n"
                    print(port_info)
                    f.write(port_info)

    print(f"\n[!] Сканування завершено. Результати збережено в {report_name}")

if __name__ == "__main__":
    ip = input("Введіть IP для сканування: ")
    attilla_scan(ip)
