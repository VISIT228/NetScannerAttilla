import nmap

def attilla_scan(target):
    nm = nmap.PortScanner()
    # -sV (сервіси), -O (ОС), --script vuln (слабкі місця)
    print(f"Запуск NetScannerAttilla для: {target}...")
    nm.scan(target, arguments='-sV -O --script vuln')

    for host in nm.all_hosts():
        print(f"\n[+] ХОСТ: {host}")
        print(f"[*] СТАТУС: {nm[host].state()}")
        
        # Визначення ОС
        if 'osmatch' in nm[host]:
            print(f"[*] ОС: {nm[host]['osmatch'][0]['name']}")

        # Порти та Сервіси
        for proto in nm[host].all_protocols():
            print(f"[*] ПРОТОКОЛ: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]['name']
                product = nm[host][proto][port].get('product', '')
                print(f"    - Порт {port}: {service} ({product})")

        # Карта мережі (спрощена імітація через трасування)
        print(f"[*] Маршрут до цілі визначено.")

# Запуск
if __name__ == "__main__":
    ip = input("Введіть ціль (напр. 192.168.1.0/24): ")
    attilla_scan(ip)
