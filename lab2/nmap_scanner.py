import nmap

target = input("Target: ")
start_port = input("Start port: ")
end_port = input("End port: ")
open_ports = []

scanner = nmap.PortScanner()

scanner.scan(
    target,
    (start_port + "-" + end_port)
)

print(scanner.all_hosts())
