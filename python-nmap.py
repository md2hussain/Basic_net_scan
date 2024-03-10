import nmap

def simple_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-Pn -sV -p 1-1000')  # Adjust the port range as needed
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            ports = nm[host][proto].keys()
            for port in ports:
                print('Port : %s\tState : %s\tService : %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name']))

if __name__ == "__main__":
    target = input("Enter target IP or range: ")
    simple_nmap_scan(target)
"# Basic_net_scan" 
