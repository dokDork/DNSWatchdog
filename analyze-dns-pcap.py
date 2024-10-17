import pyshark
import argparse
import sys
import os

# Reindirizza stderr a /dev/null o NUL
sys.stderr = open(os.devnull, 'w')

def get_dns_info(pcap_file, source_ip):
    cap = pyshark.FileCapture(pcap_file)
    dns_queries = {}
    
    for packet in cap:
        if 'DNS' in packet:
            # get all DNS response given to source_ip
            if hasattr(packet.dns, 'qry_name') and hasattr(packet.dns, 'a') and packet.ip.dst == source_ip:
                hostname = packet.dns.qry_name
                ip_address = packet.dns.a
                if hostname not in dns_queries:  # Evita duplicati
                    dns_queries[hostname] = ip_address
                
    return dns_queries



def extract_ports_tcp(pcap_file, ip_address, source_ip):
    open_ports = set()
    closed_ports = set()
    cap = pyshark.FileCapture(pcap_file)
    
    for packet in cap:
        # Analyze TCP packet source_ip (our target we want to attack with MITM)  --> ip_address (ip that source_ip want to reach).
        # if source IP get SYN+ACK then possible destination_ip has an open port
        # if source IP get RST+ACK then possible destination_ip has an open port
        if hasattr(packet, 'ip') and packet.ip.src == ip_address and packet.ip.dst == source_ip:
            if 'TCP' in packet:
                print(f"found TCP packet: SRC: {packet.ip.src}   -SRCP:{packet.tcp.srcport}  -DST: {packet.ip.dst}  -DSTPORT:{packet.tcp.dstport}  -SYN: {packet.tcp.flags_syn}   -ACK:{packet.tcp.flags_ack}   -RST:{packet.tcp.flags_res}")
                if packet.tcp.flags_syn == 'True' and packet.tcp.flags_ack == 'True':  # SYN-ACK
                    destination_port = int(packet.tcp.srcport)
                    print(f"trovata porta di destinazione {destination_port}")
                    open_ports.add(destination_port)  
                elif packet.tcp.flags_syn == 'False' and packet.tcp.flags_ack == 'True':  # RST-ACK
                    destination_port = int(packet.tcp.srcport)
                    closed_ports.add(destination_port)
    return list(open_ports), list(closed_ports)





def extract_ports_udp(pcap_file, ip_address, source_ip):
    open_ports = set()
    closed_ports = set()
    cap = pyshark.FileCapture(pcap_file)

    for packet in cap:
        # I can not understand if UDP port is open or close. 
        # if I see a packet UDP that start from source_ip then I take the destination port and add it (not 53) to my list    
        if hasattr(packet, 'ip') and packet.ip.src == source_ip:    
            if 'UDP' in packet:
                print(f"found UDP packet: SRC: {packet.ip.src}   -SRCP:{packet.udp.srcport}  -DST: {packet.ip.dst}  -DSTPORT:{packet.udp.dstport}")            
                destination_port = int(packet.udp.dstport)
                if destination_port !=53:
                   open_ports.add(destination_port)  # Aggiungi le porte UDP come aperte
    return list(open_ports), list(closed_ports)



def main(pcap_file, source_ip):
    # our target (source_ip) resolve some DNS and get IP_Address (eg 10.10.10.10) from each hostname (eg www.myTarget.htb)
    dns_info = get_dns_info(pcap_file, source_ip)
    
    # Analyze TCP packets
    results_tcp = []    
    for hostname, ip_address in dns_info.items():
        open_ports, closed_ports = extract_ports_tcp(pcap_file, ip_address, source_ip)
        results_tcp.append({
            'hostname': hostname,
            'ip_obtained': ip_address,
            'open_ports': ', '.join(map(str, open_ports)),
            'closed_ports': ', '.join(map(str, closed_ports))
        })

    # Analyze UDP packets
    results_udp = []    
    for hostname, ip_address in dns_info.items():
        open_ports, closed_ports = extract_ports_udp(pcap_file, ip_address, source_ip)
        results_udp.append({
            'hostname': hostname,
            'ip_obtained': ip_address,
            'open_ports': ', '.join(map(str, open_ports))
        })

    print("Analyzed TCP packets:")
    print(f"{'Hostname':<30} {'IP Obtained':<15} {'Open Ports':<50} {'Closed Ports'}")
    print("="*120)    
    for result in results_tcp:
        print(f"{result['hostname']:<30} {result['ip_obtained']:<15} {result['open_ports']:<50} {result['closed_ports']}")
    
    print("")    
    print("Analyzed UDP packets:")
    print(f"{'Hostname':<30} {'IP Obtained':<20} {'Open Ports':<50}")
    print("="*100)    
    for result in results_udp:
        print(f"{result['hostname']:<30} {result['ip_obtained']:<20} {result['open_ports']:<50}")




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analizza un file PCAP per estrarre informazioni DNS e porte.')
    parser.add_argument('pcap_file', type=str, help='Percorso del file PCAP da analizzare')
    parser.add_argument('source_ip', type=str, help='Indirizzo IP sorgente da analizzare')    
    args = parser.parse_args()
    main(args.pcap_file, args.source_ip)
