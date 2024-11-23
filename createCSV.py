import csv
import random

def generate_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def generate_protocol():
    return random.choices(
        ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'],
        weights=[40, 30, 10, 10, 10]  # TCP/UDP are more frequent
    )[0]

def generate_size(protocol):
    if protocol in ['ICMP']:
        return random.randint(64, 128)  # Smaller packets
    elif protocol in ['HTTP', 'HTTPS']:
        return random.randint(512, 1500)  # Larger packets
    else:
        return random.randint(64, 1500)

def generate_flags(protocol):
    if protocol == 'TCP':
        return random.choice(['SYN', 'ACK', 'FIN', 'RST', 'PSH'])
    return ''  # No flags for UDP, ICMP, etc.

def generate_label(size):
    # Malicious labels slightly correlated with large sizes
    return 'malicious' if size > 1000 and random.random() > 0.8 else 'benign'

def generate_csv(file_name, num_records=500):
    with open(file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['source_ip', 'dest_ip', 'protocol', 'size', 'flags', 'label'])
        for _ in range(num_records):
            protocol = generate_protocol()
            size = generate_size(protocol)
            writer.writerow([
                generate_ip(),
                generate_ip(),
                protocol,
                size,
                generate_flags(protocol),
                generate_label(size)
            ])
    print(f"Enhanced CSV file '{file_name}' created with {num_records} entries.")


if __name__ == "__main__":
    generate_csv('network_packets.csv', num_records=1000)
