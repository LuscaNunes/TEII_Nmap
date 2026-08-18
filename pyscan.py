#!/usr/bin/env python3
"""
pyscan.py - Scanner de portas TCP/UDP (clone simplificado do nmap)
====================================================================

Disciplina: Tópicos Especiais II
Trabalho:   A2 - NMAP - Desenvolvimento

Descrição geral
---------------
Ferramenta de linha de comando para varredura de portas TCP e UDP em um
ou mais endereços IP, usando técnicas básicas de detecção:

  - TCP SYN Scan ("half-open scan"): envia um pacote TCP com a flag SYN
    e analisa a resposta:
        SYN/ACK recebido  -> porta ABERTA (envia RST para não completar o handshake)
        RST recebido      -> porta FECHADA
        sem resposta      -> porta FILTRADA (provável firewall descartando o pacote)
        ICMP unreachable  -> porta FILTRADA

  - UDP Scan: envia um datagrama UDP vazio (ou com payload simples) e
    analisa a resposta:
        resposta UDP recebida        -> porta ABERTA
        ICMP port unreachable (tipo 3, código 3) -> porta FECHADA
        sem resposta                 -> ABERTA|FILTRADA (comportamento padrão do UDP:
                                         não há confirmação de recebimento, então a
                                         ausência de resposta é ambígua)

Requisitos
----------
  - Linux (usa raw sockets via Scapy, portanto requer privilégios de root)
  - Python 3.8+
  - Biblioteca scapy (pip install scapy)

Uso
---
    sudo python3 pyscan.py -t 192.168.0.1 -p 1-1000 --tcp --udp
    sudo python3 pyscan.py -t 192.168.0.1,192.168.0.2 -p 22,80,443 --tcp
    sudo python3 pyscan.py -t 192.168.0.0/29 -p 1-100 --tcp --threads 100

Autor: (preencher com seu nome)
"""

import argparse
import ipaddress
import sys
import os
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, conf
except ImportError:
    print("[ERRO] A biblioteca 'scapy' não está instalada.")
    print("Instale com: pip install scapy --break-system-packages")
    sys.exit(1)

conf.verb = 0  # silencia logs internos do scapy


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------

def check_root():
    """Raw sockets exigem privilégios administrativos no Linux."""
    if os.geteuid() != 0:
        print("[ERRO] Este scanner precisa ser executado como root (sudo),")
        print("       pois utiliza raw sockets para montar pacotes TCP/UDP/ICMP.")
        sys.exit(1)


def parse_ports(port_str):
    """
    Converte uma string de portas em uma lista de inteiros.
    Aceita formatos: '80', '22,80,443', '1-1000', '20-25,80,443'
    """
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def parse_targets(target_str):
    """
    Converte uma string de alvos em uma lista de IPs.
    Aceita: IP único, lista separada por vírgula, ou notação CIDR (rede).
    """
    targets = []
    for part in target_str.split(","):
        part = part.strip()
        if "/" in part:
            # notação CIDR -> varre a rede inteira (exclui rede/broadcast se aplicável)
            net = ipaddress.ip_network(part, strict=False)
            targets.extend([str(ip) for ip in net.hosts()])
        else:
            targets.append(part)
    return targets


# ---------------------------------------------------------------------------
# Técnicas de varredura
# ---------------------------------------------------------------------------

def tcp_syn_scan(ip, port, timeout=1.5):
    """
    Realiza um SYN scan em uma única porta TCP.

    Retorna uma string: 'open', 'closed' ou 'filtered'.
    """
    src_port = random.randint(1025, 65534)
    pkt = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return "filtered"  # sem resposta -> provavelmente bloqueado por firewall

    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        if flags & 0x12 == 0x12:  # SYN+ACK
            # fecha a conexão educadamente (não completa o handshake -> "half-open")
            rst_pkt = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="R")
            sr1(rst_pkt, timeout=1, verbose=0)
            return "open"
        elif flags & 0x14 == 0x14:  # RST+ACK
            return "closed"

    if resp.haslayer(ICMP):
        icmp_type = resp.getlayer(ICMP).type
        icmp_code = resp.getlayer(ICMP).code
        # tipo 3 = destination unreachable; códigos 1,2,3,9,10,13 indicam filtro
        if icmp_type == 3 and icmp_code in (1, 2, 3, 9, 10, 13):
            return "filtered"

    return "filtered"


def udp_scan(ip, port, timeout=1.5):
    """
    Realiza uma sondagem UDP em uma única porta.

    Retorna uma string: 'open', 'closed' ou 'open|filtered'.
    """
    pkt = IP(dst=ip) / UDP(sport=random.randint(1025, 65534), dport=port)
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        # UDP não confirma recebimento; sem resposta é ambíguo
        return "open|filtered"

    if resp.haslayer(ICMP):
        icmp_type = resp.getlayer(ICMP).type
        icmp_code = resp.getlayer(ICMP).code
        if icmp_type == 3 and icmp_code == 3:
            return "closed"  # port unreachable
        elif icmp_type == 3 and icmp_code in (1, 2, 9, 10, 13):
            return "filtered"

    if resp.haslayer(UDP):
        return "open"  # o host respondeu com um datagrama UDP -> porta aberta

    return "open|filtered"


# ---------------------------------------------------------------------------
# Orquestração da varredura
# ---------------------------------------------------------------------------

def scan_target(ip, ports, do_tcp, do_udp, threads):
    """
    Varre todas as portas solicitadas (TCP e/ou UDP) para um único IP,
    usando um pool de threads para acelerar o processo.

    Retorna um dicionário: {"tcp": {porta: estado}, "udp": {porta: estado}}
    """
    results = {"tcp": {}, "udp": {}}

    def worker_tcp(port):
        return port, tcp_syn_scan(ip, port)

    def worker_udp(port):
        return port, udp_scan(ip, port)

    if do_tcp:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(worker_tcp, p) for p in ports]
            for future in as_completed(futures):
                port, state = future.result()
                results["tcp"][port] = state

    if do_udp:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(worker_udp, p) for p in ports]
            for future in as_completed(futures):
                port, state = future.result()
                results["udp"][port] = state

    return results


def print_results(ip, results):
    """Exibe os resultados de forma organizada, semelhante à saída do nmap."""
    print(f"\n== Resultado da varredura para {ip} ==")

    for proto in ("tcp", "udp"):
        if not results[proto]:
            continue
        print(f"\nPROTOCOLO: {proto.upper()}")
        print(f"{'PORTA':<10}{'ESTADO':<15}")
        print("-" * 25)
        for port in sorted(results[proto].keys()):
            state = results[proto][port]
            print(f"{port:<10}{state:<15}")

        abertas = sum(1 for s in results[proto].values() if s == "open")
        fechadas = sum(1 for s in results[proto].values() if s == "closed")
        filtradas = sum(1 for s in results[proto].values() if "filtered" in s)
        print(f"\nResumo {proto.upper()}: {abertas} aberta(s), "
              f"{fechadas} fechada(s), {filtradas} filtrada(s)/ambígua(s)")


# ---------------------------------------------------------------------------
# Ponto de entrada (CLI)
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="pyscan - Scanner de portas TCP/UDP (clone simplificado do nmap)"
    )
    parser.add_argument("-t", "--targets", required=True,
                         help="IP(s) alvo. Ex: 192.168.0.1  ou  192.168.0.1,192.168.0.2  ou  192.168.0.0/24")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Portas a varrer. Ex: 80  ou  22,80,443  ou  1-1000 (padrão: 1-1024)")
    parser.add_argument("--tcp", action="store_true", help="Realiza varredura TCP (SYN scan)")
    parser.add_argument("--udp", action="store_true", help="Realiza varredura UDP")
    parser.add_argument("--threads", type=int, default=50,
                         help="Número de threads simultâneas por protocolo (padrão: 50)")
    parser.add_argument("--timeout", type=float, default=1.5,
                         help="Timeout de espera por resposta, em segundos (padrão: 1.5)")

    args = parser.parse_args()

    if not args.tcp and not args.udp:
        print("[ERRO] Especifique ao menos um protocolo: --tcp e/ou --udp")
        sys.exit(1)

    check_root()

    targets = parse_targets(args.targets)
    ports = parse_ports(args.ports)

    print(f"[INFO] Alvos: {len(targets)} host(s)")
    print(f"[INFO] Portas: {len(ports)}")
    print(f"[INFO] Protocolo(s): {'TCP ' if args.tcp else ''}{'UDP' if args.udp else ''}")
    print(f"[INFO] Threads: {args.threads}")

    start = time.time()

    for ip in targets:
        results = scan_target(ip, ports, args.tcp, args.udp, args.threads)
        print_results(ip, results)

    elapsed = time.time() - start
    print(f"\n[INFO] Varredura concluída em {elapsed:.2f} segundos.")


if __name__ == "__main__":
    main()
