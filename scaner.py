#!/bin/env python3
import click
import datetime
import nmap
import nvdlib
import os
import re
import sys


class Host:
    def __init__(self, ip_address):
        self.address = ip_address
        self.services = []


class Service:
    def __init__(self, port, protocol, state, name, product, version):
        self.port = port
        self.protocol = protocol
        self.state = state
        self.name = name
        self.product = product
        self.version = version
        self.vulnerabilities = []


def log(msg):
    logfile = "logfile.log"
    try:
        file = open(logfile, 'a')
    except OSError:
        print("[ERROR] Could not open file:", logfile)
        sys.exit(1)
    print(f"{datetime.datetime.now()}: {msg}")
    file.write(f"{datetime.datetime.now()}: {msg}\n")
    file.close()


def read_hosts(input_file):
    ip_pattern = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    hosts = []

    try:
        file = open(input_file, 'r')
    except FileNotFoundError:
        log(f"[ERROR] Could not open file: {input_file}")
        sys.exit(1)
    ips = file.read().splitlines()
    file.close()

    for index, ip in enumerate(ips):
        if re.search(ip_pattern, ip):
            hosts.append(Host(ip))
        else:
            log(f"[LOG] Invalid ip: {ip} (file: {input_file}, line: {index+1})")

    return hosts


def nmap_scan(hosts, ports_range, params):
    nm = nmap.PortScanner()
    for i in range(len(hosts)):
        log(f"[LOG] {hosts[i].address}: Scanning... ")
        result = nm.scan(hosts[i].address, ports_range, params)
        if "-sT" in params:
            hosts[i] = nmap_result_handling(hosts[i], result, "tcp")
        if "-sU" in params:
            hosts[i] = nmap_result_handling(hosts[i], result, "udp")
    return hosts


def nmap_result_handling(host, result, protocol):
    try:
        services = result['scan'][host.address][protocol]
        log(f"[LOG] {host.address}: {protocol} open ports found: {len(services)}")
        for port in services:
            host.services.append(
                Service(port, protocol, services[port]["state"],
                        services[port]["name"], services[port]["product"], services[port]["version"]))
    except Exception:
        log(f"[LOG] {host.address}: no {protocol} open ports found")
    return host


def list_vulns(hosts):
    for host in hosts:
        for service in host.services:
            if service.version == "" or service.product == "":
                log(f"[LOG] {host.address}:{service.port}: {service.name}: no specific product or version")
                continue
            log(
                f"[LOG] {host.address}:{service.port}: {service.name}:{service.product}:{service.version}:"
                f" searching of vulnerability")
            vulns = nvdlib.searchCVE(service.product + ' ' + service.version)
            for vuln in vulns:
                service.vulnerabilities.append(vuln)
    return hosts


def save_output(hosts, out_file):
    log(f"[LOG] Save output: {out_file}")
    try:
        csvfile = open(out_file, 'a')
    except OSError:
        log(f"[ERROR] Could not open file: {out_file}")
        sys.exit(1)
    for host in hosts:
        if len(host.services) == 0:
            csvfile.write(f"HOST: {host.address};\n")
            continue
        for service in host.services:
            if len(service.vulnerabilities) == 0:
                csvfile.write(f"HOST: {host.address};"
                              f"PORT: {service.port}:{service.protocol}:{service.state};"
                              f"SERVICE: {service.name}:{service.product}:{service.version};\n")
                continue
            for vuln in service.vulnerabilities:
                csvfile.write(f"HOST: {host.address};"
                              f"PORT: {service.port}:{service.protocol}:{service.state};"
                              f"SERVICE: {service.name}:{service.product}:{service.version};"
                              f"{vuln.id};{vuln.score[1]}:{vuln.score[2]};{vuln.url};\n")
    csvfile.close()


def params_handler(port_floor, port_ceil, tcp, udp, ver, min_rate):
    if port_ceil < port_floor or not 0 < port_floor <= 65535 or not 0 < port_ceil <= 65535:
        log(f"[ERROR] invalid port range {port_floor}-{port_ceil}")
        sys.exit(1)
    ports = str(port_floor) + "-" + str(port_ceil)

    params = " -sV "
    if ver:
        params += " --version-all "
    params += f" --min-rate {min_rate} "

    if udp and os.geteuid() != 0:
        log("[ERROR] to use udp scan root privileges are required")
        sys.exit(1)
    if not udp and not tcp:
        log("[ERROR] tcp and udp scan is disabled")
        sys.exit(1)

    if udp:
        params += " -sU "
    if tcp:
        params += " -sT "

    log(f"[LOG] Nmap settings: PORTS: {ports}, PARAMS: {params}")
    return ports, params


@click.group()
def cli():
    pass


@cli.command()
@click.option('--input_path', '-i', default="lista_hostow", show_default=True, help='Path to file with hosts ips')
@click.option('--output_path', '-o', default="output.csv", show_default=True, help='Output file path')
@click.option('--port_floor', '-f', default="1", show_default=True, type=int, help='Lower limit of scanned ports')
@click.option('--port_ceil', '-c', default="1000", show_default=True, type=int, help='Upper limit of scanned ports')
@click.option('--min_rate', '-r', show_default=True, default=3, help="Send packets no slower than <number> per second")
@click.option('--regular_save', '-s', is_flag=True, show_default=True, default=False,
              help="Save result after each host scan")
@click.option('--tcp_scan', '-t', is_flag=True, show_default=True, default=False,
              help="Enable tcp scan")
@click.option('--udp_scan', '-u', is_flag=True, show_default=True, default=False,
              help="Enable udp scan (root privileges are required)")
@click.option('--versions', '-v', is_flag=True, show_default=True, default=False,
              help="Enable enhanced version scanning")
def scan(input_path, output_path, port_floor, port_ceil, regular_save, tcp_scan, udp_scan, versions, min_rate):
    log("[LOG] START")
    ports, params = params_handler(port_floor, port_ceil, tcp_scan, udp_scan, versions, min_rate)

    hosts = read_hosts(input_path)
    if regular_save:
        for host in hosts:
            host = nmap_scan([host], ports, params)[0]
            host = list_vulns([host])[0]
            save_output([host], output_path)
    else:
        hosts = nmap_scan(hosts, ports, params)
        hosts = list_vulns(hosts)
        save_output(hosts, output_path)

    log("[LOG] FINISH")


cli.add_command(scan)

if __name__ == '__main__':
    cli()

