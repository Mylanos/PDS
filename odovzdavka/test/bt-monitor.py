#!/usr/bin/python
# -*- coding: utf-8 -*-
import argparse
import os
import subprocess
import pandas as pd
import socket

class Neighbour:
    def __init__(self, ip, id, port) -> None:
        self.ip = ip
        self.id = id
        self.port = port
        self.connections = []
        self.num_of_connections = 0

    def update_num_of_connections(self):
        self.num_of_connections += 1
    
    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, Neighbour):
            return False
        return self.ip == __o.ip and self.id == __o.id and self.port == __o.port

    def __str__(self):
        return f"(ip={self.ip}, id={self.id}, port={self.port}, num_of_connections={self.num_of_connections})"

    def check_connection(self, src, dst, tx_id):
        if(self.ip == src or self.ip == dst):
            if(tx_id not in self.connections):
                self.connections.append(tx_id)
                self.num_of_connections += 1
                return tx_id
        else:
            return None

class BTMonitor:

    def __init__(
        self,
        modes=None,
        dns_data=None,
        bt_dht_data=None,
        ):
        self.modes = modes
        self.dns_data = dns_data
        self.bt_dht_data = bt_dht_data
        self.known_bootstrap_nodes = ['router.utorrent.com',
                'router.bittorrent.com', 'dht.transmissionbt.com',
                'router.bitcomet.com', 'dht.aelitis.com']
        self.bootstrap_nodes = []
        self.neighbours = []

        # received pcap -> convert to csv

    def run(self):
        if self.modes.init:
            self.init_mode()
            for item in self.bootstrap_nodes:
                print(item)
        elif self.modes.peers:
            self.peers_mode()
            for item in self.neighbours:
                print(item)
        elif self.modes.downloaded:
            print('This command is not yet supported')
        elif self.modes.rtable:
            print('This command is not yet supported')
        else:
            print('Unexpected error handling BTMonitor mode')
            exit(1)

    def init_mode(self):
        [
            'udp_dstport',
            'dns_resp_name',
            'dns_qry_type',
        ]            
        for (index, row) in self.dns_data.iterrows():
            if row['dns_qry_type'] == 1 and row['dns_qry_name'] \
                in self.known_bootstrap_nodes:
                try:
                    # try to get IP address of bootstrap node
                    info = socket.getaddrinfo(row['dns_qry_name'], row["udp_dstport"])
                    for tuple in info:
                        tmp_ip = str(tuple[4][0])
                        tmp_port = str(tuple[4][1])
                        if(tmp_port == '53'):
                            continue
                        if (tmp_ip, tmp_port) not in self.bootstrap_nodes:
                            self.bootstrap_nodes.append((tmp_ip, tmp_port))
    
                except socket.gaierror:
                    print('Internal error occured!')
                    exit(1)
    
    def peers_mode(self):
        # Decode the string using Bencode library
        for (index, row) in self.bt_dht_data.iterrows():
            # get all the 
            if(type(row['bt_dht_ip']) is not float and type(row['bt_dht_id']) is not float and type(row['bt_dht_port']) is not float):
                ip_adresses = row['bt_dht_ip'].split(',')
                ids = row['bt_dht_id'].split(',')
                ports = row['bt_dht_port'].split(',')
                for ip, id, port in zip(ip_adresses, ids, ports):
                    neighbour = Neighbour(ip, id, port)
                    if neighbour not in self.neighbours:
                        self.neighbours.append(neighbour)
            if(type(row['bt_dht_bencoded_string']) is not float):
                bencoded_string_split = row['bt_dht_bencoded_string'].split(',')
                tx_id = bencoded_string_split[-5]
                for neighbour in self.neighbours:
                    if(len(tx_id) < 5):
                        if(neighbour.check_connection(row['ipsrc'], row['ipdst'], tx_id) is not None):
                            break
                    

    def rtable_mode(self):
        pass

    def downloaded_mode(self):
        pass


class PreProcessor:

    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='bt-monitor.py',
                description='BT communication detection tool',
                epilog='Good luck warrior')
        self.csv = None
        self.csv_folder = './csvs'
        self.pcap_folder = './pcaps'
        self.bittorr_data = {}
        self.dns_data = {}
        self.set_args()
        self.preprocess()

    def set_args(self):
        group1 = self.parser.add_mutually_exclusive_group(required=True)
        group1.add_argument('-pcap',
                            help='specifies that the input is from pcap file passed in the following argument'
                            )
        group1.add_argument('-csv',
                            help='specifies that the input is from csv file passed in the following argument'
                            )
        group2 = self.parser.add_mutually_exclusive_group(required=True)
        group2.add_argument('-init',
                            help='returns a list of detected bootstrap nodes (IP, port)'
                            , action='store_true')
        group2.add_argument('-peers',
                            help='returns a list of detected neighbors (IP, port, node ID, # of conn)'
                            , action='store_true')
        group2.add_argument('-downloaded',
                            help='returns file info_hash, size, chunks, contributes (IP+port), UNSUPPORTED'
                            , action='store_true')
        group2.add_argument('-rtable',
                            help='returns the routing table of the client (node IDs, IP, ports), UNSUPPORTED'
                            , action='store_true')

        self.parser = self.parser.parse_args()

    def convert_pcap_to_csv(self):

        # execute the tshark command and store the output as a pandas datafram

        csv_path = self.csv_folder + '/' + self.parser.pcap[6:-7]

            
        if not self.file_exists(csv_path + '_DNS.csv'):
            command_dns = [
                'tshark',
                '-r', self.parser.pcap,
                '-T', 'fields',
                '-E', 'separator=;',
                '-e', 'udp.dstport',
                '-e', 'dns.qry.name',
                '-e', 'dns.qry.type',
                '-Y', 'dns',
            ]

            self.csv = subprocess.run(command_dns, capture_output=True,
                    text=True)
            with open(csv_path + '_DNS.csv', 'w') as f:
                subprocess.run(command_dns, text=True, stdout=f)
        if not self.file_exists(csv_path + '_BTDHT.csv'):
            command_bt_dht = [
                'tshark',
                '-r', self.parser.pcap,
                '-T', 'fields',
                '-E', 'separator=;',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'bt-dht.ip',
                '-e', 'bt-dht.id',
                '-e', 'bt-dht.port',
                '-e', 'bt-dht.bencoded.string',
                '-d', 'udp.port==1024-65535,bt-dht',
                ]

            self.csv = subprocess.run(command_bt_dht, capture_output=True,
                    text=True)
            with open(csv_path + '_BTDHT.csv', 'w') as f:
                subprocess.run(command_bt_dht, text=True, stdout=f)
        
        self.dns_data = pd.read_csv(csv_path + '_DNS.csv', delimiter=';'
                                    , names=[
            'udp_dstport',
            'dns_qry_name',
            'dns_qry_type',
            ])
        self.bt_dht_data = pd.read_csv(csv_path + '_BTDHT.csv',
                delimiter=';', names=[
            'ipsrc',
            'ipdst',
            'bt_dht_ip',
            'bt_dht_id',
            'bt_dht_port',
            'bt_dht_bencoded_string',
            ])

    def load_csv(self):
        self.bittorr_data = pd.read_csv(self.parser.csv, delimiter=';',
                names=[
            'time_relative',
            'ipsrc',
            'ipdst',
            'tcp_srcport',
            'tcp_dstport',
            'bittorrent_protocol',
            'bittorrent_infohash',
            'bittorrent_msg',
            'bittorrent_msg_type',
            'bittorrent_piece_index',
            'bittorrent_piece_begin',
            'bittorrent_piece_length',
            'bittorrent_port',
            ])

    def write_to_csv(self):
        with open('example.csv', 'w') as f:
            f.write(self.csv)

    def file_exists(self, filename):
        return os.path.isfile(filename)

    def preprocess(self):
        if self.parser.pcap is not None:
            if not self.file_exists(self.parser.pcap):
                print('ERROR: file doesnt exist')
                exit(1)
            self.convert_pcap_to_csv()
        elif self.parser.csv is not None:
            if not self.file_exists(self.parser.csv):
                print('ERROR: file doesnt exist')
                exit(1)
            self.load_csv()


if __name__ == '__main__':
    preprocessor = PreProcessor()
    BT_monitor = BTMonitor(preprocessor.parser,
                           preprocessor.dns_data,
                           preprocessor.bt_dht_data)
    BT_monitor.run()
