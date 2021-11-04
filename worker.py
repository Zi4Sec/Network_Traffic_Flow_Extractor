from PyQt5.QtCore import pyqtSlot, QThread


class Worker(QThread):
    def __init__(self, flow_id, pkt):
        super(Worker, self).__init__()
        self.flow_id = flow_id
        self.pkt = pkt
        self.src_ip = ''
        self.destination_ip = ''
        self.src_port = 0
        self.destination_port = 0
        self.protocol = ''
        self.flow_start_time = 0.000000000
        self.flow_end_time = 0.000000000
        self.flow_sent_bytes = 0
        self.flow_recv_bytes = 0
        self.flow_total_bytes_header_in_forward = 0

    def run(self):
        # process the first packet of a flow
        # get flags
        if hasattr(self.pkt, 'tcp'):
            flags_string = self.pkt.tcp.flags.showname
            # print(flags_string)
            # if it is the first packet, set the start time of flow
            if 'SYN' in flags_string:  # this is the first packet of flow
                print('-------------BEGIN OF A TCP FLOW-----------------')
                self.flow_start_time = ("%.9f" % self.pkt.sniff_time.timestamp())
                print('start time ' + str(self.flow_start_time))
                # set 5 tuples
                self.extract_flow_5_tuple()
                self.save_into_csv_file(0)
            # else:
            #     print('this packet should be handled well')

        elif hasattr(self.pkt, 'udp'):
            print('-------------BEGIN OF A UDP FLOW-----------------')
            self.flow_start_time = ("%.9f" % self.pkt.sniff_time.timestamp())
            print('start time ' + str(self.flow_start_time))
            # set 5 tuples
            self.extract_flow_5_tuple()
            self.save_into_csv_file(0)

    def extract_flow_5_tuple(self):  # OK
        self.src_ip = str(self.pkt.ip.src)
        self.destination_ip = str(self.pkt.ip.dst)
        if hasattr(self.pkt, 'tcp'):
            self.src_port = int(self.pkt.tcp.srcport)
            self.destination_port = int(self.pkt.tcp.dstport)
            self.protocol = 'TCP'
        if hasattr(self.pkt, 'udp'):
            self.src_port = int(self.pkt.udp.srcport)
            self.destination_port = int(self.pkt.udp.dstport)
            self.protocol = 'UDP'

    @pyqtSlot(dict)
    def handle_new_incoming_packet(self, dictionary):  # process the other packets of a flow
        flow_id = dictionary['flow_id']
        pkt = dictionary['new_pkt']

        if flow_id == self.flow_id and hasattr(pkt, 'tcp'):
            flag_list = self.pkt.tcp.flags.showname
            # print(flag_list)
            # print(self.src_ip, ' ', str(pkt.ip.src))
            if 'FIN' in flag_list or 'RST' in flag_list:  # this is the last packet of flow
                print('-----------------------------------END OF A FLOW----------------------')
                self.flow_end_time = ("%.9f" % pkt.sniff_time.timestamp())
                flow_duration = self.get_flow_duration()
                print('flow_duration ' + str(flow_duration))
                self.save_into_csv_file(flow_duration)
                # self.quit()
            elif self.src_ip == str(pkt.ip.src) and 'tcp.payload' in pkt.tcp._all_fields:  # Forward Direction
                # get number of the sent bytes by this packet
                self.flow_sent_bytes = self.flow_sent_bytes + len(pkt.tcp.payload)
                # print('until now, for flow_id ' + str(flow_id) + ' flow_sent_bytes is ' + str(self.flow_sent_bytes))
                # self.flow_total_bytes_header_in_forward = self.flow_total_bytes_header_in_forward + x
            elif self.src_ip != str(pkt.ip.src) and 'tcp.payload' in pkt.tcp._all_fields:  # Backward Direction
                # get number of the received bytes by this packet
                self.flow_recv_bytes = self.flow_recv_bytes + len(pkt.tcp.payload)
                # print('until now, for flow_id ' + str(flow_id) +' flow_recv_bytes is ' + str(self.flow_recv_bytes))
            # else:
            #     print('src_ip', self.src_ip, 'new_packet_src_ip', str(pkt.ip.src))
            # elif ('ACK' in flag_list):
            #     if hasattr(self.pkt, 'tcp'):
            #         print('++++++++++++++++++++++++++++++' + str(len(pkt.tcp.payload)))
        # elif flow_id == self.flow_id and hasattr(self.pkt, 'udp'):
        #     print('UDP=========================')
        # else:
        #     if hasattr(self.pkt, 'tcp'):
        #         print('--------------TCP--------------')
        #     else:
        #         print('--------------UDP--------------')

    def get_flow_duration(self):  # OK
        return float(self.flow_end_time) - float(self.flow_start_time)

    def save_into_csv_file(self, flow_duration):
        file = open('output.csv', 'a')
        newline = self.src_ip + ', ' + self.destination_ip + ', ' + str(self.src_port) + ', ' + \
                  str(self.destination_port) + ', ' + self.protocol + ', ' + str(flow_duration) + ', ' + \
                  str(self.flow_sent_bytes) + ', ' + str(self.flow_recv_bytes) + ', ' + \
                  str(self.flow_total_bytes_header_in_forward) + '\n'
        print(newline)
        file.write(newline)
        file.close()
