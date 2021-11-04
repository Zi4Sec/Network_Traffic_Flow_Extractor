import pyshark
from PyQt5.QtCore import pyqtSignal, QThread, QObject, QThreadPool
from flow_handler import FlowHandler


def sum_octets(ip):  # OK
    # 192.168.1.1 -> 192+168+1+1
    output = 0
    octets = ip.split('.')
    for o in octets:
        output = int(o) + output
    return output


def calculate_flow_id(pkt):  # OK
    flow_id = 0
    try:
        if hasattr(pkt, 'tcp'):
            # print(pkt.ip.src + ', ' + pkt.ip.dst + ', ' + pkt.tcp.srcport + ', ' + pkt.tcp.dstport + ', TCP')
            flow_id = sum_octets(pkt.ip.src) + sum_octets(pkt.ip.dst) + int(pkt.tcp.srcport) + int(pkt.tcp.dstport) + 1
            # print('flow_id ' + str(flow_id))
            return flow_id

        if hasattr(pkt, 'udp'):
            # print(pkt.ip.src + ', ' + pkt.ip.dst + ', ' + pkt.udp.srcport + ', ' + pkt.udp.dstport + ', UDP')
            flow_id = sum_octets(pkt.ip.src) + sum_octets(pkt.ip.dst) + int(pkt.udp.srcport) + int(pkt.udp.dstport)
            # print('flow_id ' + str(flow_id))
            return flow_id

    except Exception as e:
        print("Oops!( in calculate_flow_id)", e.__class__, "occurred.")


class TrafficManager(QObject):
    new_packet_signal = pyqtSignal(dict)

    def __init__(self, time, nic):
        super(TrafficManager, self).__init__()
        self.time = time
        self.nic = nic
        self.pool = QThreadPool()  # Create a thread pool
        self.pool.globalInstance()  # Get this global thread pool
        self.pool.setMaxThreadCount(QThread.idealThreadCount())
        self.flow_id_list = set()
        # self.flow_id = 0
        self.fh = None

    def packet_receiver(self):
        try:
            capture = pyshark.LiveCapture(interface=self.nic, display_filter="ip")
            capture.sniff(timeout=self.time)

            for pkt in capture:
                flow_id = calculate_flow_id(pkt)
                # print(self.flow_id)
                if (len(self.flow_id_list) == 0) or (not (flow_id in self.flow_id_list)):
                    # create a new flow handler for this new packet
                    self.fh = FlowHandler(flow_id, pkt)
                    self.pool.start(self.fh)
                else:  # send the new packet to an existing flow handler
                    self.new_packet_signal.connect(self.fh.worker.handle_new_incoming_packet) # new
                    if 'FIN' in pkt.tcp.flags.showname_value:
                        print('FIN-1 ', flow_id)
                    self.new_packet_signal.emit({'flow_id': flow_id, 'new_pkt': pkt})

                self.flow_id_list.add(flow_id)

            self.pool.waitForDone()
        except Exception as e:
            print("Oops!( in packet_receiver)", e.__class__, "occurred.")