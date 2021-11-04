from PyQt5.QtCore import QRunnable, pyqtSignal
from worker import Worker


class FlowHandler(QRunnable):

    def __init__(self, flow_id, pkt):
        super(FlowHandler, self).__init__()
        self.pkt = pkt
        self.flow_id = flow_id
        self.worker = Worker(self.flow_id, self.pkt)

    def run(self):
        self.worker.start()

