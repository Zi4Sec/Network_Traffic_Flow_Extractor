
from traffic_manager import TrafficManager

if __name__ == '__main__':
    _time = 5  # 5 minutes
    nic = 'en0'
    try:
        print("Lets go...")
        traffic_manager = TrafficManager(_time, nic)
        traffic_manager.packet_receiver()
    except Exception as e:
        print("Oops!", e.__class__, "occurred.")

