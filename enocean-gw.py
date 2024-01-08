#!/usr/bin/env python
"""
Documents 
https://advanceddevices.com/sites/default/files/documents/EnOcean%20Radio%20Prootocol%201.pdf
https://www.enocean-alliance.org/wp-content/uploads/2020/07/EnOcean-Equipment-Profiles-3-1.pdf
"""

import serial
import crc8
import paho.mqtt.client as mqtt
import yaml
import argparse
import sys

# EnOcean sync byte
sync_byte = b'\x55'

class MQTTmessage(object):
    def __init__(self, main_topic='enocean', topic=None, sub_topic=None, msg = ""):
        self.main_topic = main_topic
        self.topic = topic
        self.sub_topic = sub_topic
        self.msg = msg

    @property
    def message(self):
        # return a tuple for MQTT, or a None if no message is ready
        topic = self.main_topic
        if self.topic:
            if topic[-1] != '/':
                topic += f'/'
            topic += f'{self.topic}'
        if self.sub_topic:
            if topic[-1] != '/':
                topic += f'/'
            topic += f'{self.sub_topic.replace(" ", "_")}'
        if self.msg:
            if topic[-1] != '/':
                topic += f'/'
            return (topic, self.msg)
        return None
    

class SensorParser(object):
    """
    See if a telegram matches any of the sensors we have setup
    and translate to a mqtt topic and value 
    """
    def __init__(self, sensors, main_topic = "enocean"):
        self.sensors = sensors
        self.main_topic = main_topic
        self.mqtt_message = MQTTmessage(main_topic=self.main_topic, topic="sensor")
        
    def process_telegram(self, telegram):
        # check telegram for a matching sender id
        if telegram.packet.sender_id in self.sensors:
            sensor = self.sensors[telegram.packet.sender_id]
            if telegram.packet.packet_type in sensor['packet_type']:
                # see if we match a configured sensor
                if 'name' in sensor:
                    sensor_name = sensor['name']
                else:
                    sensor_name = telegram.packet.sender_id.replace(":","")
                if telegram.packet.telegram_data in sensor['packet_type'][telegram.packet.packet_type]:
                    self.mqtt_message.sub_topic = sensor_name
                    self.mqtt_message.msg = sensor['packet_type'][telegram.packet.packet_type][telegram.packet.telegram_data]
                    return
                # unkown value
                self.mqtt_message.sub_topic = f"unknown_value/{sensor_name}"
                self.mqtt_message.msg = f"{hex(telegram.packet.telegram_data)}"
                return
            # unkown packet type
            if 'name' in sensor:
                sensor_name = sensor['name']
            else:
                sensor_name = telegram.packet.sender_id.replace(":","")
            self.mqtt_message.sub_topic = f"unknown_packet_type/{sensor_name}"
            self.mqtt_message.msg = f"{telegram.packet.packet_type} from {telegram.packet.sender_id}"
            return

        # report a unknown sensor sending data
        self.mqtt_message.sub_topic = 'unknown_sender'
        self.mqtt_message.msg = f"{telegram.packet.sender_id}"
        return


    @property
    def message(self):
        # return a tuple for MQTT, or a None if no message is ready
        return self.mqtt_message.message


class RadioErp1(object):
    """
    Radio Telegram with type 0x01
    """
    def __init__(self, data, optional_data):
        self.packet_type = "RADIO_ERP1"
        self.data = data
        self.optional_data = optional_data 
        self.rorg = None
        self.telegram_data = None
        self.sender_id = None
        self.status = None
        # figure out the RORG, first byte of the data
        self.rorg_id()

    def __str__(self):
        output = f"{self.packet_type}:{self.rorg}:DATA BYTE {self.telegram_data}: Sender ID {self.sender_id}"
        output += f" status: {self.status}"
        return output

    def rorg_id(self):
        if self.data[0] == 0xf6:
            self.rorg = "RPS Teach-in"
            self.process_teach_in()
        elif self.data[0] == 0xd5:
            self.rorg = "1BS Teach-in"
            self.process_teach_in()
        elif self.data[0] == 0xa5:
            self.rorg = "4BS Teach-in"
            self.process_teach_in(len=4)
        else:
            print (f"RORG UNKNOWN {self.data[0]:02x}")

    def process_teach_in(self, len=2):
        # RPA Tech in parsing
        self.telegram_data = self.data[1]  
        # turn the sender id in to a MAC like address string
        self.sender_id = ""
        for octet in self.data[-5:-1]:
           self.sender_id  += f"{octet:02x}:"
        # chop off last :
        self.sender_id = self.sender_id[0:-1]
        self.status = self.data[-1]
        

class EnoceanTelegram(object):
    """
    An Enocean Telegram
    device should be a Serial device from pyserial for reading
    """
    def __init__(self, dev):
        self.serial_device = dev
        self.header_data_length = 0x00
        self.header_optional_length = 0x00
        self.header_packet_type = 0x00
        self.header_crc8 = 0x00
        self.data = None
        self.optional_data = None
        self.crc8 = None

    def read(self):
        # read in the telegram
        self.read_header()
        try:
            self.verify_header_crc8()
        except:
            print ("Telegram Header CRC8 Fail!")
            raise Exception("CRC8 Failure in Header")
        self.read_data()
        self.read_optional_data()
        self.read_crc8()
        self.verify_crc8()
        try:
            self.verify_header_crc8()
        except:
            print ("Telegram CRC8 Fail!")
            raise Exception("CRC8 Failure")

    def read_header(self):
        # read in the 4 byte header including the crc8
        self.header_data_length = self.serial_device.read(2)  # this one is 2 bytes
        self.header_optional_length = self.serial_device.read()
        self.header_packet_type = self.serial_device.read()
        self.header_crc8 = self.serial_device.read()
        self.packet_type = None
        self.packet = None

    def read_data(self):
        # read in the data section of the telegram
        dl = int.from_bytes(self.header_data_length, 'big')
        self.data = self.serial_device.read(dl)

    def read_optional_data(self):
        # read in the optional data section of the telegram
        dl = int.from_bytes(self.header_optional_length, 'big')
        self.optional_data = self.serial_device.read(dl)

    def read_crc8(self):
        # read in the final crc8
        self.crc8 = self.serial_device.read()

    def __str__(self):
        if not self.data:
            return ""
        output = ""
        output += "[DL   | ODL | PT | CRC8 |"
        for mybyte in self.data:
           output += f"   "
        output += "| "
        for mybyte in self.optional_data:
           output += f"   "
        output += "| CRC8 ]\n"

        output += f"[{self.header_data_length.hex()} | {self.header_optional_length.hex()}  | "
        output += f"{self.header_packet_type.hex()} |  {self.header_crc8.hex()}  |"
        for mybyte in self.data:
           output += f"{mybyte:02x} "
        output += "| "
        for mybyte in self.optional_data:
           output += f"{mybyte:02x} "
        output += f"| {self.crc8.hex()}   ]\n"
        return output

    def calc_header_crc8(self):
        # calc crc8 for the header data
        hash = crc8.crc8()
        header = self.header_data_length + self.header_optional_length + self.header_packet_type
        hash.update( header)
        return hash.digest()

    def verify_header_crc8(self):
        assert self.calc_header_crc8() == self.header_crc8

    def verify_crc8(self):
        assert self.calc_crc8() == self.crc8

    def calc_crc8(self):
        # calc crc8 for the data fields
        hash = crc8.crc8()
        if int.from_bytes(self.header_data_length, 'big') > 0:
            telegram_data = self.data
            if int.from_bytes(self.header_optional_length, 'big') > 0:
                telegram_data  += self.optional_data
        hash.update(telegram_data)
        return hash.digest()
 
    def process(self):
        # process the telegram based on the packet type
        self.packet_type_id()
        print (self.packet)

    def packet_type_id(self):
        # id the telegram type from the PT header
        if self.header_packet_type == b'\01':
            # RADIO_ERP1
            self.packet_type = "RADIO_ERP1"
            self.packet = RadioErp1(self.data, self.optional_data)
            return self.packet_type
        # dont know (or care) what it is yet
        raise Exception(f"Unknown Packet type: {self.packet_type.hex()}")
    
def on_connect(client, userdata, flags, rc):
    print("MQTT Connected with result code "+str(rc))

def on_disconnect(client, userdata, rc):
    if rc != 0:
        print("MQTT Unexpected disconnection.")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic+" "+str(msg.payload))

def main():
    try:
        client.connect(config['mqtt_server'], config['mqtt_port'], 60)
    except ConnectionRefusedError as err:
        print (f"Connection Refused to {config['mqtt_server']} on port {config['mqtt_port']} - will auto reconnect")
    client.loop_start()
    client.publish("enocean/status", "UP")
    with serial.Serial(config['enocean_device'], 57200) as ser:
        while True:
            # listen for sync byte
            if not client.is_connected():
                print (f"WARNING: MQTT Connection {config['mqtt_server']}:{config['mqtt_port']} not active!")
            mybyte = ser.read()
            if mybyte == sync_byte:
                # print ("SYNC:", mybyte.hex())
                telegram = EnoceanTelegram(ser)
                try:
                    telegram.read()
                    telegram.process()
                    sensors.process_telegram(telegram)
                except Exception as err:
                    print (f"Telgram issue: {err}")
                    #client.publish("enocean/crc8", f"{err}")
                if sensors.mqtt_message.message:
                    print (telegram)
                    print ("PUBLISH:", sensors.mqtt_message.message[0], sensors.mqtt_message.message[1])
                    client.publish(sensors.mqtt_message.message[0], sensors.mqtt_message.message[1])
                client.publish("enocean/telegram", str(telegram))
            else:
                client.publish("enocean/debug", str("EXTRANDOUS CRAP"))
        

if __name__ == "__main__":
    print ("EnOcean to MQTT Gateway")

    parser = argparse.ArgumentParser(
                    prog='Simple EnOcean to MQTT Gateway',
                    description='Tranlates EnOcean events into MQTT mesages',
                    epilog='This is as lightweight as possible without being too litlle.')

    parser.add_argument('config_file', help="YAML based config file to use")
    args = parser.parse_args()
 
    # load config
    with open(args.config_file, 'r') as fd:
        config = yaml.safe_load(fd)

    if 'client_id' in config:
        client_id = config['client_id']
    else:
        client_id = "enocean-mqtt-gw"
    client = mqtt.Client(client_id=client_id)
    if config['mqtt_username'] and config['mqtt_password']:
        client.username_pw_set(username=config['mqtt_username'], password=config['mqtt_password'])
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    # sensor parser
    with open(config['sensors_file'], 'r') as fd:
        sensor_data = yaml.safe_load(fd)
    sensors = SensorParser(sensor_data)
    
    main()
   


