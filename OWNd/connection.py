""" This module handles connections to the OpenWebNet gateway """

import socket
import asyncio
import serial_asyncio

import hmac
import hashlib
import string
import random
import logging
from typing import Union
from urllib.parse import urlparse

from .discovery import find_gateways, get_gateway, get_port
from .message import OWNMessage, OWNSignaling, OWNGatewayEvent

_logger = logging.getLogger("OWNd")


class OWNGateway:
    def __init__(self, discovery_info: dict):
        # Attributes potentially provided by user
        self.address = (
            discovery_info["address"] if "address" in discovery_info else None
        )
        self._password = (
            discovery_info["password"] if "password" in discovery_info else None
        )
        # Attributes retrieved from SSDP discovery
        self.ssdp_location = (
            discovery_info["ssdp_location"]
            if "ssdp_location" in discovery_info
            else None
        )
        self.ssdp_st = (
            discovery_info["ssdp_st"] if "ssdp_st" in discovery_info else None
        )
        # Attributes retrieved from UPnP device description
        self.device_type = (
            discovery_info["deviceType"] if "deviceType" in discovery_info else None
        )
        self.friendly_name = (
            discovery_info["friendlyName"] if "friendlyName" in discovery_info else None
        )
        self.manufacturer = (
            discovery_info["manufacturer"]
            if "manufacturer" in discovery_info
            else "BTicino S.p.A."
        )
        self.manufacturer_url = (
            discovery_info["manufacturerURL"]
            if "manufacturerURL" in discovery_info
            else None
        )
        self.model_name = (
            discovery_info["modelName"]
            if "modelName" in discovery_info
            else "Unknown model"
        )
        self.model_number = (
            discovery_info["modelNumber"] if "modelNumber" in discovery_info else None
        )
        # self.presentationURL = (
        #     discovery_info["presentationURL"]
        #     if "presentationURL" in discovery_info
        #     else None
        # )
        self.serial_number = (
            discovery_info["serialNumber"] if "serialNumber" in discovery_info else None
        )
        self.udn = discovery_info["UDN"] if "UDN" in discovery_info else None
        # Attributes retrieved from SOAP service control
        self.port = discovery_info["port"] if "port" in discovery_info else None

        # Attributes for zigbee
        self._is_zigbee = (
            discovery_info["isZigbee"] if "isZigbee" in discovery_info else False
        )
        self._serial_port = (
            discovery_info["serialPort"] if "serialPort" in discovery_info else False
        )

        path = self._serial_port if self.is_zigbee else self.host
        self._log_id = f"[{self.model_name} gateway - {path}]"


    @property
    def is_zigbee(self) -> bool:
        return self._is_zigbee

    @is_zigbee.setter
    def is_zigbee(self, is_zigbee: bool) -> None:
        self._is_zigbee = is_zigbee

    @property
    def serial_port(self) -> bool:
        return self._serial_port

    @serial_port.setter
    def is_zigbee(self, serial_port: str) -> None:
        self._serial_port = serial_port

    @property
    def unique_id(self) -> str:
        return self.serial_number

    @unique_id.setter
    def unique_id(self, unique_id: str) -> None:
        self.serial_number = unique_id

    @property
    def host(self) -> str:
        return self.address

    @host.setter
    def host(self, host: str) -> None:
        self.address = host

    @property
    def firmware(self) -> str:
        return self.model_number

    @firmware.setter
    def firmware(self, firmware: str) -> None:
        self.model_number = firmware

    @property
    def serial(self) -> str:
        return self.serial_number

    @serial.setter
    def serial(self, serial: str) -> None:
        self.serial_number = serial

    @property
    def password(self) -> str:
        return self._password

    @password.setter
    def password(self, password: str) -> None:
        self._password = password

    @property
    def log_id(self) -> str:
        return self._log_id

    @log_id.setter
    def log_id(self, id: str) -> None:
        self._log_id = id

    @classmethod
    async def get_first_available_gateway(cls, password: str = None):
        local_gateways = await find_gateways()
        local_gateways[0]["password"] = password
        return cls(local_gateways[0])

    @classmethod
    async def find_from_address(cls, address: str):
        if address is not None:
            return cls(await get_gateway(address))
        else:
            return await cls.get_first_available_gateway()

    @classmethod
    async def build_from_discovery_info(cls, discovery_info: dict):
        if (
            ("address" not in discovery_info or discovery_info["address"] is None)
            and "ssdp_location" in discovery_info
            and discovery_info["ssdp_location"] is not None
        ):
            discovery_info["address"] = urlparse(
                discovery_info["ssdp_location"]
            ).hostname

        if "port" in discovery_info and discovery_info["port"] is None:
            if (
                "ssdp_location" in discovery_info
                and discovery_info["ssdp_location"] is not None
            ):
                discovery_info["port"] = await get_port(discovery_info["ssdp_location"])
            elif "address" in discovery_info and discovery_info["address"] is not None:
                return await cls.find_from_address(discovery_info["address"])
            else:
                return await cls.get_first_available_gateway(
                    password=discovery_info["password"]
                    if "password" in discovery_info
                    else None
                )

        return cls(discovery_info)


class ZigbeeOWNGateway(OWNGateway):
    def __init__(self, discovery_info: dict):
        discovery_info["serialPort"] = discovery_info["serialPort"] if "serialPort" in discovery_info else None
        discovery_info["address"] = "localhost"
        discovery_info["isZigbee"] = True
        discovery_info["deviceType"] = "BT-3578/LG-088328"
        discovery_info["friendlyName"] = "Zigbee - Interface OPEN/Zigbee"
        discovery_info["manufacturer"] = "BTicino S.p.A. / Legrand"
        discovery_info["modelName"] = "BT-3578/LG-088328"
        super().__init__(discovery_info)

    @classmethod
    async def build_from_discovery_info(cls, discovery_info: dict):
        return cls(discovery_info)

class zigbeeSession:

    SEPARATOR = "##".encode()

    def __init__(self, gateway: OWNGateway = None, logger: logging.Logger = None):
        self._gateway = gateway
        self._logger = logger
        self.event = asyncio.Event()
        #annotations for stream reader/writer:
        self._streamReaderSerial: asyncio.StreamReader
        self._streamWriterSerial: asyncio.StreamWriter
        self._streamReaderCmd: asyncio.StreamReader
        self._streamWriterCmd: asyncio.StreamWriter
        self._streamWriterEvent: asyncio.StreamWriter
        self.invertedCover: bool
        self.buggyDim: bool
        # init them to None:
        self._streamReaderCmd = None
        self._streamWriterCmd = None
        self._streamWriterEvent = None
        self.firmware = None
        self.invertedCover = False
        self.buggyDim = False
        self.dimReq = None
        self.receiver = None
        self.command = None
        self.server = None

    async def connect(self) -> dict:
        (
            self._streamReaderSerial,
            self._streamWriterSerial,
        ) = await serial_asyncio.open_serial_connection(url=self._gateway._serial_port, baudrate=19200)

        dict = await self._negotiate()
        if dict["Success"] is not True:
            return dict
        
        dict = await self._serial_configure()
        if dict["Success"] is not True:
            return dict
        
        #open server socket for event / command
        self.server = await asyncio.start_server( client_connected_cb = self.handle_client, host="localhost", port=self._gateway.port if self._gateway.port is not None else 0)
        self._logger.debug(
            "%s TCP server started on %d.", self._gateway.log_id, self.server.sockets[0].getsockname()[1]
        )
        self._gateway.port = self.server.sockets[0].getsockname()[1]
        self.receiver = asyncio.create_task(self._serial_receiver())

    async def _cmd_receiver(self):
        while True:
            try:
                self._logger.debug("waiting message...")
                raw_request = await self._streamReaderCmd.readuntil(self.SEPARATOR)
                message = raw_request.decode()
                self._logger.debug(" TCP REC receive <%s>",message)
                if message.startswith("*#"):
                    msg = OWNMessage.parse(message)
                    self.dimReq = msg.where
                else:
                    self.dimReq = None
                if self.invertedCover:
                    if message.startswith("*2*1"):
                        self._logger.debug("Fix inverted cover command Up -> Down")
                        message = message.replace("*2*1","*2*2",1)
                    elif message.startswith("*2*2"):
                        self._logger.debug("Fix inverted cover command Down -> Up")
                        message = message.replace("*2*2","*2*1",1)
                self._streamWriterSerial.write(message.encode())
                self.event.clear()
                await self._streamWriterSerial.drain()
                await self.event.wait()

            except TimeoutError:
                self._logger.debug("TCP REC Request TimeOut")
            except asyncio.IncompleteReadError:
                self._logger.warning("Connexion closed by peer.")
                break
            except asyncio.CancelledError:
                self._logger.debug("Cancel.")
                break

        self._streamWriterCmd.close()
        await self._streamWriterCmd.wait_closed()
        self._streamWriterCmd = None
        self._streamReaderCmd = None
        self._logger.info("Command connexion closed.")

    async def _serial_receiver(self):
        while True:
            try:
                self._logger.debug("waiting message...")
                raw_response = await asyncio.wait_for(self._streamReaderSerial.readuntil(self.SEPARATOR), timeout=2)
                message = raw_response.decode()
                self._logger.debug("REC receive <%s>",message)
                msg = OWNMessage.parse(message)
                if(msg is not None):                    
                    if(msg.is_event):
                        if self.invertedCover:
                            if message.startswith("*2*1"):
                                self._logger.debug("Fix inverted cover command Up -> Down")
                                message = message.replace("*2*1","*2*2",1)
                                msg = OWNMessage.parse(message)
                            elif message.startswith("*2*2"):
                                self._logger.debug("Fix inverted cover command Down -> Up")
                                message = message.replace("*2*2","*2*1",1)
                                msg = OWNMessage.parse(message)
                        if msg.where is not None and msg.where == self.dimReq:
                            if self._streamWriterCmd is not None:
                                self._streamWriterCmd.write(message.encode())
                            if self.buggyDim:
                                self._streamWriterCmd.write("*#*1##".encode())
                                self.event.set()
                                event = False
                        self._logger.debug("SERIAL REC receive event <%s>",msg.human_readable_log)
                        if self._streamWriterEvent is not None:
                            self._streamWriterEvent.write(message.encode())
                    else:
                        self._logger.debug("SERIAL REC receive message <%s>",msg.human_readable_log)
                        if self._streamWriterCmd is not None:
                            self._streamWriterCmd.write(raw_response)
                        # TODO check if there are case to not clear...
                        self.event.set()
                        event = False
                else:
                    self._logger.warning("SERIAL REC cannot translate <%s>",message)
            except TimeoutError:
                pass
            except asyncio.CancelledError:
                self._logger.debug("SERIAL REC Cancel.")
                break

        if self._streamWriterCmd is not None:
            self._streamWriterCmd.close()
            await self._streamWriterCmd.wait_closed()
        if self._streamWriterEvent is not None:
            self._streamWriterEvent.close()
            await self._streamWriterEvent.wait_closed()
            self._streamWriterEvent = None
        self._streamWriterSerial.close()
        await self._streamWriterSerial.wait_closed()
        self._streamWriterSerial = None
        self._streamReaderSerial = None
        self._logger.info("Serial connexion closed.")

    async def handle_client(self, reader : asyncio.StreamReader, writer: asyncio.StreamWriter):
        # on client connection send ACK and wait for connection type
        writer.write(f"*#*1##".encode())
        await writer.drain()
        raw_response = await reader.readuntil(self.SEPARATOR)
        resulting_message = OWNSignaling(raw_response.decode())
        self._logger.debug("%s Reply: `%s`", self._gateway.log_id, resulting_message)
        if resulting_message._type == "EVENT_SESSION":
            if self._streamWriterEvent is not None:
               self._streamWriterEvent.close()
               await self._streamWriterEvent.wait_closed()
               self._logger.debug("%s Previous Event session closed.", self._gateway.log_id)
            self._streamWriterEvent = writer
            self._logger.info("%s New Event session opened.", self._gateway.log_id)
        elif resulting_message._type == "COMMAND_SESSION":
            if self._streamWriterCmd is not None:
               self._streamWriterCmd.close()
               await self._streamWriterCmd.wait_closed()
               self.command.cancel()
               self._logger.debug("%s Previous Command session closed.", self._gateway.log_id)
            self._streamWriterCmd = writer
            self._streamReaderCmd = reader
            self._logger.info("%s New Command session opened.", self._gateway.log_id)
            self.command = asyncio.create_task(self._cmd_receiver())
        else:
            self._logger.error("%s Unexpected reply. Closing.", self._gateway.log_id)
            writer.close()        
        writer.write(f"*#*1##".encode())
        await writer.drain()

    async def _negotiate(self) -> dict:
        error = False
        error_message = None

        self._logger.debug(
            "%s Negotiating session.", self._gateway.log_id            
        )
        self._streamWriterSerial.write(f"*13*60*##".encode())
        try:
            await asyncio.wait_for(self._streamWriterSerial.drain(), timeout = 5)

            raw_response = await asyncio.wait_for(
            self._streamReaderSerial.readuntil(OWNSession.SEPARATOR),
                timeout=5,
            )
            resulting_message = OWNSignaling(raw_response.decode())
            if resulting_message.is_nack():
                self._logger.error(
                    "%s Error while opening session.", self._gateway.log_id
                )
                error = True
                error_message = "connection_refused"
            elif resulting_message.is_ack():
                self._logger.debug(
                    "%s session established successfully.",
                    self._gateway.log_id,
                )
            else:
                error = True
                error_message = "negotiation_failed"
                self._logger.debug(
                    "%s Unexpected message during negotiation: %s",
                    self._gateway.log_id,
                    resulting_message,
                )
        except asyncio.TimeoutError:
            error = True
            error_message = "communication_error"
            self._logger.error(
                "%s Keep alive test timeout.",
                self._gateway.log_id
            )
        return {"Success": not error, "Message": error_message}

    async def _serial_configure(self):
        error = False
        error_message = None
        self._logger.debug("%s Configuring session.", self._gateway.log_id)
        # check firmware version of gateway
        try:
            self._logger.debug("%s Retrieve firmware version", self._gateway.log_id)
            self._streamWriterSerial.write("*#13**16##".encode())
            await asyncio.wait_for(self._streamWriterSerial.drain(), timeout = 1)
            while True:
                raw_response = await asyncio.wait_for(
                self._streamReaderSerial.readuntil(OWNSession.SEPARATOR),
                    timeout=1,
                )
                resulting_message = OWNMessage.parse(raw_response.decode())
                if isinstance(resulting_message, OWNSignaling):
                    self._logger.debug("%s received signaling %s", self._gateway.log_id, resulting_message._human_readable_log)
                    if resulting_message.is_nack():
                        self._logger.error("%s Error while getting firmware version", self._gateway.log_id)
                        error = True
                        error_message = "cannot_get_firmware"
                        break
                    elif resulting_message.is_ack():
                        break
                else:
                    resulting_message = OWNGatewayEvent(raw_response.decode())
                    if isinstance(resulting_message, OWNGatewayEvent):
                        self._logger.debug("%s received event %s", self._gateway.log_id, resulting_message._human_readable_log)
                        if resulting_message._firmware_version is not None:
                            self.firmware = resulting_message._firmware_version
                    else:
                        self._logger.debug("%s received  %s but not translated.", self._gateway.log_id, raw_response.decode())

        except asyncio.TimeoutError:
            error = True
            error_message = "communication_error"
            self._logger.error("%s Fail to get firmware.", self._gateway.log_id)

        if error:
            return {"Success": not error, "Message": error_message}
        if self.firmware <="1.2.0":
            self.invertedCover = True
        if self.firmware <="1.2.3":
            self.buggyDim = True
        self._logger.info("%s Gateway firmware is %s (cover inverted=%s, DIM bug=%s).", self._gateway.log_id, self.firmware, self.invertedCover, self.buggyDim)
        # put gateway in supervisor mode
        try:
            self._logger.debug("%s Setting up supervisor mode", self._gateway.log_id)
            self._streamWriterSerial.write("*13*66*##".encode())
            await asyncio.wait_for(self._streamWriterSerial.drain(), timeout = 1)
            while True:
                raw_response = await asyncio.wait_for(
                self._streamReaderSerial.readuntil(OWNSession.SEPARATOR), timeout=1)

                resulting_message = OWNMessage.parse(raw_response.decode())
                if isinstance(resulting_message, OWNSignaling):
                    self._logger.debug("%s received signaling %s", self._gateway.log_id, resulting_message._human_readable_log)
                    if resulting_message.is_nack():
                        self._logger.error("%s Error while setting supervisor mode", self._gateway.log_id)
                        error = True
                        error_message = "failed_supervisor_mode"
                        break
                    elif resulting_message.is_ack():
                        self._logger.debug("%s Gateway set in supervisor mode.", self._gateway.log_id)
                        break
                else:
                    self._logger.debug("%s received  %s but not translated.", self._gateway.log_id, raw_response.decode())

        except asyncio.TimeoutError:
            error = True
            error_message = "communication_error"
            self._logger.error("%s Fail to set super visor mode.", self._gateway.log_id)

        return {"Success": not error, "Message": error_message}

    async def close(self) -> None:
        """Closes the connection to the OpenWebNet zigbee gateway"""
        # this method may be invoked on an empty instance of OWNSession, so be robust against Nones:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self._gateway.port = None
            self.command = None
        if self.command is not None:
            self.command.cancel()
            await self.command
            self.command = None
        if self.receiver is not None:
            self.receiver.cancel()
            await self.receiver
            self.receiver = None

class OWNSession:
    """Connection to OpenWebNet gateway"""

    SEPARATOR = "##".encode()

    def __init__(
        self,
        gateway: OWNGateway = None,
        connection_type: str = "test",
        logger: logging.Logger = None,
    ):
        """Initialize the class
        Arguments:
        logger: instance of logging
        gateway: OpenWebNet gateway instance
        connection_type: used when logging to identify this session
        """

        self._gateway = gateway
        self._type = connection_type.lower()
        self._logger = logger

	    # annotations for stream reader/writer and zigbee:
        self._stream_reader: asyncio.StreamReader
        self._stream_writer: asyncio.StreamWriter
        self.zb : zigbeeSession
        # init them to None:
        self._stream_reader = None
        self._stream_writer = None
        self.zb = None

    @property
    def gateway(self) -> OWNGateway:
        return self._gateway

    @gateway.setter
    def gateway(self, gateway: OWNGateway) -> None:
        self._gateway = gateway

    # password is a property inside OWNGateway... right?
    #@property
    #def password(self) -> str:
    #    return str(self._password)
    #@password.setter
    #def password(self, password: str) -> None:
    #    self._password = password

    @property
    def logger(self) -> logging.Logger:
        return self._logger

    @logger.setter
    def logger(self, logger: logging.Logger) -> None:
        self._logger = logger

    @property
    def connection_type(self) -> str:
        return self._type

    @connection_type.setter
    def connection_type(self, connection_type: str) -> None:
        self._type = connection_type.lower()

    @classmethod
    async def test_gateway(cls, gateway: OWNGateway) -> dict:
        connection = cls(gateway)
        return await connection.test_connection()

    async def test_connection(self) -> dict:
        retry_count = 0
        retry_timer = 1

        while True:
            try:
                if retry_count > 2:
                   self._logger.error(
                        "%s Test session connection still refused after 3 attempts.",
                        self._gateway.log_id,
                   )
                   return None
                
                (
                    self._stream_reader,
                    self._stream_writer,
                ) = await asyncio.open_connection(
                    self._gateway.address, self._gateway.port
                )
                break
            except ConnectionRefusedError:
                self._logger.warning(
                    "%s Test session connection refused, retrying in %ss.",
                    self._gateway.log_id,
                    retry_timer,
                )
                await asyncio.sleep(retry_timer)
                retry_count += 1
                retry_timer *= 2

        try:
            result = await self._negotiate()
            await self.close()
        except ConnectionResetError:
            error = True
            error_message = "password_retry"
            self._logger.error(
                "%s Negotiation reset while opening %s session. Wait 60 seconds before retrying.",
                self._gateway.log_id,
                self._type,
            )

            return {"Success": not error, "Message": error_message}

        return result

    async def connect(self):
        self._logger.debug("%s Opening %s session.", self._gateway.log_id, self._type)

        retry_count = 0
        retry_timer = 1
        while True:
            try:
                if retry_count > 4:
                    self._logger.error(
                        "%s %s session connection still refused after 5 attempts.",
                        self._gateway.log_id,
                        self._type.capitalize(),
                    )
                    return None
                (
                    self._stream_reader,
                    self._stream_writer,
                ) = await asyncio.open_connection(
                    self._gateway.address, self._gateway.port
                )
                return await self._negotiate()
            except (ConnectionRefusedError, asyncio.IncompleteReadError):
                self._logger.warning(
                    "%s %s session connection refused, retrying in %ss.",
                    self._gateway.log_id,
                    self._type.capitalize(),
                    retry_timer,
                )
                await asyncio.sleep(retry_timer)
                retry_count += 1
                retry_timer = retry_count * 2
            except ConnectionResetError:
                self._logger.warning(
                    "%s %s session connection reset, retrying in 60s.",
                    self._gateway.log_id,
                    self._type.capitalize(),
                )
                await asyncio.sleep(60)
                retry_count += 1

    async def close(self) -> None:
        """Closes the connection to the OpenWebNet gateway"""
        # this method may be invoked on an empty instance of OWNSession, so be robust against Nones:
        if self._stream_writer is not None:
            self._stream_writer.close()
            await self._stream_writer.wait_closed()
        if self._gateway is not None:
            self._logger.debug(
                "%s %s session closed.", self._gateway.log_id, self._type.capitalize()
            )

    async def _negotiate(self) -> dict:
        type_id = 0 if self._type == "command" else 1
        error = False
        error_message = None

        self._logger.debug(
            "%s Negotiating %s session.", self._gateway.log_id, self._type
        )

        self._stream_writer.write(f"*99*{type_id}##".encode())
        await self._stream_writer.drain()

        raw_response = await self._stream_reader.readuntil(OWNSession.SEPARATOR)
        resulting_message = OWNSignaling(raw_response.decode())
        # self._logger.debug("%s Reply: `%s`", self._gateway.log_id, resulting_message)

        if resulting_message.is_nack():
            self._logger.error(
                "%s Error while opening %s session.", self._gateway.log_id, self._type
            )
            error = True
            error_message = "connection_refused"

        raw_response = await self._stream_reader.readuntil(OWNSession.SEPARATOR)
        resulting_message = OWNSignaling(raw_response.decode())
        if resulting_message.is_nack():
            error = True
            error_message = "negotiation_refused"
            self._logger.debug(
                "%s Reply: `%s`", self._gateway.log_id, resulting_message
            )
            self._logger.error(
                "%s Error while opening %s session.", self._gateway.log_id, self._type
            )
        elif resulting_message.is_sha():
            self._logger.debug(
                "%s Received SHA challenge: `%s`",
                self._gateway.log_id,
                resulting_message,
            )
            if self._gateway.password is None:
                error = True
                error_message = "password_required"
                self._logger.warning(
                    "%s Connection requires a password but none was provided.",
                    self._gateway.log_id,
                )
                self._stream_writer.write("*#*0##".encode())
                await self._stream_writer.drain()
            else:
                if resulting_message.is_sha_1():
                    # self._logger.debug("%s Detected SHA-1 method.", self._gateway.log_id)
                    method = "sha1"
                elif resulting_message.is_sha_256():
                    # self._logger.debug("%s Detected SHA-256 method.", self._gateway.log_id)
                    method = "sha256"
                self._logger.debug(
                    "%s Accepting %s challenge, initiating handshake.",
                    self._gateway.log_id,
                    method,
                )
                self._stream_writer.write("*#*1##".encode())
                await self._stream_writer.drain()
                raw_response = await self._stream_reader.readuntil(OWNSession.SEPARATOR)
                resulting_message = OWNSignaling(raw_response.decode())
                if resulting_message.is_nonce():
                    server_random_string_ra = resulting_message.nonce
                    # self._logger.debug("%s Received Ra.", self._gateway.log_id)
                    key = "".join(random.choices(string.digits, k=56))
                    client_random_string_rb = self._hex_string_to_int_string(
                        hmac.new(key=key.encode(), digestmod=method).hexdigest()
                    )
                    # self._logger.debug("%s Generated Rb.", self._gateway.log_id)
                    hashed_password = f"*#{client_random_string_rb}*{self._encode_hmac_password(method=method, password=self._gateway.password, nonce_a=server_random_string_ra, nonce_b=client_random_string_rb)}##"  # pylint: disable=line-too-long
                    self._logger.debug(
                        "%s Sending %s session password.",
                        self._gateway.log_id,
                        self._type,
                    )
                    self._stream_writer.write(hashed_password.encode())
                    await self._stream_writer.drain()
                    try:
                        raw_response = await asyncio.wait_for(
                            self._stream_reader.readuntil(OWNSession.SEPARATOR),
                            timeout=5,
                        )
                        resulting_message = OWNSignaling(raw_response.decode())
                        if resulting_message.is_nack():
                            error = True
                            error_message = "password_error"
                            self._logger.error(
                                "%s Password error while opening %s session.",
                                self._gateway.log_id,
                                self._type,
                            )
                        elif resulting_message.is_nonce():
                            # self._logger.debug(
                            #     "%s Received HMAC response.", self._gateway.log_id
                            # )
                            hmac_response = resulting_message.nonce
                            if hmac_response == self._decode_hmac_response(
                                method=method,
                                password=self._gateway.password,
                                nonce_a=server_random_string_ra,
                                nonce_b=client_random_string_rb,
                            ):
                                # self._logger.debug(
                                #     "%s Server identity confirmed.", self._gateway.log_id
                                # )
                                self._stream_writer.write("*#*1##".encode())
                                await self._stream_writer.drain()
                                self._logger.debug(
                                    "%s Session established successfully.", self._gateway.log_id
                                )
                            else:
                                self._logger.error(
                                    "%s Server identity could not be confirmed.",
                                    self._gateway.log_id,
                                )
                                self._stream_writer.write("*#*0##".encode())
                                await self._stream_writer.drain()
                                error = True
                                error_message = "negociation_error"
                                self._logger.error(
                                    "%s Error while opening %s session: HMAC authentication failed.",
                                    self._gateway.log_id,
                                    self._type,
                                )
                    except asyncio.IncompleteReadError:
                        error = True
                        error_message = "password_error"
                        self._logger.error(
                            "%s Password error while opening %s session.",
                            self._gateway.log_id,
                            self._type,
                        )
                    except asyncio.TimeoutError:
                        error = True
                        error_message = "password_error"
                        self._logger.error(
                            "%s Password timeout error while opening %s session.",
                            self._gateway.log_id,
                            self._type,
                        )
        elif resulting_message.is_nonce():
            self._logger.debug(
                "%s Received nonce: `%s`", self._gateway.log_id, resulting_message
            )
            if self._gateway.password is not None:
                hashed_password = f"*#{self._get_own_password(self._gateway.password, resulting_message.nonce)}##"  # pylint: disable=line-too-long
                self._logger.debug(
                    "%s Sending %s session password.", self._gateway.log_id, self._type
                )
                self._stream_writer.write(hashed_password.encode())
                await self._stream_writer.drain()
                raw_response = await self._stream_reader.readuntil(OWNSession.SEPARATOR)
                resulting_message = OWNSignaling(raw_response.decode())
                # self._logger.debug("%s Reply: `%s`", self._gateway.log_id, resulting_message)
                if resulting_message.is_nack():
                    error = True
                    error_message = "password_error"
                    self._logger.error(
                        "%s Password error while opening %s session.",
                        self._gateway.log_id,
                        self._type,
                    )
                elif resulting_message.is_ack():
                    self._logger.debug(
                        "%s %s session established successfully.",
                        self._gateway.log_id,
                        self._type.capitalize(),
                    )
            else:
                error = True
                error_message = "password_error"
                self._logger.error(
                    "%s Connection requires a password but none was provided for %s session.",
                    self._gateway.log_id,
                    self._type,
                )
        elif resulting_message.is_ack():
            # self._logger.debug("%s Reply: `%s`", self._gateway.log_id, resulting_message)
            self._logger.debug(
                "%s %s session established successfully.",
                self._gateway.log_id,
                self._type.capitalize(),
            )
        else:
            error = True
            error_message = "negotiation_failed"
            self._logger.debug(
                "%s Unexpected message during negotiation: %s",
                self._gateway.log_id,
                resulting_message,
            )

        return {"Success": not error, "Message": error_message}

    def _get_own_password(self, password, nonce, test=False):
        start = True
        num1 = 0
        num2 = 0
        password = int(password)
        if test:
            print("password: %08x" % (password))
        for character in nonce:
            if character != "0":
                if start:
                    num2 = password
                start = False
            if test:
                print("c: %s num1: %08x num2: %08x" % (character, num1, num2))
            if character == "1":
                num1 = (num2 & 0xFFFFFF80) >> 7
                num2 = num2 << 25
            elif character == "2":
                num1 = (num2 & 0xFFFFFFF0) >> 4
                num2 = num2 << 28
            elif character == "3":
                num1 = (num2 & 0xFFFFFFF8) >> 3
                num2 = num2 << 29
            elif character == "4":
                num1 = num2 << 1
                num2 = num2 >> 31
            elif character == "5":
                num1 = num2 << 5
                num2 = num2 >> 27
            elif character == "6":
                num1 = num2 << 12
                num2 = num2 >> 20
            elif character == "7":
                num1 = (
                    num2 & 0x0000FF00
                    | ((num2 & 0x000000FF) << 24)
                    | ((num2 & 0x00FF0000) >> 16)
                )
                num2 = (num2 & 0xFF000000) >> 8
            elif character == "8":
                num1 = (num2 & 0x0000FFFF) << 16 | (num2 >> 24)
                num2 = (num2 & 0x00FF0000) >> 8
            elif character == "9":
                num1 = ~num2
            else:
                num1 = num2

            num1 &= 0xFFFFFFFF
            num2 &= 0xFFFFFFFF
            if character not in "09":
                num1 |= num2
            if test:
                print("     num1: %08x num2: %08x" % (num1, num2))
            num2 = num1
        return num1

    def _encode_hmac_password(
        self, method: str, password: str, nonce_a: str, nonce_b: str
    ):
        if method == "sha1":
            message = (
                self._int_string_to_hex_string(nonce_a)
                + self._int_string_to_hex_string(nonce_b)
                + "736F70653E"
                + "636F70653E"
                + hashlib.sha1(password.encode()).hexdigest()
            )
            return self._hex_string_to_int_string(
                hashlib.sha1(message.encode()).hexdigest()
            )
        elif method == "sha256":
            message = (
                self._int_string_to_hex_string(nonce_a)
                + self._int_string_to_hex_string(nonce_b)
                + "736F70653E"
                + "636F70653E"
                + hashlib.sha256(password.encode()).hexdigest()
            )
            return self._hex_string_to_int_string(
                hashlib.sha256(message.encode()).hexdigest()
            )
        else:
            return None

    def _decode_hmac_response(
        self, method: str, password: str, nonce_a: str, nonce_b: str
    ):
        if method == "sha1":
            message = (
                self._int_string_to_hex_string(nonce_a)
                + self._int_string_to_hex_string(nonce_b)
                + hashlib.sha1(password.encode()).hexdigest()
            )
            return self._hex_string_to_int_string(
                hashlib.sha1(message.encode()).hexdigest()
            )
        elif method == "sha256":
            message = (
                self._int_string_to_hex_string(nonce_a)
                + self._int_string_to_hex_string(nonce_b)
                + hashlib.sha256(password.encode()).hexdigest()
            )
            return self._hex_string_to_int_string(
                hashlib.sha256(message.encode()).hexdigest()
            )
        else:
            return None

    def _int_string_to_hex_string(self, int_string: str) -> str:
        hex_string = ""
        for i in range(0, len(int_string), 2):
            hex_string += f"{int(int_string[i:i+2]):x}"
        return hex_string

    def _hex_string_to_int_string(self, hex_string: str) -> str:
        int_string = ""
        for i in range(0, len(hex_string), 1):
            int_string += f"{int(hex_string[i:i+1], 16):0>2d}"
        return int_string


class OWNEventSession(OWNSession):
    def __init__(self, gateway: OWNGateway = None, logger: logging.Logger = None):
        super().__init__(gateway=gateway, connection_type="event", logger=logger)

    @classmethod
    async def connect_to_gateway(cls, gateway: OWNGateway):
        connection = cls(gateway)
        await connection.connect()

    async def get_next(self)-> Union[OWNMessage, str, None]:
        """Acts as an entry point to read messages on the event bus.
        It will read one frame and return it as an OWNMessage object"""
        try:
            data = await self._stream_reader.readuntil(OWNSession.SEPARATOR)
            _decoded_data = data.decode()
            _message = OWNMessage.parse(_decoded_data)
            return _message if _message else _decoded_data
        except asyncio.IncompleteReadError:
            self._logger.warning(
                "%s Connection interrupted, reconnecting...", self._gateway.log_id
            )
            await self.connect()
            return None
        except AttributeError:
            self._logger.exception(
                "%s Received data could not be parsed into a message:",
                self._gateway.log_id,
            )
            return None
        except ConnectionError:
            self._logger.exception("%s Connection error:", self._gateway.log_id)
            return None
        except Exception:  # pylint: disable=broad-except
            self._logger.exception("%s Event session crashed.", self._gateway.log_id)
            return None


class OWNCommandSession(OWNSession):
    def __init__(self, gateway: OWNGateway = None, logger: logging.Logger = None):
        super().__init__(gateway=gateway, connection_type="command", logger=logger)

    @classmethod
    async def send_to_gateway(cls, message: str, gateway: OWNGateway):
        connection = cls(gateway)
        await connection.connect()
        await connection.send(message)

    @classmethod
    async def connect_to_gateway(cls, gateway: OWNGateway):
        connection = cls(gateway)
        await connection.connect()

    async def send(self, message: str, is_status_request: bool = False):
        """Send the attached message on an existing 'command' connection,
        actively reconnecting it if it had been reset."""

        try:
            self._stream_writer.write(str(message).encode())
            await self._stream_writer.drain()
            raw_response = await self._stream_reader.readuntil(OWNSession.SEPARATOR)
            resulting_message = OWNMessage.parse(raw_response.decode())
            if (
                isinstance(resulting_message, OWNSignaling)
                and resulting_message.is_nack()
            ):
                self._stream_writer.write(str(message).encode())
                await self._stream_writer.drain()
                raw_response = await self._stream_reader.readuntil(OWNSession.SEPARATOR)
                resulting_message = OWNSignaling(raw_response.decode())
                if resulting_message.is_nack():
                    self._logger.error(
                        "%s Could not send message `%s`.", self._gateway.log_id, message
                    )
                elif resulting_message.is_ack():
                    if not is_status_request:
                        self._logger.debug(
                            "%s Message `%s` was successfully sent.",
                            self._gateway.log_id,
                            message,
                        )
                    else:
                        self._logger.debug(
                            "%s Message `%s` was successfully sent.",
                            self._gateway.log_id,
                            message,
                        )
            elif (
                isinstance(resulting_message, OWNSignaling)
                and resulting_message.is_ack()
            ):
                if not is_status_request:
                    self._logger.debug(
                        "%s Message `%s` was successfully sent.",
                        self._gateway.log_id,
                        message,
                    )
                else:
                    self._logger.debug(
                        "%s Message `%s` was successfully sent.",
                        self._gateway.log_id,
                        message,
                    )
            else:
                self._logger.debug(
                    "%s Message `%s` received response `%s`.",
                    self._gateway.log_id,
                    message,
                    resulting_message,
                )
                raw_response = await self._stream_reader.readuntil(OWNSession.SEPARATOR)
                resulting_message = OWNSignaling(raw_response.decode())
                if resulting_message.is_nack():
                    self._logger.error(
                        "%s Could not send message `%s`.", self._gateway.log_id, message
                    )
                elif resulting_message.is_ack():
                    if not is_status_request:
                        self._logger.debug(
                            "%s Message `%s` was successfully sent.",
                            self._gateway.log_id,
                            message,
                        )
                    else:
                        self._logger.debug(
                            "%s Message `%s` was successfully sent.",
                            self._gateway.log_id,
                            message,
                        )

        except (ConnectionResetError, asyncio.IncompleteReadError):
            self._logger.debug(
                "%s Command session connection reset, retrying...", self._gateway.log_id
            )
            await self.connect()
            await self.send(message=message, is_status_request=is_status_request)
        except Exception:  # pylint: disable=broad-except
            self._logger.exception("%s Command session crashed.", self._gateway.log_id)
            return None
