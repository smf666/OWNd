""" OWNd entry point when running it directly from CLI
(as opposed to imported into another project)
"""
import argparse
import asyncio
import logging

from OWNd.message import OWNMessage

from .connection import OWNEventSession, OWNGateway, ZigbeeOWNGateway, zigbeeSession


async def main(arguments: dict, connection: OWNEventSession) -> None:
    """Package entry point!"""

    zigbee = (
        arguments["zigbee"]
        if "zigbee" in arguments and isinstance(arguments["zigbee"], str)
        else None
    )
    address = (
        arguments["address"]
        if "address" in arguments and isinstance(arguments["address"], str)
        else None
    )
    port = (
        arguments["port"]
        if "port" in arguments and isinstance(arguments["port"], int)
        else None
    )
    password = (
        arguments["password"]
        if "password" in arguments and isinstance(arguments["password"], str)
        else None
    )
    serial_number = (
        arguments["serialNumber"]
        if "serialNumber" in arguments and isinstance(arguments["serialNumber"], str)
        else None
    )
    logger = (
        arguments["logger"]
        if "logger" in arguments and isinstance(arguments["logger"], logging.Logger)
        else None
    )

    if zigbee is not None:
	    # case of zigbee
        logger.info("Starting Zigbee/OPEN on serial port <%s>", zigbee)
        gateway = await ZigbeeOWNGateway.build_from_discovery_info(
            {
                "zigbee": zigbee,
            }
        )
    else:
        logger.info("Starting discovery of a supported gateway via SSDP")
        gateway = await OWNGateway.build_from_discovery_info(
        {
            "address": address,
            "port": port,
            "password": password,
            "serialNumber": serial_number,
        }
        )
    zb = zigbeeSession(gateway, _logger)

    await zb.connect()

    #connection.gateway = gateway
    #
    #if logger is not None:
    #     connection.logger = logger

    #res = await connection.test_connection()
    #if res["Success"]:
    #    logger.info("Starting connection to the discovered gateway")
    #    await connection.connect()

    #    logger.info("Now waiting for events from the gateway (e.g. a cover opening/closing)")
    #    while True:
    #        message = await connection.get_next()
    #        if message:
    #            logger.debug("Received: %s", message)
    #            if isinstance(message, OWNMessage) and message.is_event:
    #                logger.info(message.human_readable_log)
    #else:
    #    logger.error("Error during test: %s", res["Message"])


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-z", "--zigbee", type=str, help="Serial port of Zigbee/Open gateway"
    )
    parser.add_argument(
        "-a", "--address", type=str, help="IP address of the OpenWebNet gateway"
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="TCP port to connectect the gateway, default is 20000",
    )
    parser.add_argument(
        "-P",
        "--password",
        type=str,
        help="Numeric password for the OpenWebNet connection, default is 12345",
    )
    parser.add_argument(
        "-m",
        "--mac",
        type=str,
        help="MAC address of the gateway (to be used as ID, if  not found via SSDP)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        type=int,
        help="Change output verbosity [0 = WARNING; 1 = INFO (default); 2 = DEBUG]",
    )
    args = parser.parse_args()

    # create logger with 'OWNd'
    _logger = logging.getLogger("OWNd")
    _logger.setLevel(logging.DEBUG)

    # create console handler which logs even debug messages
    log_stream_handler = logging.StreamHandler()

    if args.verbose == 2:
        log_stream_handler.setLevel(logging.DEBUG)
    elif args.verbose == 0:
        log_stream_handler.setLevel(logging.WARNING)
    else:
        log_stream_handler.setLevel(logging.INFO)

    # create formatter and add it to the handlers
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    log_stream_handler.setFormatter(formatter)
    # add the handlers to the logger
    _logger.addHandler(log_stream_handler)

    event_session = OWNEventSession(gateway=None, logger=_logger)
    _arguments = {
        "zigbee": args.zigbee,
        "address": args.address,
        "port": args.port,
        "password": args.password,
        "serialNumber": args.mac,
        "logger": _logger,
    }

    loop = asyncio.get_event_loop()
    main_task = asyncio.ensure_future(main(_arguments, event_session))
    # loop.set_debug(True)

    try:
        _logger.info("Starting OWNd.")
        loop.run_forever()
        # asyncio.run(main(arguments))
    except KeyboardInterrupt:
        try:
            _logger.info("Stoping OWNd.")
            # get all task in current loop
            main_task.cancel()
            loop.run_until_complete(event_session.close())
        finally:
            loop.stop()
            loop.close()
    finally:
        _logger.info("OWNd stopped.")
