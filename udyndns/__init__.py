"""
udyndns
"""
import asyncio
import logging
from typing import Optional

import aiounifi
import requests
from aiohttp import ClientSession
from aiounifi.controller import Controller
from aiounifi.models.configuration import Configuration
from requests.auth import HTTPBasicAuth


async def get_wan_ip(host: str, port: int, username: str, password: str, timeout: int = 10) -> [Optional[str]]:
    """
    obtains the WAN IP address of the unifi gateway

    :param host: hostname or ip address of your unifi gateway / dream machine / ...
    :param port: port to your unifi gateway / dream machine / ...
    :param username: username to authenticate on your unifi device.
    :param password: password to authenticate on your unifi device.
    :param timeout: number of seconds to wait for your unifi device to respond.
    :return: the WAN IP address of the unifi gateway / dream machine / ...
    :type host: str
    :type port: int
    :type username: str
    :type password: str
    :type timeout: int
    :rtype: str | None

    """
    async with ClientSession() as _session:
        _config = Configuration(session=_session, host=host, username=username, port=port, password=password)
        api = Controller(config=_config)
        try:
            async with asyncio.timeout(10):
                await api.login()
        except aiounifi.Unauthorized as err:
            logging.warning(f"Connected to {host}:{port} but user {username} is not registered: {err}")

        except (
                TimeoutError,
                aiounifi.BadGateway,
                aiounifi.Forbidden,
                aiounifi.ServiceUnavailable,
                aiounifi.RequestError,
                aiounifi.ResponseError,
        ) as err:
            logging.error(f"Error connecting to the UniFi Network at {host}:{port}: {err}")
            return None
        _proxy_network_str = "/proxy/network" if api.connectivity.is_unifi_os else ""
        health_data = await _session.get(
            f"https://{host}:{port}{_proxy_network_str}/api/s/default/stat/health",
            headers={"Accept": "application/json",
                     "Content-Type": "application/json"},
            timeout=timeout,
            ssl=_config.ssl_context
        )
        health = await health_data.json()
        wan_ip = [subsystem for subsystem in health['data'] if subsystem["subsystem"] == "wan"][0]["wan_ip"]
        logging.info(f"WAN IP for {host}:{port}: {wan_ip}")
        return wan_ip


def update_ovh_dyn_dns(fqdn: str, ip: str, username: str, password: str) -> bool:
    """
    Updates the OVH Dyndns's registered wan ip address for your domain, if necessary.
    :param fqdn: The fully qualified domain name to be updated.
    :param ip: the wan ip address to be used for the update.
    :param username: your ovh dyndns username for updating this fqdn.
    :param password: your ovh dyndns password for updating this fqdn.
    :return: True on success, False otherwise.
    :type fqdn: str
    :type ip: str
    :type username: str
    :type password: str
    :rtype: bool
    """
    logging.info(f"Checking dynamic DNS for {fqdn}")
    session = requests.Session()
    session.auth = HTTPBasicAuth(username=username, password=password)
    current_ip_url = f"https://www.ovh.com/nic/update?system=dyndns&hostname={fqdn}"
    current_ip_resp = session.get(current_ip_url)
    if current_ip_resp.ok:
        logging.info(current_ip_resp.status_code)
        logging.info(current_ip_resp.text)
        current = current_ip_resp.text.split(" ")[1].strip()
        if current != ip:
            logging.info(f"Need to update IP from '{current}' to '{ip}'")
            new_ip_url = f"{current_ip_url}&myip={ip}"
            logging.info(new_ip_url)
            new_ip_resp = session.get(new_ip_url)
            if new_ip_resp.ok:
                logging.info(f"New IP results: {new_ip_resp.text}")
                return True
            logging.warning(new_ip_resp.status_code)
            logging.warning(new_ip_resp.reason)
            return False
        logging.info(f"Our unifi API retrieved IP {ip} is the same as our current IP: {current}")
        return True
    logging.error(f"Unable to authenticate to the {current_ip_url}")
    logging.error(current_ip_resp.status_code)
    logging.error(current_ip_resp.reason)
    logging.error(current_ip_resp.text)
    return False


__all__ = ["get_wan_ip", "update_ovh_dyn_dns"]
