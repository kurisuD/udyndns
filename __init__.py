import asyncio
import logging

import aiounifi
import requests
from aiohttp import ClientSession
from aiounifi.controller import Controller
from aiounifi.models.configuration import Configuration
from requests.auth import HTTPBasicAuth


async def get_wan_ip(host: str, username: str, port: int, password: str, timeout: int = 10) -> [str | None]:
    """
    returns the WAN IP address of the unifi gateway
    :param host:
    :param username:
    :param port:
    :param password:
    :param timeout:
    :return:
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

    :param fqdn:
    :param ip:
    :param password:
    :param username:
    :return:
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
            else:
                logging.warning(new_ip_resp.status_code)
                logging.warning(new_ip_resp.reason)
                return False
        else:
            logging.info(f"Our unifi API retrieved IP {ip} is the same as our current IP: {current}")
    else:
        logging.error(f"Unable to authenticate to the {current_ip_url}")
        logging.error(current_ip_resp.status_code)
        logging.error(current_ip_resp.reason)
        logging.error(current_ip_resp.text)
        return False

__all__ = ["get_wan_ip", "update_ovh_dyn_dns"]
