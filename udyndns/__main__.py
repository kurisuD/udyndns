import asyncio
import json
import logging
import sys
from pathlib import Path

from udyndns import get_wan_ip, update_ovh_dyn_dns


def main():
    """
    Updates OVH dyndns based on the WAN IP retrieved from the unifi API since unadyn is so stubbornly unable to do so.
    """
    udyndns_config_file = Path("~").expanduser() / ".udyndns.json"
    if not udyndns_config_file.exists():
        raise FileNotFoundError(f"{udyndns_config_file} not found")
    for fqdn, config in json.loads(udyndns_config_file.read_text()).items():
        unifi_config = config["unifi"]
        wan_ip = asyncio.run(get_wan_ip(**unifi_config))
        if wan_ip:
            ovh_config = config["ovh"]
            ovh_config.update({"fqdn": fqdn, "ip": wan_ip})
            logging.info(f"Will check and update {fqdn} with {wan_ip} if necessary")
            update_ovh_dyn_dns(**ovh_config)


if __name__ == '__main__':
    from pap_logger import PaPLogger

    p = PaPLogger(level=logging.INFO)
    try:
        main()
    except Exception as e:
        logging.error(f"Sorry, we could not proceed: {e}")
        sys.exit(1)
