# adapters/snmp_adapter.py

from typing import Dict, Optional
import sys
from pathlib import Path

# Добавляем custom_modules в путь
custom_modules_path = Path(__file__).parent.parent / "custom_modules"
if custom_modules_path.exists():
    sys.path.insert(0, str(custom_modules_path))

from custom_modules.snmp import SNMPDevice
from custom_modules.oid import general
from custom_modules.log import logger


class SNMPAdapter:
    """
    Адаптер для работы с SNMP устройствами.
    Предоставляет упрощенный интерфейс для получения данных через SNMP.
    """

    def __init__(self, default_config: Optional[Dict] = None):
        """Инициализация SNMP адаптера."""
        self.default_config = default_config or {
            'community': 'public',
            'version': '2c',
            'timeout': 10,
            'retries': 3
        }

    def get_arp_table(self, ip_address: str, community: Optional[str] = None, 
                      version: Optional[str] = None) -> Dict[str, str]:
        """
        Получить ARP-таблицу с устройства.

        Args:
            ip_address: IP-адрес устройства
            community: SNMP community string (по умолчанию из config)
            version: SNMP версия (по умолчанию из config)

        Returns:
            Dict[str, str]: Словарь {IP: MAC}
        """
        logger.info(f"Getting ARP table from {ip_address}")


        # Используем значения из конфига если не указаны явно
        community = community or self.default_config.get('community', 'public')
        version = version or self.default_config.get('version', '2c')

        try:
            # Получаем ARP таблицу напрямую через статический метод
            arp_table = SNMPDevice.get_network_table(
                ip_address=ip_address,
                table_oid=general.arp_mac,
                table_tag="IP-MAC",
                community_string=community
            )

            logger.info(f"Retrieved {len(arp_table)} ARP entries from {ip_address}")
            return arp_table

        except Exception as e:
            logger.error(f"Failed to get ARP table from {ip_address}: {str(e)}")
            raise

    def check_snmp_connectivity(self, host_ip: str, community: str, version: str = '2c') -> bool:
        """
        Perform a simple SNMP connectivity check using the existing get_hostname() method.

        Args:
            host_ip: Device IP address
            community: SNMP community string  
            version: SNMP version ('1', '2c', '3')

        Returns:
            bool: True if successful, False otherwise
        """
        logger.debug(f"Checking SNMP connectivity to {host_ip} (version {version}, community={community})")

        try:
            # Create SNMPDevice instance with provided settings
            snmp_device = SNMPDevice(
                ip_address=host_ip,
                community_string=community,
                version=version
            )

            # Use existing get_hostname() method for connectivity check
            hostname = snmp_device.get_hostname()

            if hostname:
                logger.debug(f"SNMP connectivity successful for {host_ip}: hostname='{hostname}'")
                return hostname
            else:
                logger.debug(f"SNMP connectivity failed for {host_ip}: empty hostname")
                return None

        except Exception as e:
            logger.debug(f"SNMP connectivity check failed for {host_ip}: {str(e)}")
            return None