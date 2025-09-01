from typing import List, Dict, Any, Optional
from custom_modules.log import logger
from custom_modules.prtg_connector import PRTGConnector
import config


class PRTGAdapter:
    """
    Адаптер для работы с PRTG.
    """

    def __init__(self):
        """Инициализация адаптера PRTG."""
        self.prtg_connector = PRTGConnector()
        logger.info("PRTG adapter initialized")

    def get_devices_for_netbox_import(self) -> List[Dict[str, Any]]:
        """
        Получить устройства из PRTG для получения SNMP настроек.
        Все параметры берутся из config и переменных окружения.

        Returns:
            List[Dict]: Список устройств с SNMP настройками
        """
        logger.info("Getting devices from PRTG using config settings")

        try:
            devices = self.prtg_connector.get_devices(
                tag_mapping=config.PRTG_TAG_MAPPING,
                defaults=config.PRTG_DEVICE_DEFAULTS,
                import_tag=config.PRTG_CONFIG['import_tag'],
                exclude_tag=config.PRTG_CONFIG['exclude_tag']
            )

            logger.info(f"Retrieved {len(devices)} devices from PRTG")
            return devices

        except Exception as e:
            logger.error(f"Failed to get devices from PRTG: {str(e)}")
            raise