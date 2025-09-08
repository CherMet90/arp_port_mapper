from typing import List, Dict, Optional, Any
from custom_modules.log import logger
from custom_modules.netbox_connector import NetboxDevice
from custom_modules.interface_normalizer import InterfaceNormalizer


class NetboxAdapter:
    """
    Адаптер для работы с NetBox.
    Возвращает "сырые" pynetbox объекты для дальнейшей обработки.
    """

    def __init__(self):
        """Инициализация адаптера NetBox."""
        NetboxDevice.create_connection()
        logger.info("NetBox adapter initialized")

    def get_prefixes_by_roles(self, roles: List[str]) -> List[Any]:
        """
        Получить префиксы из NetBox по ролям.

        Args:
            roles: Список ролей префиксов для поиска

        Returns:
            List[pynetbox.Record]: Список объектов префиксов
        """
        logger.info(f"Getting prefixes with roles: {roles}")

        all_prefixes = []
        try:
            for role in roles:
                role_prefixes = NetboxDevice.get_netbox_objects(
                    "ipam.prefixes", action="filter", role=role
                )
                if role_prefixes:
                    all_prefixes.extend(role_prefixes)
                logger.debug(f"Found {len(role_prefixes or [])} prefixes with role '{role}'")

        except Exception as e:
            logger.error(f"Failed to get prefixes by roles {roles}: {str(e)}")
            raise

        logger.info(f"Total prefixes found: {len(all_prefixes)}")
        return all_prefixes

    def get_devices_by_site_and_roles(self, site_slug: str, device_roles: List[str]) -> List[Any]:
        """
        Получить устройства с площадки по ролям.

        Args:
            site_slug: Slug площадки
            device_roles: Список ролей устройств

        Returns:
            List[pynetbox.Record]: Список объектов устройств
        """
        logger.info(f"Getting devices from site '{site_slug}' with roles: {device_roles}")

        all_devices = []
        try:
            for role in device_roles:
                role_devices = NetboxDevice.get_netbox_objects(
                    "dcim.devices", action="filter", 
                    site=site_slug, role=role, status="active"
                )
                if role_devices:
                    all_devices.extend(role_devices)
                logger.debug(f"Found {len(role_devices or [])} devices with role '{role}'")

        except Exception as e:
            logger.error(f"Failed to get devices for site '{site_slug}': {str(e)}")
            raise

        logger.info(f"Total devices found on site '{site_slug}': {len(all_devices)}")
        return all_devices

    def update_device_snmp_settings(self, device_name: str, 
                                   snmp_version: str, 
                                   snmp_community: str):
        """
        Обновить SNMP настройки устройства в NetBox.

        Args:
            device_name: Имя устройства
            snmp_version: Версия SNMP (1, 2c, 3)
            snmp_community: SNMP community
        """
        logger.debug(f"Updating SNMP settings for device {device_name}")

        try:
            # Безопасный поиск устройства по имени
            try:
                device = NetboxDevice.get_netbox_objects(
                    "dcim.devices", action="get", name=device_name
                )
            except Exception as get_error:
                # Обрабатываем случай множественных результатов или другие ошибки get
                logger.warning(f"Failed to get unique device '{device_name}': {str(get_error)}")
                return

            if not device:
                logger.warning(f"Device {device_name} not found in NetBox")
                return

            # Обновляем custom fields если они отличаются
            updated = False
            if device.custom_fields.get('snmp_version') != snmp_version:
                device.custom_fields['snmp_version'] = snmp_version
                updated = True

            if device.custom_fields.get('snmp_community') != snmp_community:
                device.custom_fields['snmp_community'] = snmp_community
                updated = True

            if updated:
                device.save()
                logger.info(f"Updated SNMP settings for device {device_name}")
            else:
                logger.debug(f"SNMP settings unchanged for device {device_name}")

        except Exception as e:
            logger.error(f"Failed to update SNMP settings for {device_name}: {str(e)}")
