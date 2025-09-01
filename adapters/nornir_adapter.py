# adapters/nornir_adapter.py
from typing import Dict, List, Optional, Any
import re
import yaml

from custom_modules.nornir_connector import NornirConnector
from custom_modules.log import logger
from custom_modules.errors import Error
import config

class NornirAdapter:
    """
    Высокоуровневый адаптер для получения MAC-таблиц.
    Загружает команды и правила парсинга из внешнего YAML-файла.
    """

    def __init__(self, inventory: Dict[str, Dict], platform_parsers: Dict[str, Any]):
        if not inventory:
            raise Error("Inventory cannot be empty")

        self.inventory = inventory
        self.nc = NornirConnector(
            hosts_dict=inventory,
            num_workers=config.NORNIR_CONFIG["num_workers"],
            log_level=config.NORNIR_CONFIG.get("log_level", "INFO"),
        )

        # Загрузка и обработка парсеров
        self.parsers = platform_parsers
        logger.info(f"Initialized with {len(self.parsers)} platform parsers.")

    def get_mac_tables(self) -> Dict[str, List[Dict[str, str]]]:
        """Собирает MAC-таблицы, динамически выбирая команду и парсер."""
        all_macs: Dict[str, List[Dict[str, str]]] = {}
        devices_by_platform = self._group_by_platform()

        for platform, hosts in devices_by_platform.items():
            parser_def = self.parsers.get(platform)
            if not parser_def:
                logger.warning(f"No parser definition for platform '{platform}', skipping {len(hosts)} hosts.")
                for host in hosts:
                    all_macs[host] = []
                continue

            command = parser_def['command']
            logger.info(f"Executing '{command}' on {len(hosts)} hosts with platform '{platform}'")

            # Выполнение команды через коннектор
            raw_results = self.nc.run_commands(command, hosts=hosts).get(command, {})

            for host, cli_output in raw_results.items():
                if isinstance(cli_output, str) and cli_output.startswith("ERROR:"):
                    logger.error(f"Failed to get MAC table from {host}: {cli_output}")
                    all_macs[host] = []
                    continue

                # Динамический парсинг
                parsed_entries = self._dynamic_parse(cli_output, parser_def)
                all_macs[host] = parsed_entries
                logger.debug(f"Parsed {len(parsed_entries)} MAC entries from {host}")

        return all_macs

    def _dynamic_parse(self, output: str, parser_def: Dict) -> List[Dict[str, str]]:
        """Парсит вывод, используя регулярное выражение и маппинг из определения."""
        if not output:
            return []

        regex = parser_def['regex']
        mapping = parser_def['mapping']

        try:
            pattern = re.compile(regex)
            matches = pattern.findall(output)
        except re.error as e:
            logger.error(f"Invalid regex in parser definition: {e}")
            return []

        results = []
        for match_tuple in matches:
            entry = {}
            for field, group_index in mapping.items():
                # Группы в regex 1-индексированные, кортежи в findall 0-индексированные
                try:
                    entry[field] = match_tuple[group_index - 1].strip()
                except IndexError:
                    logger.warning(f"Regex group {group_index} not found for field '{field}'. Check your regex.")
                    entry[field] = ""

            # Нормализация MAC и заполнение недостающих полей
            if 'mac' in entry:
                entry['mac'] = self._normalize_mac(entry['mac'])
            if 'type' not in entry:
                entry['type'] = 'unknown' # Default value if not in regex

            results.append(entry)

        return results

    def _group_by_platform(self) -> Dict[str, List[str]]:
        """Группирует хосты из inventory по их оригинальной платформе (для парсеров)."""
        groups: Dict[str, List[str]] = {}
        for host, data in self.inventory.items():
            # Используем original_platform если есть, иначе fallback на platform
            original_platform = data.get("data", {}).get("original_platform")
            platform_name = original_platform or data.get("platform", "unknown").lower()
            groups.setdefault(platform_name, []).append(host)
        return groups

    def _normalize_mac(self, mac: str) -> str:
        """Приводит MAC к каноническому виду XX:XX:XX:XX:XX:XX."""
        clean = re.sub(r'[^0-9A-Fa-f]', '', mac).upper()
        if len(clean) == 12:
            return ':'.join(clean[i:i+2] for i in range(0, 12, 2))
        return mac # Возвращаем как есть, если не удалось нормализовать

    def close(self):
        self.nc.close_connections()