from collections import defaultdict
from collections.abc import Mapping
from copy import deepcopy
import csv
from datetime import datetime
import ipaddress
from pathlib import Path
import pandas as pd
import os
from typing import List, Dict, Optional, Tuple, Any

import yaml

from adapters.models import GatewayRecord
from custom_modules.log import logger
from custom_modules.error_aggregator import ErrorAggregator
from custom_modules.netbox_batch_updater import NetboxBatchUpdater
from custom_modules.errors import Error

from adapters.netbox_adapter import NetboxAdapter  
from adapters.snmp_adapter import SNMPAdapter
from adapters.nornir_adapter import NornirAdapter
import config


class ARPPortMapperWorkflow:
    """
    Основной workflow для сопоставления ARP-записей с портами коммутаторов.
    """

    def __init__(self, 
                 prefix_roles: List[str], 
                 output_file: str = None, 
                 target_sites: List[str] = None, 
                 verbose: bool = None,
                 enable_session_log: bool = None):
        """
        Инициализация workflow.

        Args:
            prefix_roles: Роли префиксов для анализа (обязательный параметр)
            output_file: Путь к файлу результатов (опциональный)
            target_sites: Список площадок для обработки (опциональный, None = все площадки)
            verbose: Режим подробного вывода (опциональный, переопределяет конфиг)
            enable_session_log: Включить логирование сессий Netmiko (опциональный)
        """

        self.prefix_roles = prefix_roles

        # Параметры из конфига с возможностью переопределения
        self.device_roles = config.APP_DEFAULTS['device_roles']
        self.target_sites = target_sites
        self.gw_list_file = config.APP_DEFAULTS['gw_list_file']

        # Обрабатываем output_file
        self.output_file = output_file or 'arp_port_mapping.csv'
        self.final_output_path = None

        self.update_netbox = config.APP_DEFAULTS['update_netbox']
        self.overwrite_existing_descriptions = config.APP_DEFAULTS['overwrite_existing_descriptions']

        # Verbose режим с возможностью переопределения
        self.verbose = verbose if verbose is not None else config.APP_DEFAULTS['verbose']

        self.csv_delimiter = config.APP_DEFAULTS['csv_delimiter']

        # Инициализация агрегатора
        self.agg = ErrorAggregator()
        self.agg.reset()  # Сброс состояния для нового запуска

        # Параметры для session logging и fast_cli
        self.enable_session_log = enable_session_log if enable_session_log is not None else config.APP_DEFAULTS.get('enable_session_log', False)
        self.problem_platforms = config.APP_DEFAULTS.get('problem_platforms', ['zyxel_os'])
        self.enable_fast_cli = config.APP_DEFAULTS.get('enable_fast_cli', True)

        # Создаем папку для session logs если включено логирование
        if self.enable_session_log:
            Path("session_logs").mkdir(exist_ok=True)
            logger.info("Session logging enabled - logs will be saved to session_logs/ folder")

        self.platform_parsers = self._load_parsers(config.NORNIR_CONFIG['platform_parsers_file'])

        # Инициализация адаптеров
        self.netbox_adapter = NetboxAdapter()
        self.snmp_adapter = SNMPAdapter(default_config=config.GATEWAY_SNMP_CONFIG)
        self.nornir_adapter = None  # Будет создан позже с inventory

        # Инициализация PRTG адаптера если включен в конфиге
        self.prtg_adapter = None
        if config.PRTG_CONFIG['use_prtg']:
            try:
                from adapters.prtg_adapter import PRTGAdapter
                self.prtg_adapter = PRTGAdapter()
                logger.info("PRTG adapter initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize PRTG adapter: {str(e)}")

        # Хранилище данных
        self.prefixes_by_site = {}
        self.gateways_by_site = {}  
        self.arp_tables = {}
        self.mac_tables = {}
        self.mapping_results = []
        self.mapping_filtered = []
        self.prtg_snmp_settings = {}

    def run(self) -> List[Dict[str, Any]]:
        """Запуск основного workflow."""
        logger.info("Starting ARP Port Mapper workflow")
        logger.info(f"Target prefix roles: {self.prefix_roles}")
        logger.info(f"Target device roles: {self.device_roles}")
        logger.info(f"Target sites: {self.target_sites or 'ALL'}")

        try:
            # Шаг 1: Получение префиксов из NetBox
            self._get_prefixes_from_netbox()

            # Шаг 2: Загрузка конфигурации шлюзов
            self._load_gateway_config()

            # Шаг 3: Получение SNMP настроек из PRTG (если включено)
            if self.prtg_adapter:
                self._get_snmp_settings_from_prtg()

            # Шаг 4: Получение ARP-таблиц с шлюзов
            self._get_arp_tables()

            # Шаг 5: Получение коммутаторов и MAC-таблиц
            self._get_switch_mac_tables()

            # Шаг 6: Сопоставление ARP ↔ MAC ↔ порты
            self._correlate_arp_mac_ports()

            # Шаг 6.5: Фильтрация портов для обновления NetBox
            if config.PORT_FILTER['enabled']:
                self._filter_ports_for_netbox_update()
            else:
                self.mapping_filtered = self.mapping_results

            # Шаг 7: Сохранение результатов
            self._save_results()

            # Шаг 7': Сохранение отфильтрованных результатов
            self._save_filtered_results()

            # Шаг 8: Обновление NetBox (если требуется)
            if self.update_netbox:
                self._update_netbox_descriptions()

            # Финальные метрики
            self.agg.inc("mappings_total", len(self.mapping_results))
            self.agg.inc("mappings_selected_for_updates", len(self.mapping_filtered))
            self.agg.inc("sites_processed", len(self.prefixes_by_site))

            # Итоговая информация о session logs
            if self.enable_session_log:
                session_logs_dir = Path("session_logs")
                if session_logs_dir.exists():
                    log_files = list(session_logs_dir.glob("*_session.log"))
                    total_size = sum(f.stat().st_size for f in log_files if f.exists())
                    logger.info(f"Session logging summary: {len(log_files)} files, {total_size} bytes total")

                    if self.verbose and log_files:
                        logger.info("Session log files created:")
                        for log_file in sorted(log_files):
                            size_kb = log_file.stat().st_size / 1024
                            logger.info(f"  {log_file.name}: {size_kb:.1f} KB")

            return self.mapping_results

        except Exception as e:
            logger.error(f"Workflow failed: {str(e)}")
            raise
        finally:
            # Рендеринг итогового отчета
            self.agg.render()

    def _load_parsers(self, file_path: str) -> Dict[str, Any]:
        """Загружает и разрешает алиасы в файле парсеров."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except FileNotFoundError:
            raise Error(f"Parsers file not found: {file_path}")
        except yaml.YAMLError as e:
            raise Error(f"Error parsing YAML file {file_path}: {e}")

        parsers = data.get('platform_parsers', {})
        
        # Валидация: проверяем наличие netmiko_platform для каждой платформы
        for platform, definition in parsers.items():
            if 'netmiko_platform' not in definition:
                logger.warning(f"Platform '{platform}' missing 'netmiko_platform' parameter - will use platform name as fallback")

        return parsers

    def _get_prefixes_from_netbox(self):
        """Шаг 1: Получение префиксов из NetBox с заданными ролями."""
        logger.info(f"Getting prefixes from NetBox with roles: {self.prefix_roles}")

        prefixes = self.netbox_adapter.get_prefixes_by_roles(self.prefix_roles)

        # Группируем по площадкам
        for prefix_obj in prefixes:
            # Проверяем наличие площадки
            if not prefix_obj.site:
                logger.warning(f"Prefix {prefix_obj.prefix} has no site, skipping")
                continue

            site_slug = prefix_obj.site.slug

            # Фильтруем по целевым площадкам, если указаны
            if self.target_sites and site_slug not in self.target_sites:
                continue

            if site_slug not in self.prefixes_by_site:
                self.prefixes_by_site[site_slug] = []
            self.prefixes_by_site[site_slug].append(prefix_obj)

        self.agg.inc("sites_with_prefixes", len(self.prefixes_by_site))
        self.agg.inc("total_prefixes", len(prefixes))

        logger.info(f"Found prefixes for {len(self.prefixes_by_site)} sites: {list(self.prefixes_by_site.keys())}")

    def _load_gateway_config(self):
        """Шаг 2: Загрузка конфигурации шлюзов."""
        logger.info(f"Loading gateways from {self.gw_list_file}")

        loaded, skipped = 0, 0
        for row_num, row in self._read_gateway_csv():
            ok, reason = self._validate_row(row)
            if not ok:
                logger.warning(f"Row {row_num}: {reason}, skip")
                skipped += 1
                continue

            record = self._parse_row(row, row_num)
            if not record:
                skipped += 1
                continue

            self._merge_gateway(record)
            loaded += 1

        logger.info(f"Gateways loaded: {loaded}, skipped: {skipped}")
        logger.info(f"Configured sites after filtering: {list(self.gateways_by_site.keys())}")

    # --- helpers -------------------------------------------------

    def _read_gateway_csv(self):
        with open(self.gw_list_file, encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter=self.csv_delimiter)
            for n, r in enumerate(reader, start=2):
                yield n, r

    def _validate_row(self, row: dict) -> tuple[bool, str]:
        for col in ("site", "gw", "prefix"):
            if not row.get(col):
                return False, f"missing '{col}'"
        return True, ""

    def _parse_row(self, row: dict, row_num: int) -> GatewayRecord | None:
        site = row["site"].strip()

        if self.target_sites and site not in self.target_sites:
            logger.debug(f"Row {row_num}: site '{site}' not in target_sites {self.target_sites}, skipping")
            return None

        prefixes = self._parse_prefixes(row["prefix"], row_num)
        if not prefixes:
            return None

        return GatewayRecord(
            site=row["site"].strip(),
            gw_ip=row["gw"].strip(),
            prefixes=prefixes,
            community=(row.get("community") or config.GATEWAY_SNMP_CONFIG["community"]).strip()
        )

    def _merge_gateway(self, rec: GatewayRecord):
        site_lst = self.gateways_by_site.setdefault(rec.site, [])
        for gw in site_lst:
            if gw["gw_ip"] == rec.gw_ip:
                gw["prefixes"] = list({*gw["prefixes"], *rec.prefixes})
                return
        site_lst.append(rec.__dict__)

    def _parse_prefixes(self, prefix_field: str, row_num: int) -> List[str]:
        """
        Парсинг поля префиксов - может содержать один префикс или список через запятую.

        Args:
            prefix_field: Строка с префиксами (например, "192.168.1.0/24" или "192.168.29.0/24,192.168.1.0/24")
            row_num: Номер строки для логирования

        Returns:
            List[str]: Список валидных префиксов
        """
        valid_prefixes = []

        # Разбиваем по запятым и очищаем от пробелов
        prefix_candidates = [p.strip() for p in prefix_field.split(',')]

        for prefix in prefix_candidates:
            if not prefix:  # Пропускаем пустые строки
                continue

            try:
                # Проверяем валидность префикса
                ipaddress.ip_network(prefix, strict=False)
                valid_prefixes.append(prefix)
                logger.debug(f"Row {row_num}: valid prefix '{prefix}'")

            except (ipaddress.AddressValueError, ValueError) as e:
                logger.warning(f"Row {row_num}: invalid prefix '{prefix}': {str(e)}")
                continue

        return valid_prefixes

    def _get_snmp_settings_from_prtg(self):
        """Шаг 3: Получить SNMP настройки устройств из PRTG."""
        logger.info("Getting SNMP settings from PRTG")

        try:
            prtg_devices = self.prtg_adapter.get_devices_for_netbox_import()

            for device in prtg_devices:
                ip = device.get('ip_device')
                if ip:
                    # Используем значения из устройства или fallback из конфига
                    self.prtg_snmp_settings[ip] = {
                        'community': device.get('community') or config.PRTG_DEVICE_DEFAULTS['community'],
                        'version': device.get('snmp') or config.PRTG_DEVICE_DEFAULTS['snmp']
                    }

            logger.info(f"Retrieved SNMP settings for {len(self.prtg_snmp_settings)} devices from PRTG")

        except Exception as e:
            logger.error(f"Failed to get SNMP settings from PRTG: {str(e)}")

    def _get_arp_tables(self):
        """Шаг 4: Получение ARP-таблиц с шлюзов через SNMP."""
        logger.info("Getting ARP tables from gateways")

        total_gateways_attempted = 0

        for site, gateways_list in self.gateways_by_site.items():
            logger.debug(f"Site {site}: type={type(gateways_list)}, count={len(gateways_list) if isinstance(gateways_list, list) else 'not a list'}")
            if site not in self.prefixes_by_site:
                logger.warning(f"Site {site} has gateway config but no prefixes, skipping")
                continue

            # Инициализируем объединенную ARP таблицу для площадки
            site_arp_table = {}

            logger.info(f"Processing {len(gateways_list)} gateway(s) for site {site}")

            # Итерируемся по списку шлюзов
            for gateway_config in gateways_list:
                gw_ip = gateway_config['gw_ip']
                total_gateways_attempted += 1

                # Используем community из PRTG если доступно, иначе из конфига шлюза
                if gw_ip in self.prtg_snmp_settings:
                    community = self.prtg_snmp_settings[gw_ip]['community']
                    logger.debug(f"Using PRTG community for gateway {gw_ip}: {community}")
                else:
                    community = gateway_config['community']
                    logger.debug(f"Using config community for gateway {gw_ip}: {community}")

                logger.info(f"Getting ARP table from gateway {gw_ip} for site {site}")

                try:
                    arp_table = self.snmp_adapter.get_arp_table(gw_ip, community)
                    site_arp_table.update(arp_table)
                    logger.info(f"Retrieved {len(arp_table)} ARP entries for site {site}")
                    self.agg.inc("gateways_ok")

                except Exception as e:
                    logger.error(f"Failed to get ARP table for site {site}: {str(e)}")
                    self.agg.inc("gateways_fail")
                    continue

            self.arp_tables[site] = site_arp_table
            self.agg.inc("total_arp_entries", len(site_arp_table))
            logger.info(f"Site {site}: total {len(site_arp_table)} unique ARP entries from all gateways")

        # Итоговые метрики по шлюзам
        self.agg.inc("gateways_total", total_gateways_attempted)

    def _get_switch_mac_tables(self):
        """Шаг 5: Получение коммутаторов и их MAC-таблиц."""
        logger.info("Getting switches and MAC tables")

        for site in self.prefixes_by_site.keys():
            logger.info(f"Processing switches for site {site}")

            # Получаем коммутаторы с площадки
            switches = self.netbox_adapter.get_devices_by_site_and_roles(
                site, self.device_roles
            )
            self.agg.inc("switches_discovered", len(switches))

            if not switches:
                logger.warning(f"No switches found for site {site}")
                continue

            logger.info(f"Found {len(switches)} switches for site {site}")

            # Создаем inventory для Nornir
            try:
                inventory = self._build_nornir_inventory(switches)
            except ValueError as e:
                logger.error(f"Failed to build inventory for site {site}: {str(e)}")
                continue

            if not inventory:
                logger.warning(f"No valid inventory created for site {site} (devices may be missing IP or platform)")
                self.agg.inc("switches_no_inventory", len(switches))
                continue

            self.agg.inc("switches_valid_inventory", len(inventory))

            # Инициализируем Nornir адаптер
            try:
                self.nornir_adapter = NornirAdapter(inventory, self.platform_parsers)

                # Получаем MAC-таблицы
                mac_tables = self.nornir_adapter.get_mac_tables()

                # Логируем информацию о session logs если включено
                if self.enable_session_log:
                    session_info = self.nornir_adapter.nc.get_session_logs_info()
                    active_logs = len([info for info in session_info.values() if info['exists']])
                    if active_logs > 0:
                        logger.info(f"Site {site}: {active_logs} session log files created for troubleshooting")

                        # В verbose режиме показываем детали
                        if self.verbose:
                            for hostname, info in session_info.items():
                                if info['exists']:
                                    logger.info(f"  {hostname}: {info['log_file']} ({info['size']} bytes)")

                self.nornir_adapter.close()
                self.mac_tables[site] = mac_tables

                successful_switches = len([host for host, entries in mac_tables.items() if entries])
                failed_switches = len(inventory) - successful_switches

                self.agg.inc("switches_ok", successful_switches)
                self.agg.inc("switches_fail", failed_switches)

                # Расширенная статистика для проблемных платформ
                problem_platform_switches = len([name for name, data in inventory.items() 
                                                if data.get('platform', '').lower() in self.problem_platforms])
                if problem_platform_switches > 0:
                    logger.info(f"Site {site}: {problem_platform_switches} switches with problem platforms used fast_cli=False")

                total_macs = sum(len(table) for table in mac_tables.values())
                logger.info(f"Retrieved {total_macs} MAC entries from {len(mac_tables)} switches for site {site}")

            except Exception as e:
                logger.error(f"Failed to get MAC tables for site {site}: {str(e)}")
                self.agg.inc("switches_fail", len(inventory))
                self.mac_tables[site] = {}

                # При ошибках с session_log предлагаем посмотреть логи
                if self.enable_session_log:
                    logger.info(f"Check session logs in session_logs/ folder for detailed connection troubleshooting")

                    # Показываем последние созданные файлы
                    session_logs_dir = Path("session_logs")
                    if session_logs_dir.exists():
                        recent_logs = sorted(session_logs_dir.glob("*_session.log"), 
                                           key=lambda f: f.stat().st_mtime, reverse=True)[:3]
                        if recent_logs:
                            logger.info("Recent session logs:")
                            for log_file in recent_logs:
                                mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                                logger.info(f"  {log_file.name} (modified: {mtime.strftime('%H:%M:%S')})")

    def _build_nornir_inventory(self, switches: List) -> Dict:
        """Построение inventory для Nornir из списка коммутаторов."""
        inventory: Dict[str, Any] = {}

        for sw in switches:
            if not sw.primary_ip4 or not sw.platform:
                logger.warning(f"{sw.name}: no IP or platform, skipping")
                continue

            creds = self._select_credentials_for_device(sw)
            if creds is None:
                logger.info(f"{sw.name}: no suitable tag -> skipped (CLI not supported)")
                continue

            ip_address = str(sw.primary_ip4.address).split('/')[0]
            platform_name = str(sw.platform).lower()
            platform_config = self.platform_parsers.get(platform_name, {})
            
            netmiko_platform = platform_config.get("netmiko_platform", platform_name)

            # Базовый inventory entry
            inventory_entry = {
                'hostname': ip_address,
                'platform': netmiko_platform,  # Используем netmiko-совместимое имя
                **creds,
                'data': {
                    'site': sw.site.slug if sw.site else 'unknown',
                    'role': sw.device_role.name if sw.device_role else 'unknown',
                    'original_platform': platform_name,  # Сохраняем оригинальное имя для парсеров
                    'platform_config': platform_config,  # копируем весь конфиг платформы
                },
            }

            # Добавляем connection_options для Netmiko если нужно
            connection_options = {
                'netmiko': {
                    'extras': {}
                }
            }

            # fast_cli: только по оригинальному имени платформы или глобальное отключение
            if platform_name in self.problem_platforms or not self.enable_fast_cli:
                connection_options['netmiko']['extras']['fast_cli'] = False
                logger.debug(f"Device {sw.name} ({platform_name}): fast_cli=False (problem platform or globally disabled)")

            # Session log: включаем если запрошено
            if self.enable_session_log:
                log_file = f"session_logs/{sw.name}_session.log"
                connection_options['netmiko']['extras']['session_log'] = log_file
                logger.debug(f"Device {sw.name}: session_log enabled -> {log_file}")

            # Подмешиваем connection_options из platform_config
            yaml_conn_opts = platform_config.get("connection_options")
            if yaml_conn_opts:
                connection_options = deep_merge(connection_options, yaml_conn_opts)
                logger.debug(f"Device {sw.name} ({platform_name}): merged platform connection_options")

            # Добавляем connection_options только если есть настройки
            if connection_options['netmiko']['extras']:
                inventory_entry['connection_options'] = connection_options

            inventory[sw.name] = inventory_entry
            logger.debug(f"Added {sw.name} with creds from tag to inventory")

        logger.info(f"Built inventory for {len(inventory)} switches (tag-based auth)")
        return inventory

    def _select_credentials_for_device(self, device) -> Optional[dict]:
        """
        Pick proper credentials based on device tags.
        Returns:
            dict(username=..., password=...) or None if no suitable tag.
        """
        try:
            device_tags = device.tags or []
            tag_slugs = {tag.slug for tag in device_tags}

        except AttributeError as e:
            logger.error(f"Device {device.name}: unexpected tag format: {str(e)}")
            return None

        for tag_slug, env_suffix in config.TAG_CREDENTIALS.items():
            if tag_slug in tag_slugs:
                user = os.getenv(f"DEVICE_USERNAME_{env_suffix}")
                pwd  = os.getenv(f"DEVICE_PASSWORD_{env_suffix}")
                if user and pwd:
                    return {"username": user, "password": pwd}
                logger.warning(
                    f"Credentials for tag '{tag_slug}' missing "
                    f"(DEVICE_USERNAME_{env_suffix}/DEVICE_PASSWORD_{env_suffix})"
                )
                return None
        # No recognised tag
        return None

    def _correlate_arp_mac_ports(self):
        """Шаг 6: Сопоставление ARP ↔ MAC ↔ порты."""
        logger.info("Correlating ARP entries with MAC tables and switch ports")

        for site in self.prefixes_by_site.keys():
            arp_table = self.arp_tables.get(site, {})
            mac_tables = self.mac_tables.get(site, {})

            if not arp_table or not mac_tables:
                logger.warning(f"Missing ARP or MAC data for site {site}, skipping correlation")
                continue

            # Получаем информацию для логирования
            netbox_prefixes = len(self.prefixes_by_site.get(site, []))
            gateways_list = self.gateways_by_site.get(site, [])
            gateway_prefixes = sum(len(gw.get('prefixes', [])) for gw in gateways_list)

            logger.info(f"Correlating {len(arp_table)} ARP entries with MAC tables for site {site}")
            logger.info(f"Target prefixes: {netbox_prefixes} from NetBox, {gateway_prefixes} from gateway config")

            matched_count = 0

            # Проходим по ARP-записям
            for ip, mac in arp_table.items():
                # Проверяем, принадлежит ли IP к нашим префиксам
                if not self._ip_belongs_to_target_prefixes(ip, site):
                    continue

                # Ищем этот MAC в MAC-таблицах коммутаторов
                for switch_name, mac_entries in mac_tables.items():
                    for mac_entry in mac_entries:
                        if mac_entry['mac'].upper() == mac.upper():
                            # Найдено совпадение!
                            result = {
                                'site': site,
                                'ip_address': ip,
                                'mac_address': mac,
                                'switch': switch_name,
                                'interface': mac_entry['interface'],
                                'vlan': mac_entry.get('vlan', ''),
                                'mac_type': mac_entry.get('type', 'dynamic'),
                            }
                            self.mapping_results.append(result)
                            matched_count += 1

                            if self.verbose:
                                logger.info(f"Mapped {ip} ({mac}) → {switch_name}:{mac_entry['interface']}")

            self.agg.inc(f"site_{site}_mappings", matched_count)
            logger.info(f"Site {site}: found {matched_count} mappings")

        self.agg.inc("total_correlations", len(self.mapping_results))
        logger.info(f"Correlation completed. Found {len(self.mapping_results)} mappings")

    def _ip_belongs_to_target_prefixes(self, ip: str, site: str) -> bool:
        """
        Проверка, принадлежит ли IP-адрес к целевым префиксам площадки.

        Args:
            ip: IP-адрес для проверки
            site: Площадка

        Returns:
            bool: True если IP принадлежит одному из целевых префиксов
        """
        try:
            ip_obj = ipaddress.ip_address(ip)

            # Проверяем префиксы из NetBox
            for prefix_obj in self.prefixes_by_site.get(site, []):
                prefix_network = ipaddress.ip_network(str(prefix_obj.prefix))
                if ip_obj in prefix_network:
                    logger.debug(f"IP {ip} matches NetBox prefix {prefix_obj.prefix}")
                    return True

            logger.debug(f"IP {ip} does not match any target prefixes for site {site}")
            return False

        except (ipaddress.AddressValueError, ValueError) as e:
            logger.debug(f"Invalid IP address '{ip}': {str(e)}")
            return False

    def _filter_ports_for_netbox_update(self):
        """
        Фильтрует mapping_results для обновления NetBox.

        Исключает порты с количеством уникальных (MAC, VLAN) пар > threshold.
        Один MAC в разных VLAN считается как несколько записей (признак uplink).

        Строит:
            self.mapping_filtered – список для NetBox обновлений
            статистику для aggregator
        """
        logger.info("Filtering ports for NetBox updates")

        # Подсчитываем уникальные (MAC, VLAN) пары на каждом интерфейсе
        mac_vlan_counter = defaultdict(set)
        for rec in self.mapping_results:
            key = (rec['switch'], rec['interface'])
            # Создаем tuple (MAC, VLAN) для точного подсчета
            mac_vlan_pair = (rec['mac_address'], rec.get('vlan', ''))
            mac_vlan_counter[key].add(mac_vlan_pair)

        # Применяем фильтр
        filtered_results = []
        excluded_count = 0
        threshold = config.PORT_FILTER['mac_threshold']

        for rec in self.mapping_results:
            key = (rec['switch'], rec['interface'])
            mac_vlan_count = len(mac_vlan_counter[key])

            if mac_vlan_count <= threshold:
                filtered_results.append(rec)
            else:
                excluded_count += 1
                if self.verbose:
                    unique_pairs = mac_vlan_counter[key]
                    logger.debug(f"Port excluded from updates: {rec['switch']}:{rec['interface']} "
                               f"({mac_vlan_count} MAC-VLAN pairs: {list(unique_pairs)[:3]}...)")

        self.mapping_filtered = filtered_results

        # Обновляем метрики
        self.agg.inc("ports_excluded_from_updates", excluded_count)
        self.agg.inc("ports_selected_for_updates", len(filtered_results))

        logger.info(f"Port filtering completed: {len(filtered_results)} ports selected for updates, {excluded_count} ports excluded")

    def _save_results(self):
        """Шаг 7: Сохранение результатов в CSV."""
        # 1. Определяем, куда писать
        raw_path = Path(self.output_file)
        if raw_path.parent == Path("."):           # путь не содержит каталога
            results_dir = Path("results")
            results_dir.mkdir(exist_ok=True)
            output_path = results_dir / raw_path.name
        else:
            # путь уже содержит папки → создаём их, если надо
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            output_path = raw_path

        # Сохраняем финальный путь для использования в main.py
        self.final_output_path = output_path

        logger.info(f"Saving results to {output_path}")

        # 2. Нечего сохранять — нечего делать
        if not self.mapping_results:
            logger.warning("No mapping results to save")
            return

        # 3. Пишем CSV
        try:
            df = pd.DataFrame(self.mapping_results)
            df.to_csv(output_path, index=False, sep=self.csv_delimiter, encoding="utf-8")

            logger.info(f"Results saved: {output_path}")
            logger.info("Summary:")
            logger.info(f"  Total mappings     : {len(self.mapping_results)}")
            logger.info(f"  Sites processed    : {df['site'].nunique()}")
            logger.info(f"  Switches involved  : {df['switch'].nunique()}")
            logger.info(f"  Unique VLANs       : {df['vlan'].nunique()}")

        except Exception as exc:
            logger.error(f"Failed to save results: {exc}")
            raise
    
    def _save_filtered_results(self):
        """Сохранение отфильтрованных результатов в отдельный CSV."""
        if not config.PORT_FILTER['enabled'] or not self.mapping_filtered:
            return
    
        # Формируем имя файла с суффиксом
        base_path = Path(self.final_output_path)
        suffix = config.PORT_FILTER['save_suffix']
        filtered_filename = f"{base_path.stem}{suffix}{base_path.suffix}"
        filtered_path = base_path.parent / filtered_filename
    
        logger.info(f"Saving filtered results to {filtered_path}")
    
        try:
            df = pd.DataFrame(self.mapping_filtered)
            df.to_csv(filtered_path, index=False, sep=self.csv_delimiter, encoding="utf-8")
    
            logger.info(f"Filtered results saved: {filtered_path}")
            logger.info("Filtered summary:")
            logger.info(f"  Selected mappings  : {len(self.mapping_filtered)}")
            logger.info(f"  Sites processed    : {df['site'].nunique()}")
            logger.info(f"  Switches involved  : {df['switch'].nunique()}")
    
        except Exception as exc:
            logger.error(f"Failed to save filtered results: {exc}")

    def _update_netbox_descriptions(self):
        """Шаг 8: Обновление описаний интерфейсов в NetBox."""
        logger.info("Updating NetBox interface descriptions (batch mode)")
        batch_size = config.APP_DEFAULTS.get('nb_batch_size', 400)

        # Используем отфильтрованные результаты
        results_to_update = self.mapping_filtered if config.PORT_FILTER['enabled'] else self.mapping_results

        if not results_to_update:
            logger.warning("No ports selected for NetBox updates")
            return

        logger.info(f"Updating {len(results_to_update)} port descriptions in NetBox")

        with NetboxBatchUpdater(batch_size=batch_size,
                                overwrite_existing=self.overwrite_existing_descriptions) as upd:
            for res in results_to_update:
                descr = f"Host: {res['ip_address']} (MAC: {res['mac_address']})"
                upd.queue(device_name=res['switch'],
                          if_name=res['interface'],
                          new_descr=descr)

            upd.flush()

        # метрики
        self.agg.inc("netbox_updates_ok", upd.stats['updated'])
        self.agg.inc("netbox_updates_fail", upd.stats['failed'])
        self.agg.inc("netbox_updates_skipped", upd.stats['skipped'])
        self.agg.inc("netbox_updates_unchanged", upd.stats['unchanged'])
        self.agg.inc("netbox_updates_not_found", upd.stats['not_found'])

        logger.info(f"Batch NetBox update finished. Interfaces updated: {upd.stats['updated']}")

def deep_merge(a: dict, b: dict) -> dict:
    """Рекурсивное слияние словарей (b поверх a)."""
    result = deepcopy(a)
    for k, v in b.items():
        if k in result and isinstance(result[k], Mapping) and isinstance(v, Mapping):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = deepcopy(v)
    return result