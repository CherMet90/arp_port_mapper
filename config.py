# Основные настройки приложения
APP_DEFAULTS = {
    'device_roles': ['poe-switch', 'access-switch', 'server-switch', 'industrial-switch'],  # Роли устройств для опроса
    'gw_list_file': 'gw_list.csv',  # Файл с настройками шлюзов
    'update_netbox': False,  # Обновлять описания в NetBox
    'overwrite_existing_descriptions': False,  # Перезаписывать ли существующие описания
    'verbose': False,  # Подробный вывод
    'log_level': 'INFO',  # Уровень логирования
    'csv_delimiter': ';',  # Настраиваемый разделитель CSV
    'enable_fast_cli': True, # Глобально True, но per-platform override
    'enable_session_log': False, # По умолчанию выкл, для отладки
    'problem_platforms': ['zyxel_os'], # Список для fast_cli=False
    'enable_snmp_check_for_switches': False,  # Enable SNMP verification for switches (set to False to disable)
}

# Фильтрация портов для обновления NetBox
PORT_FILTER = {
    'enabled': True,
    'mac_threshold': 2,   # >2 уникальных MAC = исключить из обновления
    'save_suffix': '_filtered'
}

SNMP_MODELS_FILE = "models.list"

# Which tags map to which ENV-suffix
TAG_CREDENTIALS = {
    "backup-it": "BACKUP_IT",          #  DEVICE_USERNAME_BACKUP_IT / DEVICE_PASSWORD_BACKUP_IT
    "backup-it_admin": "BACKUP_IT_ADMIN"
}

# Настройки SNMP для шлюзов (по умолчанию)
GATEWAY_SNMP_CONFIG = {
    'community': 'public',
    'version': '2c',
    'timeout': 10,
    'retries': 3
}

# Настройки по умолчанию для устройств из PRTG
PRTG_DEVICE_DEFAULTS = {
    'community': 'public',
    'snmp': '1',
    'act': '',
    'site_slug': '',
    'role': '',
    'vm': '',
    'model_oid': ''
}

PRTG_TAG_MAPPING = {
    'snmp': {
        'snmp_v1': '1',
        'snmp_v2c': '2c', 
        'snmp_v3': '3',
    },
    'community': {
        'qwerty_community': 'Qwerty123',
        'ro_community': 'ro_community',
        'CAPSLOCK_community': 'PUBLIC',
    },
}

# Настройки интеграции с PRTG
PRTG_CONFIG = {
    'use_prtg': True,  # Использовать ли PRTG для SNMP настроек
    'import_tag': 'netbox',  # Тег для импорта
    'exclude_tag': 'no_netbox'  # Тег для исключения
}

# Настройки Nornir
NORNIR_CONFIG = {
    'config_file': 'config/nornir_config.yaml', # Путь к файлу конфигурации
    'num_workers': 10,
    'use_timing': True,
    'platform_parsers_file': 'platform_parsers.yaml',
    'log_level': 'INFO'
}
