"""
Адаптеры для интеграции с внешними системами
"""

from .netbox_adapter import NetboxAdapter
from .snmp_adapter import SNMPAdapter  
from .nornir_adapter import NornirAdapter

try:
    from .prtg_adapter import PRTGAdapter  
except ImportError as e:
    print(f"Warning: Could not import PRTGAdapter: {e}")
    PRTGAdapter = None

__all__ = ['NetboxAdapter', 'SNMPAdapter', 'NornirAdapter']

# Добавляем в __all__ только успешно импортированные адаптеры
if PRTGAdapter:
    __all__.append('PRTGAdapter')