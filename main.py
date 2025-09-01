import click
import sys
from pathlib import Path

from dotenv import load_dotenv

# Добавляем custom_modules в путь (для разработки, если не установлено через pip)
custom_modules_path = Path(__file__).parent.parent / "custom_modules"
if custom_modules_path.exists():
    sys.path.insert(0, str(custom_modules_path))

from custom_modules.log import setup_logger
from custom_modules.error_aggregator import ErrorAggregator
from workflow import ARPPortMapperWorkflow
import config

load_dotenv()

@click.command()
@click.argument('prefix_roles', nargs=-1, required=True)
@click.option(
    '--output', '-o',
    default='arp_port_mapping.csv',
    help='Output CSV file path (default: arp_port_mapping.csv in results/ folder)'
)
@click.option(
    '--sites', '-s',
    multiple=True,
    help='Target sites (slugs) to process. Can be specified multiple times. If not specified, all sites will be processed.'
)
@click.option(
    '--verbose', '-v',
    is_flag=True,
    default=None,
    help='Enable verbose output (overrides config setting)'
)
@click.option(
    '--enable-session-log',
    is_flag=True,
    default=None,
    help='Enable Netmiko session logging for troubleshooting connection issues'
)
def cli(prefix_roles, output, sites, verbose, enable_session_log):
    """
    ARP Port Mapper - поиск портов коммутаторов для устройств из заданных подсетей.

    PREFIX_ROLES - роли префиксов для анализа (обязательный аргумент).

    Примеры использования:

    \b
    # Базовое использование - все площадки
    python main.py servers workstations

    \b
    # Только определенные площадки
    python main.py servers --sites moscow --sites spb

    \b
    # Кастомный файл результатов для конкретной площадки
    python main.py servers --sites datacenter-1 --output dc1_mapping.csv

    \b
    # С подробным выводом
    python main.py servers workstations --verbose --sites office-main

    \b
    # Отладка проблем с подключением (создает session_logs/)
    python main.py servers --enable-session-log --verbose

    \b
    # Комбинированный пример для проблемных площадок
    python main.py servers --sites problem-site --enable-session-log --verbose
    """

    # Инициализация агрегатора ошибок
    agg = ErrorAggregator()
    agg.reset()  # Сброс состояния для нового запуска

    # Настройка логирования из конфига
    logger = setup_logger(
        log_level=config.APP_DEFAULTS['log_level'], 
        log_dir='logs', 
        log_file='arp_mapper.log'
    )

    # Определяем verbose режим (приоритет у CLI аргумента)
    verbose_mode = verbose if verbose is not None else config.APP_DEFAULTS['verbose']

    # Определяем режим session logging
    session_log_mode = enable_session_log if enable_session_log is not None else config.APP_DEFAULTS.get('enable_session_log', False)

    # Преобразуем sites в список или None
    target_sites = list(sites) if sites else None

    logger.info("Starting ARP Port Mapper")
    logger.info(f"Prefix roles: {prefix_roles}")
    logger.info(f"Target sites: {target_sites or 'ALL'}")
    logger.info(f"Output file: {output}")
    logger.info(f"Verbose mode: {verbose_mode}")
    logger.info(f"Session logging: {'enabled' if session_log_mode else 'disabled'}")
    if session_log_mode:
        logger.info("Session logs will be saved to session_logs/ folder")

    try:
        # Создаем и запускаем workflow
        workflow = ARPPortMapperWorkflow(
            prefix_roles=list(prefix_roles),
            output_file=output,
            target_sites=target_sites,
            verbose=verbose_mode,
            enable_session_log=session_log_mode
        )

        # Выполняем основную логику
        results = workflow.run()

        logger.info(f"Mapping completed. Found {len(results)} entries.")
        logger.info(f"Results saved to {workflow.final_output_path}")

        if verbose_mode:
            sites_info = f" for sites: {', '.join(target_sites)}" if target_sites else " for all sites"
            click.echo(f"✅ Completed successfully{sites_info}")
            click.echo(f"📄 Results: {workflow.final_output_path}")
            click.echo(f"📊 Error summary: results/error_summary.json")
            print_session_log_summary(verbose_mode, session_log_mode)

    except Exception as e:
        logger.error(f"Error during execution: {str(e)}")
        agg.add("critical", "main_workflow", str(e))
        if verbose_mode:
            click.echo(f"❌ Error: {str(e)}", err=True)

        # Подсказка о session logs при ошибках
        if session_log_mode:
            click.echo("💡 See session_logs/ for troubleshooting details", err=True)
        sys.exit(1)
    finally:
        # Рендеринг отчета об ошибках
        try:
            agg.render()
        except Exception as render_error:
            logger.warning(f"Failed to render error summary: {str(render_error)}")

# --- helpers -----------------------------------------------------------
def print_session_log_summary(verbose: bool, session_log_enabled: bool) -> None:
    """
    Коротко выводит информацию о session-log-файлах, если они включены
    """
    if not (verbose and session_log_enabled):
        return

    from pathlib import Path
    session_dir = Path("session_logs")
    if not session_dir.exists():
        click.echo("🔍 Session-logs directory not found")
        return

    files = list(session_dir.glob("*_session.log"))
    if not files:
        click.echo("🔍 No session-log files were created")
        return

    total_size = sum(f.stat().st_size for f in files)
    click.echo(f"🔍 Session-logs: {len(files)} file(s), {total_size//1024} KB total")

    # показываем только первые 3 файла, чтобы не «шуметь»
    for f in sorted(files)[:3]:
        click.echo(f"   {f.name} ({f.stat().st_size//1024} KB)")
    if len(files) > 3:
        click.echo(f"   …and {len(files) - 3} more")

if __name__ == "__main__":
    cli()