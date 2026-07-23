"""Public API for the TLS scanner package."""

from .cli import has_cli_option, main, parse_args, print_dry_run, print_startup_banner
from .config import (
    build_cli_scan_job,
    build_config_scan_job,
    build_job_from_sections,
    build_scan_job,
    config_targets_to_cli_value,
    config_targets_to_list,
    detect_export_format,
    list_config_reports,
    load_named_policies,
    load_named_target_groups,
    load_policy_file,
    load_report_policies,
    load_report_targets,
    load_target_group_file,
    load_yaml_config,
    merge_mappings,
    parse_ports_config,
    require_mapping,
    select_config_report,
    validate_config_name,
)
from .constants import (
    ALLOWED_EXPORT_FORMATS,
    DEFAULT_CONFIG_FILE,
    DEFAULT_EXPORT_DIR,
    DEFAULT_LOG_FILE,
    DEFAULT_POLICIES_DIR,
    DEFAULT_TARGETS_DIR,
    LOG_LEVELS,
    MINIMUM_PQC_OPENSSL_VERSION,
    PQC_TLS_GROUPS,
    SAFE_CONFIG_NAME,
)
from .crypto_policy import (
    apply_endpoint_grades,
    calculate_host_grade,
    check_compliance,
    evaluate_compliance,
    extract_cipher_suites,
    extract_public_key,
    extract_signature_algorithm,
    grade_finding,
    is_cipher_suite_compliant,
)
from .exports.cbom import build_cbom
from .exports.csv_export import build_csv_export
from .exports.markdown_report import (
    append_bar_chart,
    build_host_compliance_summary,
    build_markdown_report,
    count_values,
    dashboard_bar,
    markdown_escape,
    percent,
    sort_port,
)
from .exports.paths import (
    build_export_paths,
    export_extension,
    local_report_timestamp,
    local_scan_timestamp,
    write_exports,
)
from .logging_config import configure_logging
from .models import ConfigError, EncryptionPolicy, PQCPrerequisiteError, ScanJob, TargetGroup
from .network import normalize_targets, parse_ports, resolve_fqdn, resolve_target_fqdns
from .pqc import (
    check_pqc_prerequisites,
    evaluate_pqc_compliance,
    format_openssl_endpoint,
    parse_openssl_version,
    probe_pqc_key_exchange,
)
from .scanner import collect_scan_results, discover_open_tcp_ports, load_dependencies, run_scan_with_progress
