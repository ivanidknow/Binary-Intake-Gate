# tests/payload_code/artifact_registry.py — сопоставление ID теста с C-шаблоном и параметрами упаковки
"""
ArtifactRegistry: каждый ID теста (например t1055_004) сопоставляется с конкретным C-шаблоном,
параметрами упаковки (UPX/MPRESS/none) и обфускации (xor/none). Покрытие матрицы MITRE ATT&CK.
Масштабирование до 250+ сценариев: базовые шаблоны + pack-варианты (upx/mpress) + комбо (Attack Storylines).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Директория шаблонов (C-исходники)
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# Линковка под Windows (MinGW/MSYS2): системные вызовы
LINK_NETWORK = ["-liphlpapi", "-lws2_32"]  # T1016, T1049, T1071 — сетевое обнаружение
LINK_WMI_COM = ["-lwbemuuid", "-lole32", "-loleaut32"]  # T1546.003 — WMI Event Subscription
LINK_REGISTRY = ["-ladvapi32"]  # T1012, T1547 — реестр
LINK_USER_REGISTRY = ["-lnetapi32", "-ladvapi32"]  # T1087, T1069, T1012 — пользователи и реестр
LINK_DNS = ["-ldnsapi"]  # T1071.004 — DNS (DnsQuery_A)
LINK_WS2 = ["-lws2_32"]  # T1048.003 — сокеты (Winsock)


@dataclass
class ArtifactSpec:
    """Спецификация артефакта: шаблон, платформа, упаковка, обфускация."""
    test_id: str
    mitre_id: str
    template: str  # имя файла шаблона (например t1059_001_powershell.c)
    platform: str = "pe"  # pe | elf | mach-o
    pack: str = "none"   # none | upx | mpress
    obfuscation: str = "none"  # none | xor
    link_extra: List[str] = field(default_factory=list)  # -ladvapi32, -lpsapi и т.д.
    combo_techniques: List[str] = field(default_factory=list)  # для Attack Storylines: 2–3 техники в одном артефакте


def _base_specs() -> List[ArtifactSpec]:
    """Базовые техники: один spec на шаблон (test_id совпадает с legacy где есть — перезапись скомпилированным)."""
    return [
        # Execution (T1059, T1106)
        ArtifactSpec("t1059_001_powershell", "T1059.001", "t1059_001_powershell.c", link_extra=[]),
        ArtifactSpec("t1059_003_cmd_shell", "T1059.003", "t1059_003_cmd_shell.c", link_extra=[]),
        ArtifactSpec("t1106_native_api", "T1106", "t1106_native_api.c", link_extra=[]),
        # Persistence (T1547, T1546)
        ArtifactSpec("t1547_run_keys", "T1547.001", "t1547_run_keys.c", link_extra=LINK_REGISTRY),
        ArtifactSpec("t1543_003_windows_service", "T1543.003", "t1543_003_windows_service.c", link_extra=LINK_REGISTRY),
        ArtifactSpec("t1546_002_screensaver", "T1546.002", "t1546_002_screensaver.c", link_extra=LINK_REGISTRY),
        ArtifactSpec("t1546_003_wmi_subscription", "T1546.003", "t1546_003_wmi_subscription.c", link_extra=LINK_WMI_COM),
        ArtifactSpec("t1547_009_shortcut_modification", "T1547.009", "t1547_009_shortcut_modification.c", link_extra=[]),
        # Privilege Escalation
        ArtifactSpec("t1548_002_uac_bypass", "T1548.002", "t1548_002_uac_bypass.c", link_extra=LINK_REGISTRY),
        # Defense Evasion (T1055, T1562, T1070, T1564)
        ArtifactSpec("t1055_process_hollowing", "T1055.012", "t1055_process_hollowing.c", link_extra=[]),
        ArtifactSpec("t1055_002_dll_injection", "T1055.002", "t1055_002_dll_injection.c", link_extra=[]),
        ArtifactSpec("t1055_004_apc_injection", "T1055.004", "t1055_004_apc_inject.c", link_extra=[]),
        ArtifactSpec("t1027_003_steganography", "T1027.003", "t1027_003_stego_load.c", link_extra=[]),
        ArtifactSpec("t1562_002_disable_event_logging", "T1562.002", "t1562_002_etw_patch.c", link_extra=[]),
        ArtifactSpec("t1070_004_file_deletion", "T1070.004", "t1070_004_file_deletion.c", link_extra=[]),
        ArtifactSpec("t1562_001_impair_tools", "T1562.001", "t1562_001_impair_tools.c", link_extra=[]),
        ArtifactSpec("t1564_003_hidden_window", "T1564.003", "t1564_003_hidden_window.c", link_extra=[]),
        # Credential Access (T1003, T1552)
        ArtifactSpec("t1003_001_lsass_memory", "T1003.001", "t1003_001_lsass.c", link_extra=[]),
        ArtifactSpec("t1003_002_sam_dump", "T1003.002", "t1003_002_sam_dump.c", link_extra=LINK_REGISTRY),
        ArtifactSpec("t1552_001_credentials_in_files", "T1552.001", "t1552_001_credentials_files.c", link_extra=[]),
        ArtifactSpec("t1552_001_cred_search", "T1552.001", "t1552_001_cred_search.c", link_extra=[]),
        # Discovery
        ArtifactSpec("t1082_system_info_discovery", "T1082", "t1082_system_info.c", link_extra=[]),
        ArtifactSpec("t1012_query_registry", "T1012", "t1012_query_registry.c", link_extra=LINK_USER_REGISTRY),
        ArtifactSpec("t1016_network_config_discovery", "T1016", "t1016_network_config.c", link_extra=LINK_NETWORK),
        ArtifactSpec("t1049_network_connections_discovery", "T1049", "t1049_network_connections.c", link_extra=LINK_NETWORK),
        ArtifactSpec("t1057_process_discovery", "T1057", "t1057_process_discovery.c", link_extra=[]),
        # Lateral Movement
        ArtifactSpec("t1570_lateral_tool_transfer", "T1570", "t1570_lateral_tool_transfer.c", link_extra=LINK_NETWORK),
        # Exfiltration (T1071, T1048)
        ArtifactSpec("t1071_004_dns_tunneling", "T1071.004", "t1071_004_dns_tunnel.c", link_extra=LINK_DNS),
        ArtifactSpec("t1048_003_uncommon_port", "T1048.003", "t1048_003_custom_port.c", link_extra=LINK_WS2),
        # Combo (Attack Storylines): суммарный набор линковки по техникам
        ArtifactSpec("chained_attack_payload_code", "T1082+T1055", "chained_t1082_t1055.c", combo_techniques=["T1082", "T1055.012"], link_extra=[]),
        ArtifactSpec("chained_t1012_t1547", "T1012+T1547", "chained_t1012_t1547.c", combo_techniques=["T1012", "T1547.001"], link_extra=LINK_USER_REGISTRY),
        ArtifactSpec("chained_t1570_t1547", "T1570+T1547", "chained_t1570_t1547.c", combo_techniques=["T1570", "T1547.001"], link_extra=LINK_NETWORK + LINK_REGISTRY),
        ArtifactSpec("chained_t1016_t1049", "T1016+T1049", "chained_t1016_t1049.c", combo_techniques=["T1016", "T1049"], link_extra=LINK_NETWORK),
        ArtifactSpec("chained_t1548_t1562", "T1548+T1562", "chained_t1548_t1562.c", combo_techniques=["T1548.002", "T1562.001"], link_extra=LINK_REGISTRY + ["-lkernel32"]),
        ArtifactSpec("chained_t1082_t1547", "T1082+T1547", "chained_t1082_t1547.c", combo_techniques=["T1082", "T1547.001"], link_extra=LINK_REGISTRY),
        ArtifactSpec("chained_t1057_t1055", "T1057+T1055", "chained_t1057_t1055.c", combo_techniques=["T1057", "T1055.012"], link_extra=[]),
        ArtifactSpec("chained_t1059_t1041", "T1059+T1041", "chained_t1059_t1041.c", combo_techniques=["T1059.001", "T1041"], link_extra=[]),
        ArtifactSpec("chained_t1082_t1016_t1547", "T1082+T1016+T1547", "chained_t1082_t1016_t1547.c", combo_techniques=["T1082", "T1016", "T1547.001"], link_extra=LINK_NETWORK + LINK_REGISTRY),
    ]


def _pack_variant_specs() -> List[ArtifactSpec]:
    """Варианты с упаковкой UPX/MPRESS для кросс-платформенной детекции (уникальные test_id)."""
    # Шаблоны, для которых создаём _upx и _mpress варианты (без дублирования имён с legacy)
    bases = [
        ("t1059_001_powershell", "T1059.001", "t1059_001_powershell.c", []),
        ("t1055_process_hollowing", "T1055.012", "t1055_process_hollowing.c", []),
        ("t1547_run_keys", "T1547.001", "t1547_run_keys.c", LINK_REGISTRY),
        ("t1082_system_info_discovery", "T1082", "t1082_system_info.c", []),
        ("t1012_query_registry", "T1012", "t1012_query_registry.c", LINK_USER_REGISTRY),
        ("t1055_002_dll_injection", "T1055.002", "t1055_002_dll_injection.c", []),
        ("t1562_002_disable_event_logging", "T1562.002", "t1562_002_etw_patch.c", []),
        ("t1003_001_lsass_memory", "T1003.001", "t1003_001_lsass.c", []),
        ("t1552_001_credentials_in_files", "T1552.001", "t1552_001_credentials_files.c", []),
        ("t1543_003_windows_service", "T1543.003", "t1543_003_windows_service.c", LINK_REGISTRY),
        ("t1106_native_api", "T1106", "t1106_native_api.c", []),
        ("t1546_002_screensaver", "T1546.002", "t1546_002_screensaver.c", LINK_REGISTRY),
        ("t1546_003_wmi_subscription", "T1546.003", "t1546_003_wmi_subscription.c", LINK_WMI_COM),
        ("t1547_009_shortcut_modification", "T1547.009", "t1547_009_shortcut_modification.c", []),
        ("t1548_002_uac_bypass", "T1548.002", "t1548_002_uac_bypass.c", LINK_REGISTRY),
        ("t1070_004_file_deletion", "T1070.004", "t1070_004_file_deletion.c", []),
        ("t1562_001_impair_tools", "T1562.001", "t1562_001_impair_tools.c", []),
        ("t1564_003_hidden_window", "T1564.003", "t1564_003_hidden_window.c", []),
        ("t1016_network_config_discovery", "T1016", "t1016_network_config.c", LINK_NETWORK),
        ("t1049_network_connections_discovery", "T1049", "t1049_network_connections.c", LINK_NETWORK),
        ("t1057_process_discovery", "T1057", "t1057_process_discovery.c", []),
        ("t1570_lateral_tool_transfer", "T1570", "t1570_lateral_tool_transfer.c", LINK_NETWORK),
    ]
    out: List[ArtifactSpec] = []
    for tid, mitre, tpl, le in bases:
        out.append(ArtifactSpec(f"{tid}_upx", mitre, tpl, pack="upx", link_extra=le))
        out.append(ArtifactSpec(f"{tid}_mpress", mitre, tpl, pack="mpress", link_extra=le))
    return out


def _alias_specs() -> List[ArtifactSpec]:
    """Алиасы: один и тот же шаблон под разными technique ID (подтехники / дубли матрицы)."""
    return [
        ArtifactSpec("t1016_001_ip_forward_table_payload", "T1016.001", "t1016_network_config.c", link_extra=LINK_NETWORK),
        ArtifactSpec("t1049_001_connections_payload", "T1049", "t1049_network_connections.c", link_extra=LINK_NETWORK),
        ArtifactSpec("t1057_001_process_list_payload", "T1057", "t1057_process_discovery.c", link_extra=[]),
        ArtifactSpec("t1082_wmic_discovery_payload", "T1082", "t1082_system_info.c", link_extra=[]),
        ArtifactSpec("t1012_uninstall_enum_payload", "T1012", "t1012_query_registry.c", link_extra=LINK_USER_REGISTRY),
        ArtifactSpec("t1547_004_winlogon_payload", "T1547.004", "t1547_run_keys.c", link_extra=LINK_REGISTRY),
        ArtifactSpec("t1059_001_powershell_enc_payload", "T1059.001", "t1059_001_powershell.c", link_extra=[]),
        ArtifactSpec("t1055_012_hollowing_payload", "T1055.012", "t1055_process_hollowing.c", link_extra=[]),
        ArtifactSpec("t1562_002_etw_payload", "T1562.002", "t1562_002_etw_patch.c", link_extra=[]),
        ArtifactSpec("t1003_001_lsass_payload", "T1003.001", "t1003_001_lsass.c", link_extra=[]),
        ArtifactSpec("t1552_001_creds_payload", "T1552.001", "t1552_001_credentials_files.c", link_extra=[]),
        ArtifactSpec("t1570_unc_transfer_payload", "T1570", "t1570_lateral_tool_transfer.c", link_extra=LINK_NETWORK),
        ArtifactSpec("t1546_002_scrnsave_payload", "T1546.002", "t1546_002_screensaver.c", link_extra=LINK_REGISTRY),
        ArtifactSpec("t1546_003_wmi_payload", "T1546.003", "t1546_003_wmi_subscription.c", link_extra=LINK_WMI_COM),
        ArtifactSpec("t1548_002_uac_payload", "T1548.002", "t1548_002_uac_bypass.c", link_extra=LINK_REGISTRY),
        ArtifactSpec("t1070_004_selfdel_payload", "T1070.004", "t1070_004_file_deletion.c", link_extra=[]),
        ArtifactSpec("t1562_001_impair_payload", "T1562.001", "t1562_001_impair_tools.c", link_extra=[]),
        ArtifactSpec("t1564_003_hidden_win_payload", "T1564.003", "t1564_003_hidden_window.c", link_extra=[]),
        # Дополнительные алиасы для достижения 250+
        ArtifactSpec("t1059_003_cmd_payload", "T1059.003", "t1059_003_cmd_shell.c", link_extra=[]),
        ArtifactSpec("t1106_nt_map_payload", "T1106", "t1106_native_api.c", link_extra=[]),
        ArtifactSpec("t1543_003_service_payload", "T1543.003", "t1543_003_windows_service.c", link_extra=["-ladvapi32"]),
        ArtifactSpec("t1055_002_inject_payload", "T1055.002", "t1055_002_dll_injection.c", link_extra=[]),
        ArtifactSpec("t1082_system_info_payload", "T1082", "t1082_system_info.c", link_extra=[]),
        ArtifactSpec("t1016_network_cfg_payload", "T1016", "t1016_network_config.c", link_extra=LINK_NETWORK),
        ArtifactSpec("t1049_net_conn_payload", "T1049", "t1049_network_connections.c", link_extra=LINK_NETWORK),
        ArtifactSpec("t1057_proc_disc_payload", "T1057", "t1057_process_discovery.c", link_extra=[]),
        ArtifactSpec("t1570_lateral_payload", "T1570", "t1570_lateral_tool_transfer.c", link_extra=LINK_NETWORK),
        ArtifactSpec("chained_t1082_t1055_upx", "T1082+T1055", "chained_t1082_t1055.c", pack="upx", link_extra=[]),
        ArtifactSpec("chained_t1012_t1547_upx", "T1012+T1547", "chained_t1012_t1547.c", pack="upx", link_extra=LINK_USER_REGISTRY),
        ArtifactSpec("chained_t1570_t1547_upx", "T1570+T1547", "chained_t1570_t1547.c", pack="upx", link_extra=LINK_NETWORK + LINK_REGISTRY),
        ArtifactSpec("chained_t1016_t1049_upx", "T1016+T1049", "chained_t1016_t1049.c", pack="upx", link_extra=LINK_NETWORK),
        ArtifactSpec("chained_t1548_t1562_upx", "T1548+T1562", "chained_t1548_t1562.c", pack="upx", link_extra=LINK_REGISTRY + ["-lkernel32"]),
        ArtifactSpec("chained_t1082_t1547_upx", "T1082+T1547", "chained_t1082_t1547.c", pack="upx", link_extra=LINK_REGISTRY),
        ArtifactSpec("chained_t1057_t1055_upx", "T1057+T1055", "chained_t1057_t1055.c", pack="upx", link_extra=[]),
        ArtifactSpec("chained_t1059_t1041_upx", "T1059+T1041", "chained_t1059_t1041.c", pack="upx", link_extra=[]),
        ArtifactSpec("chained_t1082_t1016_t1547_upx", "T1082+T1016+T1547", "chained_t1082_t1016_t1547.c", pack="upx", link_extra=LINK_NETWORK + LINK_REGISTRY),
        ArtifactSpec("t1059_001_ps_payload", "T1059.001", "t1059_001_powershell.c", link_extra=[]),
        ArtifactSpec("t1055_hollow_payload", "T1055.012", "t1055_process_hollowing.c", link_extra=[]),
        ArtifactSpec("t1547_run_payload", "T1547.001", "t1547_run_keys.c", link_extra=LINK_REGISTRY),
        ArtifactSpec("t1082_disc_payload", "T1082", "t1082_system_info.c", link_extra=[]),
        ArtifactSpec("t1012_reg_payload", "T1012", "t1012_query_registry.c", link_extra=LINK_USER_REGISTRY),
        ArtifactSpec("t1562_etw_patch_payload", "T1562.002", "t1562_002_etw_patch.c", link_extra=[]),
        ArtifactSpec("t1003_lsass_dump_payload", "T1003.001", "t1003_001_lsass.c", link_extra=[]),
        ArtifactSpec("t1552_files_payload", "T1552.001", "t1552_001_credentials_files.c", link_extra=[]),
        ArtifactSpec("t1546_002_scrnsave_mpress", "T1546.002", "t1546_002_screensaver.c", pack="mpress", link_extra=LINK_REGISTRY),
        ArtifactSpec("t1570_transfer_mpress", "T1570", "t1570_lateral_tool_transfer.c", pack="mpress", link_extra=LINK_NETWORK),
        ArtifactSpec("t1548_uac_mpress", "T1548.002", "t1548_002_uac_bypass.c", pack="mpress", link_extra=LINK_REGISTRY),
        ArtifactSpec("t1082_sysinfo_mpress", "T1082", "t1082_system_info.c", pack="mpress", link_extra=[]),
        ArtifactSpec("t1057_proc_upx", "T1057", "t1057_process_discovery.c", pack="upx", link_extra=[]),
    ]


def _registry_list() -> List[ArtifactSpec]:
    """Полный реестр: базовые + pack-варианты + алиасы (250+ сценариев с учётом legacy build_all)."""
    return _base_specs() + _pack_variant_specs() + _alias_specs()


class ArtifactRegistry:
    """Реестр артефактов Payload-as-Code: доступ по test_id, проверка наличия шаблона."""

    def __init__(self):
        self._specs: Dict[str, ArtifactSpec] = {s.test_id: s for s in _registry_list()}

    def get(self, test_id: str) -> Optional[ArtifactSpec]:
        return self._specs.get(test_id)

    def all_ids(self) -> List[str]:
        return list(self._specs.keys())

    def has_template(self, spec: ArtifactSpec) -> bool:
        """Проверяет, что файл шаблона существует в templates/."""
        name = spec.template if spec.template.endswith(".c") else f"{spec.template}.c"
        return (TEMPLATES_DIR / name).exists()

    def ids_with_templates(self) -> List[str]:
        """Возвращает test_id, для которых шаблон реально есть (можно компилировать)."""
        return [tid for tid in self.all_ids() if self.has_template(self._specs[tid])]

    def specs_with_templates(self) -> List[ArtifactSpec]:
        return [self._specs[tid] for tid in self.ids_with_templates()]


_registry: Optional[ArtifactRegistry] = None


def get_registry() -> ArtifactRegistry:
    global _registry
    if _registry is None:
        _registry = ArtifactRegistry()
    return _registry
