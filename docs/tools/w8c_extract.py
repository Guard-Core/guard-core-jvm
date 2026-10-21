#!/usr/bin/env python3
"""Wave 8c every-feature matrix extractor.

Mechanically enumerates the guard_core (python reference) authored public
surface and maps each declaration to its guard-core-jvm (Kotlin) counterpart.
Outputs TSV rows: family, py_file, py_line, py_symbol, jvm_file, jvm_line,
status, note. Unmatched rows land in a MANUAL report for review.

Read-only on both trees.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass

PY_ROOT = (
    "/Users/renzof/Documents/GitHub/ZZZ/guard-core-ecosystem/Python/guard-core/guard_core"
)
JVM_ROOT = "/tmp/guard-core-jvm"
JVM_SRC = [
    os.path.join(JVM_ROOT, "guard-core/src/main/kotlin"),
    os.path.join(JVM_ROOT, "guard-core-engine/src/main/kotlin"),
]
CONFORMANCE_SRC = os.path.join(
    JVM_ROOT, "guard-core-conformance/src/main/kotlin"
)

EXCLUDE_DIRS = {"__pycache__", "sync"}


# ---------------------------------------------------------------------------
# Module map: python relpath -> kotlin relpaths (verified against wave docs)
# ---------------------------------------------------------------------------

F = "guard-core/src/main/kotlin/com/guardcore"
E = "guard-core-engine/src/main/kotlin/com/guardcore/engine"

MODULE_MAP: dict[str, list[str]] = {
    # --- config family ---
    "models.py": [f"{F}/config/SecurityConfig.kt", f"{F}/config/SecurityConfigBuilder.kt", f"{F}/config/ConfigSeams.kt"],
    "_security_config_fields.py": [f"{F}/config/ConfigFieldRegistry.kt"],
    "_security_config_field_validators.py": [f"{F}/config/ConfigValidators.kt"],
    "_security_config_validators.py": [f"{F}/config/ConfigValidators.kt", f"{F}/config/RuleConfigs.kt"],
    "_security_config_geo_validators.py": [f"{F}/config/ConfigValidators.kt"],
    "_security_config_typed_validators.py": [f"{F}/config/ConfigValidators.kt"],
    "_config_field_revalidators.py": [f"{F}/config/ConfigValidators.kt", f"{F}/config/SecurityConfig.kt"],
    "_config_capabilities.py": [f"{F}/config/ConfigFieldRegistry.kt", f"{F}/config/ConfigSeams.kt"],
    "_pydantic_plugin_mute.py": [f"{F}/config/ConfigSeams.kt", f"{F}/core/events/SecurityEventEnvelope.kt"],
    "_dynamic_rules.py": [f"{F}/handlers/DynamicRules.kt", f"{F}/config/RuleConfigs.kt"],
    "exceptions.py": [f"{F}/errors/Errors.kt"],
    "detection_result.py": [f"{F}/DetectionResult.kt"],
    "utils.py": [f"{F}/util/LoggingUtils.kt", f"{F}/GuardCore.kt", f"{F}/util/IdentityHash.kt"],
    "__init__.py": [f"{F}/GuardCore.kt"],
    # --- protocols ---
    "protocols/__init__.py": [f"{F}/protocols/Protocols.kt"],
    "protocols/agent_protocol.py": [f"{F}/protocols/AgentProtocol.kt"],
    "protocols/cloud_ip_store_protocol.py": [f"{F}/protocols/CloudIpStoreProtocol.kt"],
    "protocols/geo_ip_protocol.py": [f"{F}/protocols/GeoIpProtocol.kt"],
    "protocols/middleware_protocol.py": [f"{F}/protocols/MiddlewareProtocol.kt"],
    "protocols/redis_protocol.py": [f"{F}/protocols/RedisProtocol.kt"],
    "protocols/request_protocol.py": [f"{F}/protocols/RequestProtocol.kt"],
    "protocols/response_protocol.py": [f"{F}/protocols/ResponseProtocol.kt"],
    # --- _utils ---
    "_utils/__init__.py": [f"{F}/util/"],
    "_utils/access_control.py": [f"{F}/util/AccessControl.kt"],
    "_utils/agent_events.py": [f"{F}/util/AgentEvents.kt"],
    "_utils/block_events.py": [f"{F}/util/BlockEvents.kt"],
    "_utils/body_content_scan.py": [f"{F}/util/BodyContentScan.kt"],
    "_utils/body_form_scan.py": [f"{F}/util/BodyFormScan.kt"],
    "_utils/body_json_scan.py": [f"{F}/util/BodyJsonScan.kt"],
    "_utils/body_reader.py": [f"{F}/util/BodyReader.kt"],
    "_utils/detection_config.py": [f"{F}/util/DetectionConfig.kt"],
    "_utils/detection_result_builders.py": [f"{F}/util/DetectionResultBuilders.kt"],
    "_utils/detection_scan.py": [f"{F}/util/DetectionScan.kt", f"{F}/util/DetectionScanBudget.kt", f"{F}/util/DetectionScanContext.kt"],
    "_utils/embedded_json_scan.py": [f"{F}/util/EmbeddedJsonScan.kt"],
    "_utils/identity_hash.py": [f"{F}/util/IdentityHash.kt"],
    "_utils/ip_extraction.py": [f"{F}/util/IpExtraction.kt"],
    "_utils/logging_utils.py": [f"{F}/util/LoggingUtils.kt"],
    "_utils/lru_store.py": [f"{F}/util/LruStore.kt"],
    "_utils/pair_hidden_assign.py": [f"{F}/util/PairHiddenAssign.kt"],
    "_utils/pair_redaction.py": [f"{F}/util/PairRedaction.kt"],
    "_utils/pair_value_scan.py": [f"{F}/util/PairValueScan.kt"],
    "_utils/penetration_detection.py": [f"{F}/util/PenetrationDetection.kt"],
    "_utils/request_logging.py": [f"{F}/util/RequestLogging.kt"],
    # --- handlers ---
    "handlers/__init__.py": [f"{F}/handlers/"],
    "handlers/behavior_handler.py": [f"{F}/handlers/BehaviorTracker.kt"],
    "handlers/_behavior_action_dispatch.py": [f"{F}/handlers/BehaviorActionDispatch.kt"],
    "handlers/_behavior_json_pattern.py": [f"{F}/handlers/BehaviorResponsePattern.kt"],
    "handlers/_behavior_response_pattern.py": [f"{F}/handlers/BehaviorResponsePattern.kt"],
    "handlers/cloud_handler.py": [f"{F}/handlers/CloudManager.kt"],
    "handlers/_cloud_azure_fetch.py": [f"{F}/handlers/CloudAzureFetch.kt"],
    "handlers/_cloud_provider_fetchers.py": [f"{F}/handlers/CloudFetchers.kt"],
    "handlers/_cloud_provider_registry.py": [f"{F}/handlers/CloudProviderRegistry.kt"],
    "handlers/cloud_ip_stores.py": [f"{F}/handlers/CloudIpStores.kt"],
    "handlers/cors_handler.py": [f"{F}/handlers/CorsHandler.kt"],
    "handlers/dynamic_rule_handler.py": [f"{F}/handlers/DynamicRuleManager.kt"],
    "handlers/_dynamic_rule_application.py": [f"{F}/handlers/DynamicRuleManager.kt"],
    "handlers/_dynamic_rule_events.py": [f"{F}/handlers/DynamicRuleEvents.kt"],
    "handlers/_dynamic_rule_persistence.py": [f"{F}/handlers/DynamicRuleManager.kt"],
    "handlers/_dynamic_rule_snapshot.py": [f"{F}/handlers/DynamicRuleManager.kt"],
    "handlers/ipban_handler.py": [f"{F}/handlers/IpBanManager.kt"],
    "handlers/_ipban_bans.py": [f"{F}/handlers/IpBanBans.kt"],
    "handlers/_ipban_cache.py": [f"{F}/handlers/TtlCache.kt"],
    "handlers/_ipban_events.py": [f"{F}/handlers/IpBanBans.kt"],
    "handlers/_ipban_migration.py": [f"{F}/handlers/IpBanMigration.kt"],
    "handlers/_ipban_queries.py": [f"{F}/handlers/IpBanQueries.kt"],
    "handlers/ipinfo_handler.py": [f"{F}/handlers/IpInfoManager.kt"],
    "handlers/ratelimit_handler.py": [f"{F}/handlers/RateLimitManager.kt"],
    "handlers/redis_handler.py": [f"{F}/handlers/RedisManager.kt"],
    "handlers/security_headers_handler.py": [f"{F}/handlers/SecurityHeadersManager.kt"],
    "handlers/_security_headers_cache.py": [f"{F}/handlers/SecurityHeadersManager.kt"],
    "handlers/_security_headers_config.py": [f"{F}/handlers/SecurityHeadersManager.kt"],
    "handlers/_security_headers_cors.py": [f"{F}/handlers/SecurityHeadersManager.kt"],
    "handlers/_security_headers_events.py": [f"{F}/handlers/SecurityHeadersManager.kt"],
    "handlers/suspatterns_handler.py": [f"{E}/suspatterns/SusPatternsManager.kt", f"{F}/handlers/SusPatternsRegistry.kt"],
    "handlers/_suspatterns_enhanced.py": [f"{F}/handlers/DetectionScanRedaction.kt"],
    "handlers/_suspatterns_file_upload.py": [f"{E}/suspatterns/SusPatternsFileUploadTemplates.kt"],
    "handlers/_suspatterns_templates.py": [f"{E}/suspatterns/SusPatternsFileUploadTemplates.kt"],
    "handlers/_suspatterns_ldap_ipv4.py": [f"{E}/suspatterns/SusPatternsLdapIpv4.kt"],
    "handlers/_suspatterns_matchers.py": [f"{E}/suspatterns/SusPatternsMatchers.kt"],
    "handlers/_suspatterns_pattern_table.py": [f"{E}/suspatterns/SusPatternsTable.kt"],
    "handlers/_suspatterns_pickle.py": [f"{E}/suspatterns/SusPatternsPickle.kt"],
    "handlers/_suspatterns_regex.py": [f"{E}/suspatterns/SusPatternsManager.kt"],
    "handlers/_suspatterns_registry.py": [f"{F}/handlers/SusPatternsRegistry.kt"],
    "handlers/_suspatterns_shell_sources.py": [f"{E}/suspatterns/SusPatternsShell.kt", f"{E}/suspatterns/SusPatternsSources.kt"],
    "handlers/_suspatterns_shell_validators.py": [f"{E}/suspatterns/SusPatternsShell.kt"],
    "handlers/_suspatterns_sources.py": [f"{E}/suspatterns/SusPatternsSources.kt"],
    "handlers/_suspatterns_state.py": [f"{E}/suspatterns/SusPatternsState.kt"],
    "handlers/_suspatterns_views.py": [f"{E}/suspatterns/SusPatternsManager.kt"],
    "handlers/_suspatterns_xml_xxe.py": [f"{E}/suspatterns/SusPatternsXmlXxe.kt"],
    "handlers/scripts/rate_lua.py": [f"{F}/handlers/RateLimitScript.kt"],
    # --- detection engine ---
    "detection_engine/__init__.py": [f"{E}/"],
    "detection_engine/compiler.py": [f"{E}/detection/Compiler.kt"],
    "detection_engine/preprocessor.py": [f"{E}/detection/Preprocessor.kt", f"{F}/util/py/PyUrllib.kt"],
    "detection_engine/truncation.py": [f"{E}/detection/Truncation.kt"],
    "detection_engine/base64_alphabet.py": [f"{E}/detection/Base64.kt"],
    "detection_engine/base64_decode.py": [f"{E}/detection/Base64Decode.kt"],
    "detection_engine/base64_view.py": [f"{E}/detection/Base64View.kt"],
    "detection_engine/binary_prefix.py": [f"{E}/detection/Binary.kt"],
    "detection_engine/binary_islands.py": [f"{E}/detection/Binary.kt"],
    "detection_engine/encoding_decoders.py": [f"{E}/detection/EncodingDecoders.kt"],
    "detection_engine/scan_window.py": [f"{E}/detection/ScanWindow.kt"],
    "detection_engine/semantic.py": [f"{E}/detection/Semantic.kt", f"{E}/py/PyAst.kt"],
    "detection_engine/monitor.py": [f"{E}/detection/Monitor.kt"],
    "detection_engine/monitor_types.py": [f"{E}/detection/Monitor.kt"],
    "detection_engine/monitor_anomalies.py": [f"{E}/detection/Monitor.kt"],
    "detection_engine/monitor_reporting.py": [f"{E}/detection/Monitor.kt"],
    "detection_engine/_validation_cache.py": [f"{E}/detection/ValidationCache.kt"],
    "detection_engine/_redos_ambiguous_tail.py": [f"{E}/detection/AmbiguousTail.kt"],
    "detection_engine/_redos_class_intersection.py": [f"{E}/detection/ClassIntersection.kt"],
    "detection_engine/_redos_cost_arbiter.py": [f"{E}/detection/CostArbiter.kt"],
    "detection_engine/_redos_exact_state.py": [f"{E}/detection/ExactState.kt"],
    "detection_engine/_redos_ignorecase_fold.py": [f"{E}/detection/IgnorecaseFold.kt"],
    "detection_engine/_redos_intervals.py": [f"{E}/detection/IntervalSet.kt"],
    "detection_engine/_redos_literal_in_wildcard.py": [f"{E}/detection/LiteralInWildcard.kt"],
    "detection_engine/_redos_literal_runs.py": [f"{E}/detection/LiteralRuns.kt"],
    "detection_engine/_redos_parse_slots.py": [f"{E}/detection/ParseSlots.kt"],
    "detection_engine/_redos_prefix_history.py": [f"{E}/detection/PrefixHistory.kt"],
    "detection_engine/_redos_prefixed_probe.py": [f"{E}/detection/PrefixedProbe.kt"],
    "detection_engine/_redos_probe_batches.py": [f"{E}/detection/ProbeBatches.kt"],
    "detection_engine/_redos_probe_fill.py": [f"{E}/detection/ProbeFill.kt"],
    "detection_engine/_redos_reach_probe.py": [f"{E}/detection/ReachProbe.kt"],
    "detection_engine/_redos_repeat_alphabet.py": [f"{E}/detection/RepeatAlphabet.kt"],
    "detection_engine/_redos_repeat_lookbehind.py": [f"{E}/detection/RepeatLookbehind.kt"],
    "detection_engine/_redos_repeat_prefix.py": [f"{E}/detection/RepeatPrefix.kt"],
    "detection_engine/_redos_repeat_prefix_state.py": [f"{E}/detection/RepeatPrefixState.kt"],
    "detection_engine/_redos_repeat_units.py": [f"{E}/detection/RepeatUnits.kt"],
    "detection_engine/_redos_stray_chooser.py": [f"{E}/detection/StrayChooser.kt"],
    "detection_engine/_redos_structural_prefilters.py": [f"{E}/detection/StructuralPrefilters.kt"],
    "detection_engine/_redos_structure.py": [f"{E}/detection/StructureRules.kt", f"{E}/detection/StructurePrimitives.kt"],
    "detection_engine/_redos_structure_primitives.py": [f"{E}/detection/StructurePrimitives.kt"],
    "detection_engine/_redos_structure_rules.py": [f"{E}/detection/StructureRules.kt"],
    "detection_engine/_redos_unreachable_terminator.py": [f"{E}/detection/UnreachableTerminator.kt"],
    # --- core ---
    "core/__init__.py": [f"{F}/core/"],
    "core/checks/__init__.py": [f"{F}/core/checks/"],
    "core/checks/base.py": [f"{F}/core/checks/SecurityCheck.kt"],
    "core/checks/pipeline.py": [f"{F}/core/checks/SecurityCheckPipeline.kt"],
    "core/checks/helpers.py": [f"{F}/core/checks/ChecksHelpers.kt"],
    "core/checks/factory.py": [f"{F}/core/checks/ChecksFactory.kt"],
    "core/checks/_verifier.py": [f"{F}/core/checks/Verifier.kt"],
    "core/checks/implementations/route_config.py": [f"{F}/core/checks/implementations/RouteConfigCheck.kt"],
    "core/checks/implementations/emergency_mode.py": [f"{F}/core/checks/implementations/EmergencyModeCheck.kt"],
    "core/checks/implementations/https_enforcement.py": [f"{F}/core/checks/implementations/HttpsEnforcementCheck.kt"],
    "core/checks/implementations/request_logging.py": [f"{F}/core/checks/implementations/RequestLoggingCheck.kt"],
    "core/checks/implementations/request_size_content.py": [f"{F}/core/checks/implementations/RequestSizeContentCheck.kt"],
    "core/checks/implementations/required_headers.py": [f"{F}/core/checks/implementations/RequiredHeadersCheck.kt"],
    "core/checks/implementations/authentication.py": [f"{F}/core/checks/implementations/AuthenticationCheck.kt"],
    "core/checks/implementations/referrer.py": [f"{F}/core/checks/implementations/ReferrerCheck.kt"],
    "core/checks/implementations/custom_validators.py": [f"{F}/core/checks/implementations/CustomValidatorsCheck.kt"],
    "core/checks/implementations/time_window.py": [f"{F}/core/checks/implementations/TimeWindowCheck.kt"],
    "core/checks/implementations/cloud_ip_refresh.py": [f"{F}/core/checks/implementations/CloudIpRefreshCheck.kt"],
    "core/checks/implementations/ip_security.py": [f"{F}/core/checks/implementations/IpSecurityCheck.kt"],
    "core/checks/implementations/cloud_provider.py": [f"{F}/core/checks/implementations/CloudProviderCheck.kt"],
    "core/checks/implementations/user_agent.py": [f"{F}/core/checks/implementations/UserAgentCheck.kt"],
    "core/checks/implementations/rate_limit.py": [f"{F}/core/checks/implementations/RateLimitCheck.kt"],
    "core/checks/implementations/suspicious_activity.py": [f"{F}/core/checks/implementations/SuspiciousActivityCheck.kt"],
    "core/checks/implementations/custom_request.py": [f"{F}/core/checks/implementations/CustomRequestCheck.kt"],
    "core/events/__init__.py": [f"{F}/core/events/"],
    "core/events/event_types.py": [f"{F}/core/events/EventTypes.kt", f"{F}/config/EventTypes.kt"],
    "core/events/middleware_events.py": [f"{F}/core/events/SecurityEventBus.kt"],
    "core/events/metrics.py": [f"{F}/core/events/MetricsCollector.kt"],
    "core/events/composite_handler.py": [f"{F}/core/events/CompositeAgentHandler.kt"],
    "core/events/enricher.py": [f"{F}/core/events/EventEnricher.kt"],
    "core/events/otel_handler.py": [f"{F}/core/events/OtelHandler.kt"],
    "core/events/logfire_handler.py": [f"{F}/core/events/LogfireHandler.kt"],
    "core/initialization/__init__.py": [f"{F}/core/initialization/"],
    "core/initialization/handler_initializer.py": [f"{F}/core/initialization/HandlerInitializer.kt"],
    "core/initialization/_handler_initializer_steps.py": [f"{F}/core/initialization/HandlerInitializer.kt"],
    "core/responses/__init__.py": [f"{F}/core/responses/"],
    "core/responses/context.py": [f"{F}/core/responses/ErrorResponseFactory.kt"],
    "core/responses/factory.py": [f"{F}/core/responses/ErrorResponseFactory.kt"],
    "core/routing/__init__.py": [f"{F}/core/routing/"],
    "core/routing/context.py": [f"{F}/core/routing/RouteConfigResolver.kt"],
    "core/routing/resolver.py": [f"{F}/core/routing/RouteConfigResolver.kt"],
    "core/validation/__init__.py": [f"{F}/core/validation/"],
    "core/validation/context.py": [f"{F}/core/validation/RequestValidator.kt"],
    "core/validation/validator.py": [f"{F}/core/validation/RequestValidator.kt"],
    "core/validation/path_matching.py": [f"{F}/util/PathMatching.kt"],
    "core/bypass/__init__.py": [f"{F}/core/bypass/"],
    "core/bypass/context.py": [f"{F}/core/bypass/BypassHandler.kt"],
    "core/bypass/handler.py": [f"{F}/core/bypass/BypassHandler.kt"],
    "core/behavioral/__init__.py": [f"{F}/core/behavioral/"],
    "core/behavioral/context.py": [f"{F}/core/behavioral/BehavioralProcessor.kt"],
    "core/behavioral/processor.py": [f"{F}/core/behavioral/BehavioralProcessor.kt"],
    # --- decorators ---
    "decorators/__init__.py": [f"{F}/decorators/"],
    "decorators/base.py": [f"{F}/decorators/BaseSecurityDecorator.kt", f"{F}/decorators/RouteConfigProvider.kt"],
    "decorators/route_config.py": [f"{F}/decorators/RouteConfig.kt"],
    "decorators/access_control.py": [f"{F}/decorators/SecurityDecorator.kt"],
    "decorators/advanced.py": [f"{F}/decorators/SecurityDecorator.kt"],
    "decorators/authentication.py": [f"{F}/decorators/SecurityDecorator.kt"],
    "decorators/behavioral.py": [f"{F}/decorators/SecurityDecorator.kt"],
    "decorators/content_filtering.py": [f"{F}/decorators/SecurityDecorator.kt"],
    "decorators/rate_limiting.py": [f"{F}/decorators/SecurityDecorator.kt"],
    # --- scripts ---
    "scripts/__init__.py": [f"{F}/handlers/"],
    "scripts/rate_lua.py": [f"{F}/handlers/RateLimitScript.kt"],
}

FAMILY_OF: dict[str, str] = {}
for mod in MODULE_MAP:
    if mod.startswith("protocols/"):
        FAMILY_OF[mod] = "protocols"
    elif mod.startswith("_utils/"):
        FAMILY_OF[mod] = "utils"
    elif mod.startswith("handlers/") or mod.startswith("scripts/"):
        FAMILY_OF[mod] = "handlers"
    elif mod.startswith("detection_engine/"):
        FAMILY_OF[mod] = "detection"
    elif mod.startswith("core/"):
        FAMILY_OF[mod] = "core"
    elif mod.startswith("decorators/"):
        FAMILY_OF[mod] = "decorators"
    else:
        FAMILY_OF[mod] = "config"


def py_family(rel: str) -> str:
    if rel in FAMILY_OF:
        return FAMILY_OF[rel]
    if rel.startswith("protocols/"):
        return "protocols"
    if rel.startswith("_utils/"):
        return "utils"
    if rel.startswith("handlers/") or rel.startswith("scripts/"):
        return "handlers"
    if rel.startswith("detection_engine/"):
        return "detection"
    if rel.startswith("core/"):
        return "core"
    if rel.startswith("decorators/"):
        return "decorators"
    return "config"


# ---------------------------------------------------------------------------
# Python side extraction
# ---------------------------------------------------------------------------


@dataclass
class PySym:
    family: str
    file: str
    line: int
    name: str
    kind: str  # class | fun | method | field | const | property


def is_public(name: str) -> bool:
    return not name.startswith("_")


def extract_python() -> list[PySym]:
    syms: list[PySym] = []
    for dirpath, dirnames, filenames in os.walk(PY_ROOT):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, PY_ROOT)
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            try:
                tree = ast.parse(src)
            except SyntaxError as exc:
                print(f"WARN: syntax error {rel}: {exc}", file=sys.stderr)
                continue
            fam = py_family(rel)
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    if is_public(node.name):
                        syms.append(PySym(fam, rel, node.lineno, node.name, "class"))
                    else:
                        # surface-bearing private classes (registry, models)
                        syms.append(PySym(fam, rel, node.lineno, node.name, "class-priv"))
                    for sub in node.body:
                        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            if is_public(sub.name):
                                syms.append(PySym(fam, rel, sub.lineno, f"{node.name}.{sub.name}", "method"))
                        elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                            syms.append(PySym(fam, rel, sub.lineno, f"{node.name}.{sub.target.id}", "cfield"))
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if is_public(node.name):
                        syms.append(PySym(fam, rel, node.lineno, node.name, "fun"))
                    else:
                        syms.append(PySym(fam, rel, node.lineno, node.name, "fun-priv"))
                elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    name = node.targets[0].id
                    if name.isupper() or (name.startswith("_") and name[1:].isupper()):
                        syms.append(PySym(fam, rel, node.lineno, name, "const"))
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    name = node.target.id
                    if name.isupper():
                        syms.append(PySym(fam, rel, node.lineno, name, "const"))
    return syms


# ---------------------------------------------------------------------------
# Kotlin side extraction
# ---------------------------------------------------------------------------

KT_CLASS_RE = re.compile(r"^\s*(?:@\w\S*\s+)*(?:(?:public|private|internal|abstract|sealed|open|data|enum|value|annotation)\s+)*(?:class|object|interface)\s+(\w+)")
KT_FUN_RE = re.compile(r"^\s*(?:(?:public|private|internal|protected|override|open|abstract|suspend|inline|operator|expect|actual|final|tailrec)\s+)*fun\s+(?:<[^>]+>\s+)?(?:[\w?.<>]*\.)?(\w+)\s*[<(]")
KT_CONST_RE = re.compile(r"^\s*(?:(?:public|private|internal|protected|override|open)\s+)*(?:const\s+)?(?:val|var)\s+(?:[\w?.<>]*\.)?(\w+)\s*[:=]")
KT_COMMENT_RE = re.compile(r"^\s*(//|/\*|\*)")


@dataclass
class KtSym:
    file: str  # relpath from JVM_ROOT
    line: int
    name: str
    kind: str  # class | fun | val


def extract_kotlin() -> dict[str, list[KtSym]]:
    """Returns name -> list of symbols across all main-source kotlin files."""
    index: dict[str, list[KtSym]] = {}
    for src in JVM_SRC:
        for dirpath, dirnames, filenames in os.walk(src):
            for fn in sorted(filenames):
                if not fn.endswith(".kt"):
                    continue
                path = os.path.join(dirpath, fn)
                rel = os.path.relpath(path, JVM_ROOT)
                with open(path, encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, 1):
                        stripped = line.rstrip("\n")
                        if KT_COMMENT_RE.match(stripped):
                            continue
                        m = KT_CLASS_RE.match(stripped)
                        if m:
                            index.setdefault(m.group(1), []).append(KtSym(rel, lineno, m.group(1), "class"))
                            continue
                        m = KT_FUN_RE.match(stripped)
                        if m:
                            index.setdefault(m.group(1), []).append(KtSym(rel, lineno, m.group(1), "fun"))
                            continue
                        m = KT_CONST_RE.match(stripped)
                        if m:
                            index.setdefault(m.group(1), []).append(KtSym(rel, lineno, m.group(1), "val"))
    return index


def build_file_index() -> dict[str, list[KtSym]]:
    """file-scoped index: kotlin relpath-prefix -> symbols."""
    per_file: dict[str, list[KtSym]] = {}
    for syms in extract_kotlin().values():
        for s in syms:
            per_file.setdefault(s.file, []).append(s)
    return per_file


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(p.title() if p else "" for p in parts[1:])


def pascal(name: str) -> str:
    return "".join(p.title() if p else "" for p in name.split("_"))


def candidates_for(sym: PySym) -> list[str]:
    """Name candidates the JVM declaration may carry for a python symbol."""
    simple = sym.name.split(".")[-1]
    out = [camel(simple), pascal(simple), simple.replace("_", ""), simple]
    # python property x -> `isX` for bools is covered by camel; also try both
    if simple.startswith("is_"):
        out.append(pascal(simple[3:]))
    # initialism conventions: IpInfo/IpBan/DigitalOcean/Url etc.
    initialisms = {
        "ipinfo": "IpInfo", "ipban": "IpBan", "digitalocean": "DigitalOcean",
        "url": "URL", "http": "HTTP", "json": "JSON", "xml": "XML",
        "cors": "Cors", "lua": "Lua", "ttl": "Ttl", "lru": "Lru",
        "csrf": "Csrf", "api": "Api",
    }
    for low, repl in initialisms.items():
        if low in simple:
            variant = camel(simple.replace(low, repl))
            if variant not in out:
                out.append(variant)
            pv = pascal(simple.replace(low, repl))
            if pv not in out:
                out.append(pv)
    # models.py model_validator -> ConfigValidators validateXValue convention
    out.append(camel(simple) + "Value")
    out.append(pascal(simple) + "Value")
    return out


def match_symbol(sym: PySym, per_file: dict[str, list[KtSym]]) -> tuple[str, int, str] | None:
    """Returns (jvm_file, line, note) or None."""
    mapped = MODULE_MAP.get(sym.file)
    if not mapped:
        return None
    cands = candidates_for(sym)
    # search in the mapped files first
    for krel in mapped:
        if krel.endswith("/"):
            prefix = krel
            files = [f for f in per_file if f.startswith(prefix)]
        else:
            files = [krel]
        for f in files:
            for s in per_file.get(f, []):
                if s.name in cands:
                    return s.file, s.line, ""
    # family-wide fallback: same-name decl anywhere in the mapped family dirs
    fam_dirs = {
        "protocols": [f"{F}/protocols/"],
        "utils": [f"{F}/util/"],
        "handlers": [f"{F}/handlers/", f"{E}/suspatterns/"],
        "detection": [f"{E}/detection/", f"{E}/py/"],
        "core": [f"{F}/core/"],
        "decorators": [f"{F}/decorators/"],
        "config": [f"{F}/config/", f"{F}/errors/", f"{F}"],
    }[sym.family]
    for kd in fam_dirs:
        for f, syms in per_file.items():
            if not f.startswith(kd):
                continue
            for s in syms:
                if s.name in cands:
                    return s.file, s.line, "family-fallback"
    return None


# ---------------------------------------------------------------------------
# Observable constants family
# ---------------------------------------------------------------------------


def extract_constants(per_file: dict[str, list[KtSym]]) -> list[PySym]:
    """Extra rows: observable constants (check names, categories, redis namespaces,
    security headers, lua script). Anchored at their python definition site; matched
    by string value in the JVM tree."""
    rows: list[PySym] = []
    # 1. check names
    impl_dir = os.path.join(PY_ROOT, "core/checks/implementations")
    for fn in sorted(os.listdir(impl_dir)):
        if not fn.endswith(".py"):
            continue
        rel = f"core/checks/implementations/{fn}"
        with open(os.path.join(impl_dir, fn), encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                m = re.search(r'check_name\s*=\s*"([^"]+)"', line)
                if m:
                    rows.append(PySym("constants", rel, lineno, f"check_name={m.group(1)}", "check_name"))
    # 2. event + metric type values from core/events/event_types.py
    et = os.path.join(PY_ROOT, "core/events/event_types.py")
    with open(et, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            m = re.match(r'^([A-Z][A-Z0-9_]*)\s*(?::\s*\w+\s*)?=\s*"([^"]+)"', line)
            if m:
                rows.append(PySym("constants", "core/events/event_types.py", lineno, f"{m.group(1)}={m.group(2)}", "event_type"))
    # 3. detection categories from _suspatterns_sources.py
    src = os.path.join(PY_ROOT, "handlers/_suspatterns_sources.py")
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    m = re.search(r"DETECTION_CATEGORIES[^=]*=\s*[\[(](.*?)[\])]", text, re.S)
    base_line = text[: m.start()].count("\n") + 1 if m else 1
    if m:
        for cat in re.findall(r'"([a-z0-9_]+)"', m.group(1)):
            line_off = text[: text.find(f'"{cat}"', m.start())].count("\n") + 1
            rows.append(PySym("constants", "handlers/_suspatterns_sources.py", line_off, f"category={cat}", "category"))
    del base_line
    # 4. redis namespaces used by handlers (namespace=... call sites)
    hdir = os.path.join(PY_ROOT, "handlers")
    seen_ns: set[str] = set()
    for fn in sorted(os.listdir(hdir)):
        if not fn.endswith(".py"):
            continue
        rel = f"handlers/{fn}"
        with open(os.path.join(hdir, fn), encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                for m2 in re.finditer(r'namespace\s*=\s*"([a-z0-9_:]+)"', line):
                    ns = m2.group(1)
                    if ns not in seen_ns:
                        seen_ns.add(ns)
                        rows.append(PySym("constants", rel, lineno, f"redis_namespace={ns}", "redis_ns"))
    # 5. security header names from the default header table
    shc = os.path.join(PY_ROOT, "handlers/_security_headers_config.py")
    with open(shc, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            for m3 in re.finditer(r'"((?:X|Content-Security|Strict-Transport|Permissions|Referrer|Cross-Origin)[A-Za-z-]*)"\s*:', line):
                rows.append(PySym("constants", "handlers/_security_headers_config.py", lineno, f"header={m3.group(1)}", "header"))
    return rows


def match_constant(sym: PySym, jvm_texts: dict[str, list[str]]) -> tuple[str, int] | None:
    """Find the constant's VALUE in the mapped JVM files; value match is the
    observable-identity proof (ground rule 4: identifiers never renamed)."""
    if "=" not in sym.name:
        return None
    key, value = sym.name.split("=", 1)
    mapped = MODULE_MAP.get(sym.file, [])
    search_files = [f for f in mapped if not f.endswith("/")]
    if sym.kind in ("event_type",):
        # event values may live in either EventTypes.kt copies
        search_files = [f"{F}/core/events/EventTypes.kt", f"{F}/config/EventTypes.kt"]
    if sym.kind == "category":
        search_files = [f"{E}/suspatterns/SusPatternsSources.kt", f"{E}/suspatterns/SusPatternsState.kt", f"{E}/suspatterns/SusPatternsTable.kt"]
    if sym.kind == "check_name":
        # check_name value appears in the corresponding implementation file
        base = sym.file.split("/")[-1].replace(".py", "")
        kt = "".join(p.title() for p in base.split("_")) + "Check.kt"
        search_files = [f"{F}/core/checks/implementations/{kt}"]
    if sym.kind == "redis_ns":
        search_files = [
            f"{F}/handlers/RateLimitManager.kt", f"{F}/handlers/IpBanBans.kt",
            f"{F}/handlers/IpBanManager.kt", f"{F}/handlers/IpBanQueries.kt",
            f"{F}/handlers/IpBanMigration.kt", f"{F}/handlers/BehaviorTracker.kt",
            f"{F}/handlers/DynamicRuleManager.kt", f"{F}/handlers/SusPatternsRegistry.kt",
            f"{F}/handlers/CloudIpStores.kt", f"{F}/handlers/CloudManager.kt",
            f"{F}/handlers/RedisManager.kt", f"{F}/handlers/IpInfoManager.kt",
            f"{F}/handlers/SecurityHeadersManager.kt",
        ]
    if sym.kind == "header":
        search_files = [f"{F}/handlers/SecurityHeadersManager.kt"]
    for f in search_files:
        lines = jvm_texts.get(f)
        if not lines:
            continue
        for i, line in enumerate(lines, 1):
            if f'"{value}"' in line:
                return f, i
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def load_jvm_texts() -> dict[str, list[str]]:
    texts: dict[str, list[str]] = {}
    for src in JVM_SRC:
        for dirpath, _dirnames, filenames in os.walk(src):
            for fn in filenames:
                if not fn.endswith(".kt"):
                    continue
                path = os.path.join(dirpath, fn)
                rel = os.path.relpath(path, JVM_ROOT)
                with open(path, encoding="utf-8") as fh:
                    texts[rel] = fh.read().splitlines()
    return texts


def main() -> None:
    py_syms = extract_python()
    per_file = build_file_index()
    jvm_texts = load_jvm_texts()

    rows = []
    manual = []
    for sym in py_syms:
        # (a) rows are the public surface: private decls are internals of their
        # module's public entry points (proven per-module by the wave gates)
        if sym.kind in ("class-priv", "fun-priv"):
            continue
        # (b) underscore module constants are internal; not surface rows
        if sym.kind == "const" and sym.name.startswith("_"):
            continue
        if sym.kind == "cfield":
            if not sym.file.endswith("_security_config_fields.py"):
                # class-level annotated constants outside the registry: keep only UPPER
                simple = sym.name.split(".")[-1]
                if not simple.isupper():
                    continue
        if sym.file.endswith("__init__.py"):
            # package-surface rows handled at family level
            continue
        if sym.kind == "const" and sym.file == "core/events/event_types.py":
            continue  # covered in constants family
        hit = match_symbol(sym, per_file)
        if hit:
            jf, jl, note = hit
            rows.append((sym.family, sym.file, sym.line, sym.name, sym.kind, jf, jl, note))
        else:
            manual.append(sym)

    const_rows = extract_constants(per_file)
    for sym in const_rows:
        hit = match_constant(sym, jvm_texts)
        if hit:
            jf, jl = hit
            rows.append((sym.family, sym.file, sym.line, sym.name, sym.kind, jf, jl, ""))
        else:
            manual.append(sym)

    with open("/tmp/w8c_rows.tsv", "w", encoding="utf-8") as out:
        for r in sorted(rows):
            out.write("\t".join(str(x) for x in r) + "\n")
    with open("/tmp/w8c_manual.txt", "w", encoding="utf-8") as out:
        for s in sorted(manual, key=lambda s: (s.family, s.file, s.line)):
            out.write(f"{s.family}\t{s.file}:{s.line}\t{s.name}\t{s.kind}\n")
    print(f"rows={len(rows)} manual={len(manual)}")


def _is_surface_private(sym: PySym) -> bool:
    """Private-named python decls that are nevertheless part of the ported
    surface: any decl inside a private MODULE (the whole module is a ported
    unit, every function is the module's content, ported file-for-file)."""
    base = sym.file.rsplit("/", 1)[-1]
    top = sym.file.split("/")[0]
    private_module_prefixes = ("_",)
    if base.startswith(private_module_prefixes):
        return True
    if top in ("handlers", "core", "detection_engine", "decorators", "scripts"):
        return True
    if sym.file.startswith("config") or "/" not in sym.file.rstrip("/"):
        # root-level private modules (_security_config_*, _config_*, etc.)
        return base.startswith("_")
    return False


if __name__ == "__main__":
    main()
