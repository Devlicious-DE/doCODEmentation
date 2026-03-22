from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from ruamel.yaml import YAML


def ensure_output_dir(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)


def write_inventory_yaml(inventory: dict[str, Any], output_dir: Path) -> Path:
    ensure_output_dir(output_dir)
    out = output_dir / "inventory.yaml"
    yaml = YAML()
    yaml.default_flow_style = False
    yaml.sort_base_mapping_type_on_output = True
    with out.open("w", encoding="utf-8") as f:
        yaml.dump(inventory, f)
    return out


def write_inventory_json(inventory: dict[str, Any], output_dir: Path) -> Path:
    ensure_output_dir(output_dir)
    out = output_dir / "inventory.json"
    with out.open("w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2, sort_keys=True)
        f.write("\n")
    return out


def write_inventory_markdown(inventory: dict[str, Any], output_dir: Path) -> Path:
    ensure_output_dir(output_dir)
    out = output_dir / "inventory.md"
    services = inventory.get("services", [])
    networks = inventory.get("networks", {})
    security = inventory.get("security_summary", {})

    lines: list[str] = []
    lines.append("# Infrastructure Inventory")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Name | Image | URL | Networks | Security Score |")
    lines.append("|---|---|---|---|---:|")
    for s in services:
        urls = ", ".join(s.get("urls", [])[:2]) or "-"
        net = ", ".join(s.get("networks", [])) or "-"
        score = s.get("security", {}).get("score", 0)
        lines.append(f"| {s.get('name','-')} | {s.get('image','-')} | {urls} | {net} | {score} |")
    lines.append("")

    lines.append("## Services")
    lines.append("")
    for s in services:
        lines.append(f"### {s.get('name','unknown')}")
        lines.append(f"- Source: `{s.get('source', 'compose')}`")
        lines.append(f"- File: `{s.get('source_file','-')}`")
        lines.append(f"- Container: `{s.get('container_name') or '-'}`")
        lines.append(f"- Compose Service: `{s.get('compose_service_name') or '-'}`")
        lines.append(f"- Image: `{s.get('image') or '-'}`")
        lines.append(f"- Image Tag: `{s.get('image_tag') or '-'}`")
        lines.append(f"- Service Type: `{s.get('service_type') or 'other'}`")
        lines.append(f"- URL(s): {', '.join(s.get('urls', [])) or '-'}")
        lines.append(f"- Internal Port(s): {', '.join(str(p) for p in s.get('internal_ports', [])) or '-'}")
        lines.append(f"- Published Port(s): {', '.join(s.get('published_ports', [])) or '-'}")
        lines.append(f"- Networks: {', '.join(s.get('networks', [])) or '-'}")
        lines.append(f"- Bind Mounts: {', '.join(s.get('bind_mounts', [])) or '-'}")
        lines.append(f"- Environment Keys: {', '.join(s.get('environment_keys', [])) or '-'}")
        lines.append(f"- Depends On: {', '.join(s.get('depends_on', [])) or '-'}")
        hc = s.get("healthcheck", {})
        lines.append(f"- Healthcheck: `present={hc.get('present', False)}`")
        if hc.get("command"):
            lines.append(f"- Health Command: `{hc.get('command')}`")
        sec = s.get("security", {})
        lines.append(
            f"- Security: no-new-privileges={sec.get('no_new_privileges')}, "
            f"cap_drop={sec.get('cap_drop')}, read_only={sec.get('read_only')}, "
            f"user={sec.get('user_mode')}, score={sec.get('score')}"
        )
        secrets = s.get("potential_hardcoded_secrets") or []
        if secrets:
            keys_only = ", ".join(str(x.get("key", "")) for x in secrets)
            lines.append(f"- Potential hardcoded secret keys (no values): {keys_only}")
        if s.get("note"):
            lines.append(f"- Note: {s.get('note')}")
        lines.append("")

    lines.append("## Network Topology")
    lines.append("")
    for network_name, svc_list in networks.items():
        lines.append(f"- **{network_name}**: {', '.join(svc_list)}")
    if not networks:
        lines.append("- No networks discovered.")
    lines.append("")

    lines.append("## Security Overview")
    lines.append("")
    lines.append(f"- Services running as root: {', '.join(security.get('root_services', [])) or 'none'}")
    lines.append(
        f"- Services with user unset: {', '.join(security.get('unset_user_services', [])) or 'none'}"
    )
    lines.append(
        "- Services without healthcheck: "
        f"{', '.join(security.get('services_without_healthcheck', [])) or 'none'}"
    )
    hw = security.get("hardcoded_secret_warnings", [])
    if hw:
        lines.append("- Potential hardcoded secrets (keys only):")
        for item in hw:
            lines.append(f"  - `{item.get('service')}` / `{item.get('key')}`")
    lines.append("")

    with out.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out
