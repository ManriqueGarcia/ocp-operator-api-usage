#!/usr/bin/env python3
"""Capture or analyze OpenShift audit evidence for OLM operators."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import gzip
import html
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


UTC = dt.timezone.utc
AUDIT_FILENAME = re.compile(r"^audit(?:[-.].*)?\.log(?:\.gz)?$")
TERMINAL_CONTROLS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
AUDIT_EXPORT_WORKERS = 3


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def isoformat(value: dt.datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def terminal_safe(value: Any) -> str:
    return " ".join(TERMINAL_CONTROLS.sub(" ", str(value)).split())


def parse_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


# Small helpers keep cluster access and time parsing consistent across capture steps.
def run_oc(args: list[str], *, stdout: Any = subprocess.PIPE) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["oc", *args],
            check=False,
            text=True,
            stdout=stdout,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("No se encuentra `oc`; instálalo o usa el modo de análisis local.") from exc


def require_cluster_access() -> None:
    if run_oc(["whoami"]).returncode != 0:
        raise RuntimeError("`oc` no está conectado a un clúster. Ejecuta `oc login`.")


def load_json_command(args: list[str], description: str) -> dict[str, Any]:
    result = run_oc(args)
    if result.returncode != 0:
        detail = terminal_safe(result.stderr or "")
        raise RuntimeError(f"No se pudo {description}: {detail}")
    try:
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"La respuesta de `oc {' '.join(args)}` no es JSON válido.") from exc


def list_installed_csvs(namespace: str | None) -> list[dict[str, Any]]:
    result = load_json_command(
        ["get", "clusterserviceversions", "-A", "-o", "json"],
        "listar los ClusterServiceVersions instalados",
    )
    candidates = [
        item
        for item in result.get("items", [])
        if item.get("status", {}).get("phase") == "Succeeded"
        and (namespace is None or item.get("metadata", {}).get("namespace") == namespace)
    ]
    return sorted(candidates, key=lambda item: (
        item.get("spec", {}).get("displayName") or item.get("metadata", {}).get("name", ""),
        item.get("metadata", {}).get("namespace", ""),
        item.get("metadata", {}).get("name", ""),
    ))


def print_csvs(candidates: list[dict[str, Any]]) -> None:
    print("Operadores instalados:")
    for index, item in enumerate(candidates, start=1):
        metadata = item.get("metadata", {})
        display_name = item.get("spec", {}).get("displayName") or metadata.get("name", "desconocido")
        print(f"  {index}. {terminal_safe(display_name)} — CSV: {terminal_safe(metadata.get('name', '?'))} — namespace: {terminal_safe(metadata.get('namespace', '?'))}")


def choose_csv(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    if not candidates:
        raise RuntimeError("No se encontraron CSV instalados en estado Succeeded.")
    print_csvs(candidates)
    if not sys.stdin.isatty():
        raise RuntimeError("Indica --operator CSV para elegir un elemento sin interacción.")
    while True:
        selection = input("Número del operador que quieres revisar: ").strip()
        if selection.isdigit() and 1 <= int(selection) <= len(candidates):
            return candidates[int(selection) - 1]
        print(f"Elige un número entre 1 y {len(candidates)}.", file=sys.stderr)


def choose_csvs(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not candidates:
        raise RuntimeError("No se encontraron CSV instalados en estado Succeeded.")
    print_csvs(candidates)
    if not sys.stdin.isatty():
        raise RuntimeError("Indica --operator CSV (puedes repetirlo) para elegir sin interacción.")
    while True:
        selection = input("Números de los operadores que quieres revisar, separados por comas (o 'todos'): ").strip().lower()
        if selection == "todos":
            return candidates
        try:
            indexes = [int(value.strip()) for value in selection.split(",")]
        except ValueError:
            indexes = []
        if indexes and all(1 <= index <= len(candidates) for index in indexes):
            return [candidates[index - 1] for index in dict.fromkeys(indexes)]
        print(f"Introduce números entre 1 y {len(candidates)}, separados por comas, o 'todos'.", file=sys.stderr)


def select_csvs(operator_names: list[str], namespace: str | None) -> list[dict[str, Any]]:
    candidates = list_installed_csvs(namespace)
    if not operator_names:
        return choose_csvs(candidates)

    selected = []
    for operator in operator_names:
        matches = [
            item for item in candidates
            if item.get("metadata", {}).get("name") == operator
        ]
        if not matches:
            raise RuntimeError(f"No se encontró el CSV `{operator}` en estado Succeeded. Comprueba el nombre y el namespace.")
        if len(matches) > 1:
            namespaces = ", ".join(sorted(item.get("metadata", {}).get("namespace", "?") for item in matches))
            raise RuntimeError(f"El CSV `{operator}` aparece en varios namespaces ({namespaces}); usa la selección interactiva o --namespace.")
        selected.append(matches[0])
    unique = {(item.get("metadata", {}).get("namespace"), item.get("metadata", {}).get("name")): item for item in selected}
    if len(unique) != len(selected):
        raise RuntimeError("Se ha indicado el mismo CSV más de una vez.")
    return selected


def select_csv(operator: str | None, namespace: str | None) -> dict[str, Any]:
    if not operator:
        return choose_csv(list_installed_csvs(namespace))
    if namespace:
        result = load_json_command(
            ["get", "clusterserviceversions", operator, "-n", namespace, "-o", "json"],
            f"obtener el CSV {operator} en {namespace}",
        )
        candidates = [result]
    else:
        result = load_json_command(
            ["get", "clusterserviceversions", "-A", f"--field-selector=metadata.name={operator}", "-o", "json"],
            f"buscar el CSV {operator}",
        )
        candidates = result.get("items", [])

    candidates = [item for item in candidates if item.get("metadata", {}).get("name") == operator]
    if not candidates:
        raise RuntimeError(f"No se encontró el CSV `{operator}`. Comprueba el nombre y el namespace.")
    if len(candidates) > 1:
        namespaces = ", ".join(sorted(item.get("metadata", {}).get("namespace", "?") for item in candidates))
        raise RuntimeError(f"El CSV `{operator}` aparece en varios namespaces ({namespaces}); indica --namespace.")
    csv = candidates[0]
    if csv.get("status", {}).get("phase") != "Succeeded":
        phase = csv.get("status", {}).get("phase", "desconocido")
        raise RuntimeError(f"El CSV `{operator}` no está en estado Succeeded (estado: {phase}).")
    return csv


def owned_crds(csv: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    namespace = csv.get("metadata", {}).get("namespace", "")
    deployment_specs = csv.get("spec", {}).get("install", {}).get("spec", {}).get("deployments", [])
    operator_sas = set()
    for deployment in deployment_specs:
        pod_spec = deployment.get("spec", {}).get("template", {}).get("spec", {})
        service_account = pod_spec.get("serviceAccountName", "default")
        operator_sas.add(f"system:serviceaccount:{namespace}:{service_account}")

    crd_refs = csv.get("spec", {}).get("customresourcedefinitions", {}).get("owned", [])
    results: list[dict[str, Any]] = []
    for ref in crd_refs:
        name = ref.get("name")
        if not name:
            continue
        crd = load_json_command(["get", "crd", name, "-o", "json"], f"obtener el CRD {name}")
        spec = crd.get("spec", {})
        results.append(
            {
                "name": name,
                "group": spec.get("group", ""),
                "plural": spec.get("names", {}).get("plural", ""),
                "kind": spec.get("names", {}).get("kind", ref.get("kind", "")),
                "scope": spec.get("scope", "Unknown"),
                "versions": [
                    version.get("name")
                    for version in spec.get("versions", [])
                    if version.get("served") and version.get("name")
                ],
            }
        )
    return results, sorted(operator_sas)


# Capture only resource names and namespaces so the snapshot does not retain CR specs.
def list_resource_instances(crds: list[dict[str, Any]], output_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    inventory_file = output_dir / "resources.jsonl"
    summaries: list[dict[str, Any]] = []
    errors: list[str] = []
    with inventory_file.open("w", encoding="utf-8") as inventory:
        for crd in crds:
            api_resource = f"{crd['plural']}.{crd['group']}"
            columns = "NAMESPACE:.metadata.namespace,NAME:.metadata.name" if crd["scope"] == "Namespaced" else "NAME:.metadata.name"
            command = ["get", api_resource]
            if crd["scope"] == "Namespaced":
                command.append("--all-namespaces")
            command.extend(["-o", f"custom-columns={columns}", "--no-headers"])

            count = 0
            error = None
            with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as error_file:
                try:
                    proc = subprocess.Popen(
                        ["oc", *command],
                        stdout=subprocess.PIPE,
                        stderr=error_file,
                        text=True,
                    )
                except FileNotFoundError as exc:
                    raise RuntimeError("No se encuentra `oc`.") from exc
                assert proc.stdout is not None
                for line in proc.stdout:
                    fields = line.split()
                    if not fields:
                        continue
                    if crd["scope"] == "Namespaced":
                        if len(fields) < 2:
                            continue
                        namespace, name = fields[0], fields[1]
                    else:
                        namespace, name = "", fields[0]
                    inventory.write(json.dumps({"crd": crd["name"], "namespace": namespace, "name": name}) + "\n")
                    count += 1
                return_code = proc.wait()
                if return_code != 0:
                    error_file.seek(0)
                    detail = error_file.read().strip()
                    error = f"{api_resource}: {detail or 'falló la consulta'}"
                    errors.append(error)
            summaries.append({"crd": crd["name"], "count": count, "status": "error" if error else "ok"})
    return summaries, errors


def parse_log_listing(output: str) -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        node, filename = fields[0], fields[-1].rstrip("/")
        if AUDIT_FILENAME.fullmatch(Path(filename).name):
            files.append((node, Path(filename).name))
    return sorted(set(files))


def capture_audit_logs(output_dir: Path) -> tuple[list[dict[str, str]], list[str]]:
    listing = run_oc(["adm", "node-logs", "--role=master", "--path=kube-apiserver/"])
    if listing.returncode != 0:
        detail = terminal_safe(listing.stderr or "")
        return [], [f"No se pudo listar la auditoría de kube-apiserver: {detail}"]
    available = parse_log_listing(listing.stdout or "")
    if not available:
        return [], ["No se encontraron ficheros audit*.log en los nodos master."]

    audit_dir = output_dir / "audit"
    audit_dir.mkdir()
    def export_one(node: str, filename: str) -> tuple[dict[str, str] | None, str | None]:
        local_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{node}__{filename}")
        destination = audit_dir / local_name
        with destination.open("wb") as output_file:
            result = run_oc(
                ["adm", "node-logs", node, f"--path=kube-apiserver/{filename}"],
                stdout=output_file,
            )
        if result.returncode != 0:
            destination.unlink(missing_ok=True)
            return None, f"{terminal_safe(node)}/{terminal_safe(filename)}: {terminal_safe(result.stderr or '') or 'falló la exportación'}"
        return {"node": node, "source": filename, "file": f"audit/{local_name}"}, None

    captured: list[dict[str, str]] = []
    errors: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=AUDIT_EXPORT_WORKERS) as pool:
        futures = [pool.submit(export_one, node, filename) for node, filename in available]
        for index, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            item, error = future.result()
            if item:
                captured.append(item)
                print(f"[{index}/{len(available)}] Exportado {terminal_safe(item['node'])}/{terminal_safe(item['source'])}", file=sys.stderr)
            if error:
                errors.append(error)
    return captured, errors


# Capture metadata and resource inventory once, then export every retained API audit log.
def capture(args: argparse.Namespace) -> None:
    require_cluster_access()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=False)

    started_at = utc_now()
    csv = select_csv(args.operator, args.namespace)
    crds, operator_sas = owned_crds(csv)
    resource_summaries, inventory_errors = list_resource_instances(crds, output_dir)
    if args.metadata_only:
        audit_files, audit_errors = [], []
    else:
        audit_files, audit_errors = capture_audit_logs(output_dir)
    metadata = {
        "formatVersion": 1,
        "captureStartedAt": isoformat(started_at),
        "captureCompletedAt": isoformat(utc_now()),
        "requestedDays": args.days,
        "operator": {
            "csv": csv.get("metadata", {}).get("name"),
            "namespace": csv.get("metadata", {}).get("namespace"),
            "displayName": csv.get("spec", {}).get("displayName") or csv.get("metadata", {}).get("name"),
            "phase": csv.get("status", {}).get("phase"),
        },
        "ownedCRDs": crds,
        "operatorServiceAccounts": operator_sas,
        "resourceInventory": resource_summaries,
        "resourceInventoryErrors": inventory_errors,
        "auditFiles": audit_files,
        "auditCaptureErrors": audit_errors,
        "auditSource": "external files" if args.metadata_only else "kube-apiserver",
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Snapshot guardado en {terminal_safe(output_dir)}")
    if inventory_errors or audit_errors:
        print("La captura está incompleta; consulta los errores en metadata.json.", file=sys.stderr)


def report(args: argparse.Namespace) -> None:
    require_cluster_access()
    csvs = select_csvs(args.operator, args.namespace)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    report_date = utc_now().date().isoformat()
    csv_names = [item.get("metadata", {}).get("name", "operator") for item in csvs]
    duplicated = {name for name in csv_names if csv_names.count(name) > 1}
    outputs = []
    for csv in csvs:
        metadata = csv.get("metadata", {})
        name = metadata.get("name", "operator")
        if name in duplicated:
            name = f"{name}-{metadata.get('namespace', 'namespace')}"
        filename = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{name}-{report_date}.md")
        outputs.append(output_dir / filename)
    if len(set(outputs)) != len(outputs):
        raise RuntimeError("Los nombres de CSV seleccionados producen nombres de informe duplicados.")
    html_output = output_dir / f"operator-api-usage-{report_date}.html"
    if any(path.exists() for path in outputs) or html_output.exists():
        run_name = f"run-{report_date}-{utc_now().strftime('%H%M%S')}"
        run_dir = output_dir / run_name
        suffix = 2
        while run_dir.exists():
            run_dir = output_dir / f"{run_name}-{suffix}"
            suffix += 1
        run_dir.mkdir(parents=True)
        output_dir = run_dir
        outputs = [output_dir / path.name for path in outputs]
        html_output = output_dir / html_output.name
        print(f"Ya había informes de hoy; los nuevos se guardarán en {terminal_safe(output_dir)}.", file=sys.stderr)

    print(f"Se generarán {len(csvs)} informes; los logs se descargarán y analizarán una sola vez.", file=sys.stderr)
    started_at = utc_now()
    with tempfile.TemporaryDirectory(prefix="ocp-operator-api-usage-", dir=output_dir) as temporary:
        temporary_dir = Path(temporary)
        metadata_list = []
        metadata_paths = []
        inventory_errors_by_operator = []
        for index, csv in enumerate(csvs, start=1):
            print(f"[{index}/{len(csvs)}] Preparando {terminal_safe(csv.get('spec', {}).get('displayName') or csv.get('metadata', {}).get('name'))}", file=sys.stderr)
            metadata_dir = temporary_dir / f"operator-{index}"
            metadata_dir.mkdir()
            crds, operator_sas = owned_crds(csv)
            resource_summaries, inventory_errors = list_resource_instances(crds, metadata_dir)
            inventory_errors_by_operator.append(inventory_errors)
            metadata = {
                "formatVersion": 1,
                "captureStartedAt": isoformat(started_at),
                "captureCompletedAt": "",
                "requestedDays": args.days,
                "operator": {
                    "csv": csv.get("metadata", {}).get("name"),
                    "namespace": csv.get("metadata", {}).get("namespace"),
                    "displayName": csv.get("spec", {}).get("displayName") or csv.get("metadata", {}).get("name"),
                    "phase": csv.get("status", {}).get("phase"),
                },
                "ownedCRDs": crds,
                "operatorServiceAccounts": operator_sas,
                "resourceInventory": resource_summaries,
                "resourceInventoryErrors": inventory_errors,
                "auditFiles": [],
                "auditCaptureErrors": [],
                "auditSource": "kube-apiserver",
            }
            metadata_list.append(metadata)
            metadata_paths.append(metadata_dir / "metadata.json")

        audit_files, audit_errors = capture_audit_logs(temporary_dir)
        completed_at = isoformat(utc_now())
        for metadata, metadata_path in zip(metadata_list, metadata_paths):
            metadata["captureCompletedAt"] = completed_at
            metadata["auditFiles"] = audit_files
            metadata["auditCaptureErrors"] = audit_errors
            metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

        states, audit_summary = scan_audit_logs(metadata_list, temporary_dir / "audit", args.days)
        for index, (metadata, metadata_path, output, inventory_errors) in enumerate(zip(metadata_list, metadata_paths, outputs, inventory_errors_by_operator)):
            write_report(metadata, metadata_path, output, states[index], audit_summary)
            if inventory_errors or audit_errors:
                print(f"Captura incompleta para {terminal_safe(metadata['operator']['csv'])}; revisa el estado indicado en el informe.", file=sys.stderr)
        write_html_report(metadata_list, metadata_paths, outputs, states, audit_summary, html_output)


def write_html_report(
    metadata_list: list[dict[str, Any]],
    metadata_paths: list[Path],
    markdown_outputs: list[Path],
    states: list[dict[str, Any]],
    audit_summary: dict[str, Any],
    output: Path,
) -> None:
    escape = lambda value: html.escape(str(value), quote=True)
    generated_at = isoformat(utc_now())
    first_state = states[0]
    oldest = isoformat(audit_summary["oldest"]) if audit_summary["oldest"] else "sin marcas de tiempo"
    newest = isoformat(audit_summary["newest"]) if audit_summary["newest"] else "sin marcas de tiempo"
    total_crds = sum(len(metadata.get("ownedCRDs", [])) for metadata in metadata_list)
    total_requests = sum(state["matched"] for state in states)
    total_instances = 0
    any_inventory_error = False
    for metadata in metadata_list:
        for item in metadata.get("resourceInventory", []):
            if item.get("status") == "error":
                any_inventory_error = True
            else:
                total_instances += item.get("count", 0)

    lines = [
        "<!doctype html>",
        '<html lang="es">',
        "<head>",
        '  <meta charset="utf-8">',
        '  <meta name="viewport" content="width=device-width, initial-scale=1">',
        '  <title>Informe de actividad de operadores OpenShift</title>',
        "  <style>",
        "    :root { --red: #ee0000; --red-light: #fef0f0; --ink: #151515; --gray-70: #383838; --gray-50: #707070; --gray-20: #e0e0e0; --gray-10: #f2f2f2; --white: #fff; --orange: #f0561d; --green: #3d7317; }",
        "    * { box-sizing: border-box; } body { margin: 0; background: var(--gray-10); color: var(--ink); font: 15px/1.5 Arial, Helvetica, sans-serif; }",
        "    main { max-width: 1120px; margin: 28px auto; padding: 0 20px 48px; } .topline { height: 8px; background: var(--red); }",
        "    header, section, article { background: var(--white); } header { padding: 28px 32px; border-bottom: 1px solid var(--gray-20); }",
        "    .eyebrow { margin: 0 0 8px; color: var(--red); font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }",
        "    h1 { margin: 0; font-size: 30px; line-height: 1.2; } h2 { margin: 0 0 16px; font-size: 22px; } h3 { margin: 0 0 10px; font-size: 17px; }",
        "    .meta { margin: 14px 0 0; color: var(--gray-50); } .panel { margin-top: 20px; padding: 24px 28px; border: 1px solid var(--gray-20); }",
        "    .cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 18px 0 24px; } .card { padding: 14px 16px; border: 1px solid var(--gray-20); border-top: 3px solid var(--red); }",
        "    .card-label { display: block; color: var(--gray-50); font-size: 12px; } .card-value { display: block; margin-top: 4px; font-size: 23px; font-weight: 700; }",
        "    table { width: 100%; border-collapse: collapse; margin: 10px 0 22px; } th, td { padding: 9px 10px; border-bottom: 1px solid var(--gray-20); text-align: left; vertical-align: top; } th { background: var(--gray-10); font-size: 12px; }",
        "    a { color: var(--ink); text-decoration-color: var(--red); text-underline-offset: 3px; } .operator { margin-top: 24px; border-top: 4px solid var(--red); } .operator-head { padding: 22px 28px 0; } .operator-body { padding: 0 28px 24px; }",
        "    .note { padding: 12px 14px; border-left: 4px solid var(--red); background: var(--red-light); } .warning { padding: 12px 14px; border-left: 4px solid var(--orange); background: #fff4ed; }",
        "    .ok { color: var(--green); font-weight: 700; } .incomplete { color: var(--orange); font-weight: 700; } .small { color: var(--gray-50); font-size: 13px; } .section-label { margin-top: 24px; }",
        "    @media (max-width: 760px) { .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); } main { margin-top: 0; padding: 0 10px 28px; } header, .panel { padding: 20px; } .operator-head, .operator-body { padding-left: 20px; padding-right: 20px; } table { font-size: 13px; } th, td { padding: 7px 6px; } }",
        "    @media print { body { background: #fff; } main { max-width: none; margin: 0; padding: 0; } header, section, article { border-color: #bbb; } .panel { break-inside: avoid; } .operator { break-before: page; } a { text-decoration: none; } }",
        "  </style>",
        "</head>",
        "<body>",
        '  <div class="topline"></div>',
        "  <main>",
        "    <header>",
        '      <p class="eyebrow">OpenShift · Informe de uso de APIs</p>',
        "      <h1>Actividad de operadores</h1>",
        f'      <p class="meta">Generado {escape(generated_at)} · Ventana: {first_state["days"]} días ({escape(isoformat(first_state["start"]))} a {escape(isoformat(first_state["end"]))})</p>',
        "    </header>",
        '    <section class="panel">',
        "      <h2>Resumen</h2>",
        '      <div class="cards">',
        f'        <div class="card"><span class="card-label">Operadores revisados</span><span class="card-value">{len(metadata_list)}</span></div>',
        f'        <div class="card"><span class="card-label">CRDs declarados</span><span class="card-value">{total_crds}</span></div>',
        f'        <div class="card"><span class="card-label">Instancias actuales</span><span class="card-value">{"≥ " if any_inventory_error else ""}{total_instances}</span></div>',
        f'        <div class="card"><span class="card-label">Peticiones relacionadas</span><span class="card-value">{total_requests}</span></div>',
        "      </div>",
        f'      <p class="small">Logs analizados: {len(audit_summary["files"])} ficheros · {audit_summary["parsed"]} eventos JSON válidos · rango observado: {escape(oldest)} a {escape(newest)}.</p>',
        '      <table><thead><tr><th>Operador</th><th>Namespace</th><th>CRDs</th><th>Instancias</th><th>Peticiones</th><th>Correctas</th><th>Fallidas</th><th>Captura</th></tr></thead><tbody>',
    ]
    for index, (metadata, state) in enumerate(zip(metadata_list, states)):
        operator = metadata.get("operator", {})
        request_count = sum(stat["total"] for stat in state["api_stats"].values())
        success_count = sum(stat["success"] for stat in state["api_stats"].values())
        failed_count = sum(stat["failed"] for stat in state["api_stats"].values())
        inventory_errors = metadata.get("resourceInventoryErrors", [])
        instance_count = sum(item.get("count", 0) for item in metadata.get("resourceInventory", []) if item.get("status") != "error")
        instance_value = f"≥ {instance_count}" if inventory_errors else str(instance_count)
        status = "incompleta" if metadata.get("auditCaptureErrors") or inventory_errors else "sin errores registrados"
        lines.append(
            f'<tr><td><a href="#operator-{index + 1}">{escape(operator.get("displayName", "desconocido"))}</a><br><span class="small">{escape(operator.get("csv", "desconocido"))}</span></td>'
            f'<td>{escape(operator.get("namespace", "desconocido"))}</td><td>{len(metadata.get("ownedCRDs", []))}</td><td>{instance_value}</td>'
            f'<td>{request_count}</td><td>{success_count}</td><td>{failed_count}</td><td class="{"incomplete" if status == "incompleta" else "ok"}">{status}</td></tr>'
        )
    lines.extend([
        "      </tbody></table>",
        '      <p class="note">La ausencia de instancias actuales no descarta accesos durante el periodo. La ausencia de eventos en los logs disponibles tampoco demuestra que un operador sea prescindible; la decisión corresponde al cliente.</p>',
        '      <p class="small">Los totales de instancias y peticiones suman los valores por operador; si varios operadores declaran el mismo CRD, esos datos pueden aparecer en más de un informe.</p>',
        "    </section>",
    ])

    for index, (metadata, metadata_path, markdown_path, state) in enumerate(zip(metadata_list, metadata_paths, markdown_outputs, states), start=1):
        operator = metadata.get("operator", {})
        operator_title = operator.get("displayName", "desconocido")
        inventory_by_crd = {item.get("crd"): item for item in metadata.get("resourceInventory", [])}
        lines.extend([
            f'    <article class="operator" id="operator-{index}">',
            '      <div class="operator-head">',
            f"        <p class=\"eyebrow\">Detalle {index} de {len(metadata_list)}</p>",
            f"        <h2>{escape(operator_title)}</h2>",
            f'        <p class="meta">CSV: {escape(operator.get("csv", "desconocido"))} · Namespace: {escape(operator.get("namespace", "desconocido"))}</p>',
            "      </div>",
            '      <div class="operator-body">',
            f'        <p class="small">Snapshot: {escape(metadata.get("captureStartedAt", "desconocido"))} a {escape(metadata.get("captureCompletedAt", "desconocido"))} · Eventos relacionados: {state["matched"]} · Informe Markdown: {escape(markdown_path.name)}</p>',
            '        <h3 class="section-label">APIs y recursos personalizados</h3>',
            '        <table><thead><tr><th>API</th><th>CRD</th><th>Instancias actuales</th><th>Peticiones</th><th>Correctas</th><th>Fallidas</th></tr></thead><tbody>',
        ])
        if not metadata.get("ownedCRDs"):
            lines.append('<tr><td colspan="6">El CSV no declara CRDs propios.</td></tr>')
        for crd in metadata.get("ownedCRDs", []):
            inventory = inventory_by_crd.get(crd.get("name"), {})
            instance_value = "desconocido (consulta fallida)" if inventory.get("status") == "error" else str(inventory.get("count", 0))
            for version in crd.get("versions") or ["unknown"]:
                api_name = f"{crd.get('plural', '?')}.{version}.{crd.get('group', '?')}"
                stat = state["api_stats"].get(api_name, {"total": 0, "success": 0, "failed": 0})
                lines.append(
                    f'<tr><td><code>{escape(api_name)}</code></td><td><code>{escape(crd.get("name", "?"))}</code></td>'
                    f'<td>{instance_value}</td><td>{stat["total"]}</td><td>{stat["success"]}</td><td>{stat["failed"]}</td></tr>'
                )
        lines.extend(['        </tbody></table>', '        <h3 class="section-label">Actividad por identidad</h3>'])
        actor_stats = state["actor_stats"]
        if not actor_stats:
            lines.append("        <p>No se encontraron eventos coincidentes en la ventana solicitada.</p>")
        else:
            lines.extend(['        <table><thead><tr><th>Tipo</th><th>Identidad</th><th>userAgent</th><th>APIs</th><th>Namespaces</th><th>Peticiones</th><th>Verbos</th><th>Primera / última</th></tr></thead><tbody>'])
            for (category, username, user_agent), stat in sorted(actor_stats.items(), key=lambda item: (-item[1]["count"], item[0])):
                verbs = ", ".join(f"{verb}: {count}" for verb, count in sorted(stat["verbs"].items()))
                apis = ", ".join(sorted(stat["apis"]))
                namespaces = ", ".join(sorted(stat["namespaces"])) or "cluster-scope / no especificado"
                lines.append(
                    f'<tr><td>{escape(category)}</td><td><code>{escape(username)}</code></td><td><code>{escape(user_agent)}</code></td>'
                    f'<td>{escape(apis)}</td><td>{escape(namespaces)}</td><td>{stat["count"]}</td><td>{escape(verbs)}</td>'
                    f'<td>{escape(isoformat(stat["first"]))}<br>{escape(isoformat(stat["last"]))}</td></tr>'
                )
            lines.append("        </tbody></table>")

        resources_path = metadata_path.parent / "resources.jsonl"
        lines.append('        <h3 class="section-label">Instancias actuales</h3>')
        resource_rows = []
        if resources_path.is_file():
            with resources_path.open(encoding="utf-8") as source:
                for line in source:
                    try:
                        resource_rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        if resource_rows:
            lines.extend(['        <table><thead><tr><th>CRD</th><th>Namespace</th><th>Recurso</th></tr></thead><tbody>'])
            for item in resource_rows:
                lines.append(f'<tr><td><code>{escape(item.get("crd", "?"))}</code></td><td>{escape(item.get("namespace") or "cluster")}</td><td><code>{escape(item.get("name", "?"))}</code></td></tr>')
            lines.append("        </tbody></table>")
        else:
            lines.append("        <p>No se encontraron instancias en el inventario capturado.</p>")

        errors = metadata.get("auditCaptureErrors", []) + metadata.get("resourceInventoryErrors", [])
        if errors:
            lines.append('        <div class="warning"><strong>Captura incompleta; revisar antes de interpretar:</strong><ul>')
            lines.extend(f"          <li>{escape(error)}</li>" for error in errors)
            lines.append("        </ul></div>")
        lines.extend(["      </div>", "    </article>"])

    lines.extend(["  </main>", "</body>", "</html>"])
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Informe HTML escrito en {terminal_safe(output)}")


def audit_files_from(directory: Path) -> list[Path]:
    files = []
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        if "audit" in path.name.lower() or path.suffix in {".json", ".jsonl", ".ndjson", ".gz"}:
            files.append(path)
    return sorted(files)


def event_time(event: dict[str, Any]) -> dt.datetime | None:
    return parse_time(event.get("requestReceivedTimestamp") or event.get("stageTimestamp"))


def api_version(event: dict[str, Any]) -> str:
    value = (event.get("objectRef") or {}).get("apiVersion", "")
    if "/" in value:
        return value.split("/", 1)[1]
    if value:
        return value
    parts = event.get("requestURI", "").split("?", 1)[0].strip("/").split("/")
    return parts[2] if len(parts) >= 3 and parts[0] == "apis" else "unknown"


def actor_category(username: str, operator_sas: set[str]) -> str:
    if username in operator_sas:
        return "operator"
    if username.startswith("system:serviceaccount:"):
        return "service-account"
    if username.startswith("system:") or username.startswith("kube:"):
        return "platform/system"
    return "user"


def md(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", text)
    return text.replace("<", "&lt;").replace(">", "&gt;")


def md_code(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    escaped = html.escape(text, quote=False).replace("|", "&#124;")
    return f"<code>{escaped}</code>"


# Procesa una sola vez los logs aunque se generen informes de varios operadores.
def scan_audit_logs(metadata_list: list[dict[str, Any]], audit_dir: Path, days_override: int | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    files = audit_files_from(audit_dir)
    if not files and not any(item.get("auditCaptureErrors") for item in metadata_list):
        raise RuntimeError(f"No se encontraron logs audit en {audit_dir}.")

    states = []
    crd_targets: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for index, metadata in enumerate(metadata_list):
        if metadata.get("formatVersion") != 1 or not isinstance(metadata.get("ownedCRDs"), list):
            raise RuntimeError("Formato de metadata no compatible; usa un snapshot creado por este script.")
        days = days_override if days_override is not None else int(metadata.get("requestedDays", 30))
        end = parse_time(metadata.get("captureCompletedAt")) or utc_now()
        states.append({
            "metadata": metadata,
            "days": days,
            "start": end - dt.timedelta(days=days),
            "end": end,
            "operator_sas": set(metadata.get("operatorServiceAccounts", [])),
            "actor_stats": {},
            "api_stats": defaultdict(lambda: {"total": 0, "success": 0, "failed": 0, "unknown": 0}),
            "matched": 0,
        })
        for crd in metadata["ownedCRDs"]:
            key = (crd.get("group", ""), crd.get("plural", ""))
            if key[0] and key[1]:
                crd_targets[key].append((index, crd))

    oldest: dt.datetime | None = None
    newest: dt.datetime | None = None
    malformed = 0
    parsed = 0
    for file_index, path in enumerate(files, start=1):
        print(f"[{file_index}/{len(files)}] Analizando {terminal_safe(path.name)}", file=sys.stderr)
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as source:
            for line in source:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                if not isinstance(event, dict):
                    continue
                parsed += 1
                timestamp = event_time(event)
                if timestamp:
                    oldest = min(oldest, timestamp) if oldest else timestamp
                    newest = max(newest, timestamp) if newest else timestamp
                if event.get("stage") != "ResponseComplete" or timestamp is None:
                    continue

                object_ref = event.get("objectRef") or {}
                group = object_ref.get("apiGroup") or ""
                resource = object_ref.get("resource") or ""
                version = object_ref.get("apiVersion") or ""
                if "/" in version:
                    group_from_version, version = version.split("/", 1)
                    group = group or group_from_version
                targets = crd_targets.get((group, resource), []) if group and resource else []
                matching = [
                    (index, crd) for index, crd in targets
                    if not version or version in crd.get("versions", [])
                ]
                if not matching:
                    uri = event.get("requestURI", "").split("?", 1)[0]
                    parts = uri.strip("/").split("/")
                    if len(parts) >= 4 and parts[0] == "apis":
                        group, version = parts[1], parts[2]
                        resource_index = 5 if len(parts) > 5 and parts[3] == "namespaces" else 3
                        resource = parts[resource_index] if resource_index < len(parts) else ""
                        targets = crd_targets.get((group, resource), [])
                        matching = [
                            (index, crd) for index, crd in targets
                            if not version or version in crd.get("versions", [])
                        ]
                if not matching:
                    continue

                username = (event.get("user") or {}).get("username", "unknown")
                user_agent = event.get("userAgent", "") or "unknown"
                namespace = object_ref.get("namespace")
                code = (event.get("responseStatus") or {}).get("code")
                for index, crd in matching:
                    state = states[index]
                    if timestamp < state["start"] or timestamp > state["end"]:
                        continue
                    state["matched"] += 1
                    category = actor_category(username, state["operator_sas"])
                    actor_key = (category, username, user_agent)
                    api_name = f"{crd['plural']}.{version or api_version(event)}.{crd['group']}"
                    stat = state["actor_stats"].setdefault(
                        actor_key,
                        {"count": 0, "verbs": Counter(), "apis": set(), "namespaces": set(), "first": timestamp, "last": timestamp, "success": 0, "failed": 0, "unknown": 0},
                    )
                    stat["count"] += 1
                    stat["verbs"][event.get("verb", "unknown")] += 1
                    stat["apis"].add(api_name)
                    if namespace:
                        stat["namespaces"].add(namespace)
                    stat["first"] = min(stat["first"], timestamp)
                    stat["last"] = max(stat["last"], timestamp)

                    api_stat = state["api_stats"][api_name]
                    api_stat["total"] += 1
                    if isinstance(code, int) and 200 <= code < 400:
                        stat["success"] += 1
                        api_stat["success"] += 1
                    elif isinstance(code, int) and code >= 400:
                        stat["failed"] += 1
                        api_stat["failed"] += 1
                    else:
                        stat["unknown"] += 1
                        api_stat["unknown"] += 1
        print(f"[{file_index}/{len(files)}] Terminado {terminal_safe(path.name)}", file=sys.stderr)

    return states, {"files": files, "parsed": parsed, "malformed": malformed, "oldest": oldest, "newest": newest}


def write_report(metadata: dict[str, Any], metadata_path: Path, output: Path, state: dict[str, Any], audit_summary: dict[str, Any]) -> None:
    operator = metadata.get("operator", {})
    days = state["days"]
    start, end = state["start"], state["end"]
    actor_stats, api_stats = state["actor_stats"], state["api_stats"]
    actor_totals = Counter()
    for (category, _username, _agent), stat in actor_stats.items():
        actor_totals[category] += stat["count"]
    other_count = sum(count for category, count in actor_totals.items() if category != "operator")
    operator_count = actor_totals.get("operator", 0)
    coverage_start = isoformat(audit_summary["oldest"]) if audit_summary["oldest"] else "no timestamps found"
    coverage_end = isoformat(audit_summary["newest"]) if audit_summary["newest"] else "no timestamps found"
    incomplete = bool(metadata.get("auditCaptureErrors") or metadata.get("resourceInventoryErrors"))
    inventory_by_crd = {item.get("crd"): item for item in metadata.get("resourceInventory", [])}
    lines = [
        "# Informe de actividad de operador",
        "",
        f"- Operador: **{md(operator.get('displayName', 'desconocido'))}**",
        f"- CSV: {md_code(operator.get('csv', 'desconocido'))}; namespace: {md_code(operator.get('namespace', 'desconocido'))}",
        f"- Ventana solicitada: {days} días ({isoformat(start)} a {isoformat(end)})",
        f"- Informe generado: {isoformat(utc_now())}",
        f"- Origen de logs: {md(metadata.get('auditSource', 'desconocido'))}",
        f"- Ficheros de auditoría analizados: {len(audit_summary['files'])}; eventos JSON válidos: {audit_summary['parsed']}; eventos relacionados: {state['matched']}",
        f"- Rango temporal observado en los logs: {coverage_start} a {coverage_end}",
        f"- Snapshot capturado: {metadata.get('captureStartedAt', 'desconocido')} a {metadata.get('captureCompletedAt', 'desconocido')}",
        "",
        "> La cobertura temporal refleja las marcas de tiempo encontradas; no demuestra que los logs cubran cada instante del periodo.",
        "> La actividad fuera de las cuentas de servicio del operador no demuestra por sí sola que una persona dependa del operador.",
        "",
        "## Resumen",
        "",
        "| API del operador | CRD | Instancias actuales | Peticiones | Correctas | Fallidas |",
        "|---|---|---:|---:|---:|---:|",
    ]
    if not metadata["ownedCRDs"]:
        lines.append("| No declara CRD propios | — | — | — | — | — |")
    else:
        for crd in metadata["ownedCRDs"]:
            inventory = inventory_by_crd.get(crd.get("name"), {})
            instance_count = "desconocido (falló consulta)" if inventory.get("status") == "error" else inventory.get("count", 0)
            for version in crd.get("versions") or ["unknown"]:
                api_name = f"{crd.get('plural', '?')}.{version}.{crd.get('group', '?')}"
                stat = api_stats.get(api_name, {"total": 0, "success": 0, "failed": 0})
                lines.append(f"| {md_code(api_name)} | {md_code(crd.get('name', '?'))} | {instance_count} | {stat['total']} | {stat['success']} | {stat['failed']} |")
    lines.extend([
        "",
        f"- Peticiones de las cuentas de servicio identificadas del operador: **{operator_count}**.",
        f"- Peticiones de otras identidades: **{other_count}**.",
        f"- Estado de captura: **{'incompleta; revisar metadata.json' if incomplete else 'sin errores de captura registrados'}**.",
        "",
        "## Actividad por identidad",
        "",
    ])
    if not actor_stats:
        lines.append("No se encontraron eventos coincidentes dentro de la ventana solicitada.")
    else:
        lines.extend(["| Tipo | Identidad | userAgent | APIs | Namespaces | Peticiones | Verbos | Primera | Última |", "|---|---|---|---|---|---:|---|---|---|"])
        for (category, username, user_agent), stat in sorted(actor_stats.items(), key=lambda item: (-item[1]["count"], item[0])):
            verbs = ", ".join(f"{verb}: {count}" for verb, count in sorted(stat["verbs"].items()))
            apis = ", ".join(sorted(stat["apis"]))
            namespaces = ", ".join(sorted(stat["namespaces"])) or "cluster-scope / no especificado"
            lines.append(f"| {md(category)} | {md_code(username)} | {md_code(user_agent)} | {md(apis)} | {md(namespaces)} | {stat['count']} | {md(verbs)} | {isoformat(stat['first'])} | {isoformat(stat['last'])} |")
    lines.extend(["", "## Recursos actuales", ""])
    resources_path = metadata_path.parent / "resources.jsonl"
    if resources_path.is_file():
        resource_rows = []
        with resources_path.open(encoding="utf-8") as source:
            for line in source:
                try:
                    resource_rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        if resource_rows:
            lines.extend(["| CRD | Namespace | Recurso |", "|---|---|---|"])
            for item in resource_rows:
                lines.append(f"| {md_code(item.get('crd', '?'))} | {md_code(item.get('namespace') or 'cluster')} | {md_code(item.get('name', '?'))} |")
        else:
            lines.append("No se encontraron instancias en el inventario capturado.")
    else:
        lines.append("No hay fichero local de inventario de recursos.")
    if audit_summary["malformed"]:
        lines.extend(["", f"Líneas de log que no se pudieron interpretar como JSON: {audit_summary['malformed']}."])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Informe escrito en {terminal_safe(output)}")


def analyze(metadata_path: Path, audit_dir: Path, output: Path, days_override: int | None) -> None:
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"No se pudo leer metadata JSON: {metadata_path}") from exc
    states, audit_summary = scan_audit_logs([metadata], audit_dir, days_override)
    write_report(metadata, metadata_path, output, states[0], audit_summary)
    write_html_report([metadata], [metadata_path], [output], states, audit_summary, output.with_suffix(".html"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sin subcomando, selecciona operadores y genera un informe por cada uno. También permite capturar o analizar snapshots.",
        epilog=(
            "FLUJO RECOMENDADO: CAPTURAR Y ANALIZAR EN DOS PASOS\n"
            "  1. Con acceso al clúster, captura metadata y logs de auditoría disponibles:\n"
            "     ocp-operator-api-usage.sh capture --operator ejemplo-operator.v1.2.3 --output-dir snapshot-ejemplo\n"
            "  2. Analiza el snapshot localmente (no consulta el clúster):\n"
            "     ocp-operator-api-usage.sh analyze --snapshot-dir snapshot-ejemplo --output informe.md\n"
            "  La captura contiene metadata.json, el inventario de recursos y los logs en audit/.\n"
            "  El análisis genera el Markdown solicitado y un HTML junto a él.\n\n"
            "USAR LOGS DE AUDITORÍA DESCARGADOS POR SEPARADO\n"
            "  1. Con acceso al clúster, crea metadata para un operador, sin descargar logs:\n"
            "     ocp-operator-api-usage.sh capture --operator ejemplo-operator.v1.2.3 --output-dir metadata-ejemplo --metadata-only\n"
            "     Conserva metadata-ejemplo/metadata.json para el análisis posterior.\n"
            "  2. Lista los ficheros de auditoría visibles en los nodos master:\n"
            "     oc adm node-logs --role=master --path=kube-apiserver/\n"
            "  3. Crea un directorio y exporta cada fichero audit*.log que quieras analizar,\n"
            "     usando el nodo y el nombre exacto mostrados por el comando anterior:\n"
            "     mkdir -p logs-audit\n"
            "     Sustituye NODE y FILE por los valores listados; repite para cada fichero:\n"
            "     NODE=master-0; FILE=audit.log\n"
            "     oc adm node-logs \"$NODE\" --path=\"kube-apiserver/$FILE\" > \"logs-audit/${NODE}__${FILE}\"\n"
            "     Requiere permisos\n"
            "     para leer los logs de los nodos; el periodo depende de la retención existente.\n"
            "  4. Analiza esos logs con la metadata correspondiente al CSV:\n"
            "     ocp-operator-api-usage.sh analyze --audit-dir logs-audit \\\n"
            "       --metadata metadata-ejemplo/metadata.json --days 30 --output informe.md\n"
            "  Se aceptan logs JSON por líneas y comprimidos en .gz; el directorio se recorre\n"
            "  también en sus subdirectorios. Cada ejecución de este modo analiza un operador.\n\n"
            "La ausencia de eventos en los logs disponibles no demuestra que el operador sea prescindible."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    capture_parser = subparsers.add_parser(
        "capture",
        help="captura metadata, inventario de recursos y logs de auditoría",
        description="Conecta con el clúster y guarda datos locales para un operador.",
        epilog=(
            "Captura completa (metadata, inventario y logs de auditoría disponibles):\n"
            "  ocp-operator-api-usage.sh capture --operator ejemplo-operator.v1.2.3 --output-dir snapshot-ejemplo\n\n"
            "Solo metadata e inventario, para combinar después con logs descargados aparte:\n"
            "  ocp-operator-api-usage.sh capture --operator ejemplo-operator.v1.2.3 --output-dir metadata-ejemplo --metadata-only\n\n"
            "Si hay CSV con el mismo nombre en varios namespaces, indica --namespace.\n"
            "El directorio de salida debe ser nuevo. La captura necesita acceso al clúster;\n"
            "los logs disponibles dependen de la retención y de los permisos del usuario."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    capture_parser.add_argument("--operator", help="nombre exacto del CSV; si se omite, muestra un listado interactivo")
    capture_parser.add_argument("--namespace", help="namespace del CSV, si el nombre aparece más de una vez")
    capture_parser.add_argument("--days", type=int, default=30, help="periodo que se analizará (por defecto: 30 días)")
    capture_parser.add_argument("--output-dir", required=True, help="directorio nuevo donde guardar el snapshot")
    capture_parser.add_argument("--metadata-only", action="store_true", help="guarda metadatos para analizar logs exportados aparte")
    capture_parser.set_defaults(func=capture)

    report_parser = subparsers.add_parser("report", help="selecciona varios operadores y genera un informe por cada uno")
    report_parser.add_argument("--operator", action="append", default=[], help="CSV instalado; repite la opción para seleccionar varios")
    report_parser.add_argument("--namespace", help="limita el listado o búsqueda de CSV a un namespace")
    report_parser.add_argument("--days", type=int, default=30, help="periodo que se analizará (por defecto: 30 días)")
    report_parser.add_argument("--output-dir", default="operator-reports", help="directorio donde guardar los informes Markdown (por defecto: ./operator-reports)")
    report_parser.set_defaults(func=report)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="analiza un snapshot local sin consultar el clúster",
        description="Analiza un snapshot completo o logs de auditoría descargados aparte.",
        epilog=(
            "Snapshot completo creado con capture:\n"
            "  ocp-operator-api-usage.sh analyze --snapshot-dir snapshot-ejemplo --output informe.md\n\n"
            "Logs descargados aparte: --metadata debe ser el metadata.json creado para ese CSV\n"
            "con capture --metadata-only. --audit-dir contiene los logs JSON por líneas,\n"
            "incluidos los comprimidos en .gz. --days sobrescribe la ventana guardada.\n"
            "Se generan un informe Markdown y otro HTML con el mismo nombre base.\n\n"
            "Ejemplo:\n"
            "  ocp-operator-api-usage.sh analyze --audit-dir logs-audit \\\n"
            "    --metadata metadata-ejemplo/metadata.json --days 30 --output informe.md"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    input_group = analyze_parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--snapshot-dir", help="directorio creado con el comando capture")
    input_group.add_argument("--audit-dir", help="directorio con logs de auditoría JSON exportados manualmente")
    analyze_parser.add_argument("--metadata", help="metadata.json de un snapshot; requerido con --audit-dir")
    analyze_parser.add_argument("--days", type=int, help="sobrescribe la ventana guardada en metadata.json")
    analyze_parser.add_argument("--output", default="operator-api-usage-report.md", help="ruta del informe Markdown")
    analyze_parser.set_defaults(func=run_analysis)
    return parser


def run_analysis(args: argparse.Namespace) -> None:
    if args.snapshot_dir:
        snapshot_dir = Path(args.snapshot_dir).expanduser().resolve()
        metadata_path = snapshot_dir / "metadata.json"
        audit_dir = snapshot_dir / "audit"
        if args.metadata:
            raise RuntimeError("No combines --snapshot-dir con --metadata.")
    else:
        if not args.metadata:
            raise RuntimeError("--metadata es obligatorio cuando se usa --audit-dir.")
        metadata_path = Path(args.metadata).expanduser().resolve()
        audit_dir = Path(args.audit_dir).expanduser().resolve()
    analyze(metadata_path, audit_dir, Path(args.output).expanduser().resolve(), args.days)


def main() -> int:
    # Audit files contain user identities; keep snapshots and reports private by default.
    os.umask(0o077)
    parser = build_parser()
    argv = sys.argv[1:]
    if not argv or (argv[0].startswith("-") and argv[0] not in {"-h", "--help"}):
        argv.insert(0, "report")
    args = parser.parse_args(argv)
    if getattr(args, "days", 1) is not None and args.days < 1:
        parser.error("--days debe ser al menos 1")
    try:
        args.func(args)
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"Error: {terminal_safe(exc)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
