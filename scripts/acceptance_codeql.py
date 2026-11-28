"""Installed-product controls for imported LDAP factories and native value proofs."""

from pathlib import Path


def write_codeql_controls(source: Path) -> None:
    (source / "html_bootstrap.py").write_text(
        "import importlib, os\nfrom flask import Flask\n"
        'plugin=importlib.import_module(os.getenv("PLUGIN_MODULE"))\n'
        "plugin.register_html_controls(Flask(__name__))\n",
        encoding="utf-8",
    )
    for variant, expression in (
        ("unsafe", "value"),
        ("safe", "escape(value)"),
        ("markup_unsafe", "Markup(value)"),
    ):
        (source / f"html_factory_{variant}.py").write_text(
            "from flask import request\nfrom markupsafe import Markup, escape\n"
            'def register_html_controls(app):\n    @app.route("/html")\n    def handler():\n'
            '        value=request.args.get("input")\n        response=""\n'
            f"        response+={expression}\n        return response\n",
            encoding="utf-8",
        )
    (source / "services").mkdir()
    (source / "services/ldap_factory.py").write_text(
        "import ldap3\ndef build_connection():\n"
        '    conn=ldap3.Connection("host")\n    conn.bind()\n    return conn\n',
        encoding="utf-8",
    )
    for safe in (False, True):
        value = "escape_filter_chars(value)" if safe else "value"
        (source / f"ldap_factory_{'safe' if safe else 'unsafe'}.py").write_text(
            "from flask import request\nimport services.ldap_factory\n"
            "from ldap3.utils.conv import escape_filter_chars\ndef init(app):\n"
            '    @app.route("/ldap")\n    def route():\n'
            '        value=request.args.get("input")\n'
            "        conn=services.ldap_factory.build_connection()\n        alias=conn\n"
            f'        alias.search(search_base="base",search_filter="(uid="+{value}+")")\n'
            '        return "done"\n',
            encoding="utf-8",
        )
        for kind in ("path", "xpath"):
            sink = "open(bar).read()" if kind == "path" else "str(etree.XPath(bar))"
            for model in ("match", "list"):
                body = (
                    f'choice="ABC"[{1 if safe else 0}]\nmatch choice:\n'
                    '    case "A":\n        bar=value\n    case "B":\n        bar="fixed"\n'
                    '    case "C" | "D":\n        bar=value\n    case _:\n        bar="fixed"\n'
                    if model == "match"
                    else 'lst=[]\nlst.append("first")\nlst.append(value)\nlst.append("last")\n'
                    f"lst.pop(0)\nbar=lst[{1 if safe else 0}]\n"
                )
                code = (
                    "from flask import Flask, request\nfrom lxml import etree\n"
                    'app=Flask(__name__)\n@app.get("/values")\ndef route():\n'
                    '    value=request.args.get("input")\n'
                    + "".join("    " + line + "\n" for line in body.splitlines())
                    + f"    return {sink}\n"
                )
                (
                    source / f"{model}_{kind}_{'safe' if safe else 'unsafe'}.py"
                ).write_text(code, encoding="utf-8")


def check_codeql_controls(
    findings: list[dict], diagnostic: dict, *, partial: bool
) -> None:
    html = [
        finding
        for finding in findings
        if any(
            source["rule_id"] == "pysec/flask-registration-html-injection"
            for source in finding["sources"]
        )
    ]
    html_paths = {loc["path"] for finding in html for loc in finding["locations"]}
    if (
        not {"html_factory_unsafe.py", "html_factory_markup_unsafe.py"} <= html_paths
        or "html_factory_safe.py" in html_paths
    ):
        raise ValueError("installed HTML factory positive/escaping controls failed")
    if any(not finding["evidence"].get("sarif_code_flows") for finding in html):
        raise ValueError("installed HTML factory finding lost its native path")
    ldap = [
        finding
        for finding in findings
        if any(
            source["rule_id"] == "pysec/ldap-factory-filter-injection"
            for source in finding["sources"]
        )
    ]
    paths = {loc["path"] for finding in ldap for loc in finding["locations"]}
    if "ldap_factory_unsafe.py" not in paths or "ldap_factory_safe.py" in paths:
        raise ValueError("installed LDAP factory positive/escaping controls failed")
    if any(not finding["evidence"].get("sarif_code_flows") for finding in ldap):
        raise ValueError("installed LDAP factory finding lost its native path")
    exclusions = diagnostic.get("native_flow_refinement", {}).get("exclusions", [])
    for kind, rule in (("path", "py/path-injection"), ("xpath", "py/xpath-injection")):
        locations = {
            loc["path"]
            for finding in findings
            if any(source["rule_id"] == rule for source in finding["sources"])
            for loc in finding["locations"]
        }
        for model in ("match", "list"):
            safe = f"{model}_{kind}_safe.py"
            if (
                f"{model}_{kind}_unsafe.py" not in locations
                or (safe in locations) != partial
            ):
                raise ValueError(f"installed {model}/{kind} controls failed")
            if not partial and not any(
                item["native_proof"]["ruleId"] == f"pysec/constant-{kind}-proof"
                and item["original_finding"]["evidence"].get("sarif_code_flows")
                and any(
                    loc["path"] == safe for loc in item["original_finding"]["locations"]
                )
                for item in exclusions
            ):
                raise ValueError(
                    f"installed {model}/{kind} exclusion lost native proof or original alert"
                )
