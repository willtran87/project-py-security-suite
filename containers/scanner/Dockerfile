# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# Python policy: the scanner image deliberately runs the oldest supported
# runtime (3.11) so the published `requires-python` floor is exercised end to
# end; CI covers 3.11 through 3.14 separately. See docs/compatibility-matrix.md.
FROM python:3.15.1-slim-bookworm@sha256:575f8bc12ec26542e0678bc6b60e385218248019d433157ec327264a78c3a853 AS wheel-builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# The build backend is hash-locked by the scanner project's `build` group and
# the wheel is built without network access or build isolation.
COPY containers/scanner/build-requirements.lock /build/build-requirements.lock
RUN python -m pip install --require-hashes --no-deps -r /build/build-requirements.lock

COPY pyproject.toml README.md LICENSE MANIFEST.in /build/source/
COPY src /build/source/src
RUN python -m pip wheel --no-deps --no-build-isolation --no-index \
    --wheel-dir /build/dist /build/source

FROM python:3.15.1-slim-bookworm@sha256:575f8bc12ec26542e0678bc6b60e385218248019d433157ec327264a78c3a853

ARG OSV_SCANNER_VERSION=2.3.8
ARG OSV_SCANNER_LINUX_AMD64_DIGEST=bc98e15319ed0d515e3f9235287ba53cdc5535d576d24fd573978ecfe9ab92dc
ARG OSV_PYPI_DATABASE_SHA256

LABEL org.opencontainers.image.title="Python Security Suite scanner bundle"
LABEL org.opencontainers.image.description="Offline runtime for the Python Security Suite standard profile"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL io.pysec.bandit.version="1.9.4"
LABEL io.pysec.semgrep.version="1.187.0"
LABEL io.pysec.detect-secrets.version="1.5.0"
LABEL io.pysec.osv-scanner.version="${OSV_SCANNER_VERSION}"
LABEL io.pysec.sbom.path="/opt/pysec-bundle/python-sbom.cdx.json"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

COPY containers/scanner/requirements.lock /opt/pysec-suite/requirements.lock
RUN python -m pip install --require-hashes -r /opt/pysec-suite/requirements.lock \
    && mkdir -p /opt/pysec-bundle /opt/osv-db/osv-scanner/PyPI

# Runtime dependencies are already hash-locked above, so the suite itself is
# installed from the locally built wheel without resolving anything further.
COPY --from=wheel-builder /build/dist/ /opt/pysec-wheel/
# The bundled Semgrep rules are exposed at a stable, layout-independent path
# that the image and self-scan configurations reference.
RUN python -m pip install --no-deps --no-index /opt/pysec-wheel/py_security_suite-*.whl \
    && python -m pip check \
    && python -c "import pathlib, shutil, py_security_suite; shutil.copytree(pathlib.Path(py_security_suite.__file__).parent / 'rules', '/opt/pysec-suite/rules')"
COPY containers/scanner/pysec.toml /opt/pysec-suite/pysec.toml

RUN python - <<'PY'
import hashlib
import importlib.metadata
import json
import pathlib
import uuid

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

root_distribution = importlib.metadata.distribution("py-security-suite")
root_display_name = root_distribution.metadata["Name"]
root_name = canonicalize_name(root_display_name)
root_version = root_distribution.version
if not root_version:
    raise SystemExit("package version authority is unavailable")
root_ref = f"pkg:pypi/{root_name}@{root_version}"
distributions = sorted(
    (
        distribution
        for distribution in importlib.metadata.distributions()
        if canonicalize_name(distribution.metadata.get("Name", "")) != root_name
    ),
    key=lambda item: (item.metadata.get("Name", "").casefold(), item.version),
)
references = {
    canonicalize_name(distribution.metadata.get("Name", "")): (
        f"pkg:pypi/{canonicalize_name(distribution.metadata.get('Name', ''))}"
        f"@{distribution.version}"
    )
    for distribution in distributions
    if distribution.metadata.get("Name", "").strip()
}
components = []
for distribution in distributions:
    name = distribution.metadata.get("Name", "").strip()
    if not name:
        continue
    canonical_name = canonicalize_name(name)
    metadata = distribution.read_text("METADATA") or ""
    component = {
        "type": "library",
        "bom-ref": references[canonical_name],
        "name": name,
        "version": distribution.version,
        "purl": references[canonical_name],
        "properties": [
            {
                "name": "io.pysec.installed-metadata.sha256",
                "value": hashlib.sha256(metadata.encode()).hexdigest(),
            }
        ],
    }
    license_expression = distribution.metadata.get("License-Expression", "").strip()
    if license_expression:
        component["licenses"] = [{"expression": license_expression}]
    components.append(component)
marker_environment = default_environment()
marker_environment["extra"] = ""
dependencies = []
for distribution in distributions:
    name = distribution.metadata.get("Name", "").strip()
    if not name:
        continue
    depends_on = set()
    for raw_requirement in distribution.requires or ():
        try:
            requirement = Requirement(raw_requirement)
        except InvalidRequirement:
            continue
        if requirement.marker and not requirement.marker.evaluate(marker_environment):
            continue
        dependency_ref = references.get(canonicalize_name(requirement.name))
        if dependency_ref:
            depends_on.add(dependency_ref)
    dependencies.append(
        {"ref": references[canonicalize_name(name)], "dependsOn": sorted(depends_on)}
    )
root_dependencies = set()
for raw_requirement in root_distribution.requires or ():
    requirement = Requirement(raw_requirement)
    if requirement.marker and not requirement.marker.evaluate(marker_environment):
        continue
    dependency_ref = references.get(canonicalize_name(requirement.name))
    if dependency_ref:
        root_dependencies.add(dependency_ref)
dependencies.append({"ref": root_ref, "dependsOn": sorted(root_dependencies)})
identity = hashlib.sha256(
    json.dumps(
        {"components": components, "dependencies": dependencies},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
).hexdigest()
document = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "bom-ref": root_ref,
            "name": root_display_name,
            "version": root_version,
            "purl": root_ref,
        },
        "properties": [{"name": "io.pysec.bom-graph.sha256", "value": identity}],
    },
    "components": components,
    "dependencies": dependencies,
}
pathlib.Path("/opt/pysec-bundle/python-sbom.cdx.json").write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

RUN python - "${OSV_SCANNER_VERSION}" "${OSV_SCANNER_LINUX_AMD64_DIGEST}" <<'PY'
import hashlib
import pathlib
import sys
import urllib.request

version, expected = sys.argv[1:]
target = pathlib.Path("/usr/local/bin/osv-scanner")
url = (
    "https://github.com/google/osv-scanner/releases/download/"
    f"v{version}/osv-scanner_linux_amd64"
)
with urllib.request.urlopen(url) as response, target.open("wb") as output:
    while chunk := response.read(1024 * 1024):
        output.write(chunk)
actual = hashlib.sha256(target.read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit(f"OSV-Scanner checksum mismatch: {actual} != {expected}")
target.chmod(0o755)
pathlib.Path("/opt/pysec-bundle/osv-scanner.sha256").write_text(
    f"{actual}  /usr/local/bin/osv-scanner\n",
    encoding="utf-8",
)
PY

# The connected preparation lane supplies one already sealed snapshot as a named
# BuildKit context. The image build never resolves the mutable publisher URL.
# Hadolint cannot resolve BuildKit named contexts as external input stages.
# hadolint ignore=DL3022
COPY --from=osv_database /osv-pypi-all.zip /opt/osv-db/osv-scanner/PyPI/all.zip
RUN python - "${OSV_PYPI_DATABASE_SHA256}" <<'PY'
import hashlib
import pathlib
import sys

expected = sys.argv[1]
target = pathlib.Path("/opt/osv-db/osv-scanner/PyPI/all.zip")
digest = hashlib.sha256(target.read_bytes()).hexdigest()
if len(expected) != 64 or digest != expected:
    raise SystemExit(f"PyPI OSV database checksum mismatch: {digest} != {expected}")
target.chmod(0o444)
pathlib.Path("/opt/pysec-bundle/osv-pypi-database.sha256").write_text(
    f"{digest}  /opt/osv-db/osv-scanner/PyPI/all.zip\n",
    encoding="utf-8",
)
PY

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN python -m pip freeze --all | sort > /opt/pysec-bundle/python-packages.txt

# Runtime callers deliberately use their host UID so bind-mounted evidence is
# not left owned by root. BuildKit does not guarantee a portable source mode
# for named-context copies, so every governed runtime asset must be explicitly
# traversable and readable by an otherwise unknown UID.
RUN chmod 0555 /opt /opt/osv-db /opt/osv-db/osv-scanner /opt/osv-db/osv-scanner/PyPI \
    /opt/pysec-bundle \
    && chmod 0444 /opt/osv-db/osv-scanner/PyPI/all.zip /opt/pysec-bundle/*

RUN bandit --version \
    && semgrep --version \
    && detect-secrets --version \
    && osv-scanner --version

RUN useradd --create-home --uid 65532 --shell /usr/sbin/nologin pysec \
    && mkdir -p /workspace \
    && chown pysec:pysec /workspace

WORKDIR /workspace
USER pysec

# This image runs a finite scanner command rather than a long-lived service.
HEALTHCHECK NONE

ENTRYPOINT ["python", "-m", "py_security_suite"]
CMD ["--help"]
