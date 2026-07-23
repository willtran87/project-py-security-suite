# syntax=docker/dockerfile:1
FROM python:3.11.13-slim-bookworm

ARG BANDIT_VERSION=1.9.4
ARG SEMGREP_VERSION=1.170.0
ARG DETECT_SECRETS_VERSION=1.5.0
ARG OSV_SCANNER_VERSION=2.3.8
ARG OSV_SCANNER_LINUX_AMD64_SHA256=bc98e15319ed0d515e3f9235287ba53cdc5535d576d24fd573978ecfe9ab92dc
ARG OSV_PYPI_DATABASE_SHA256=4b29a3ec3f5680ad6fc43714a00ec3ed726d2214eac73031279e9b0f02549627

LABEL org.opencontainers.image.title="Python Security Suite scanner bundle"
LABEL org.opencontainers.image.description="Offline runtime for the Python Security Suite standard profile"
LABEL io.pysec.bandit.version="${BANDIT_VERSION}"
LABEL io.pysec.semgrep.version="${SEMGREP_VERSION}"
LABEL io.pysec.detect-secrets.version="${DETECT_SECRETS_VERSION}"
LABEL io.pysec.osv-scanner.version="${OSV_SCANNER_VERSION}"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

RUN python -m pip install \
      "bandit==${BANDIT_VERSION}" \
      "semgrep==${SEMGREP_VERSION}" \
      "detect-secrets==${DETECT_SECRETS_VERSION}" \
    && mkdir -p /opt/pysec-bundle /opt/osv-db/osv-scanner/PyPI

RUN python - "${OSV_SCANNER_VERSION}" "${OSV_SCANNER_LINUX_AMD64_SHA256}" <<'PY'
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

# Connected update lane: acquire the current PyPI advisory database, store it in
# OSV-Scanner's documented cache layout, and record the imported bytes by digest.
RUN python - "${OSV_PYPI_DATABASE_SHA256}" <<'PY'
import hashlib
import pathlib
import sys
import urllib.request

expected = sys.argv[1]
target = pathlib.Path("/opt/osv-db/osv-scanner/PyPI/all.zip")
url = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
with urllib.request.urlopen(url) as response, target.open("wb") as output:
    while chunk := response.read(1024 * 1024):
        output.write(chunk)
digest = hashlib.sha256(target.read_bytes()).hexdigest()
if digest != expected:
    raise SystemExit(f"PyPI OSV database checksum mismatch: {digest} != {expected}")
pathlib.Path("/opt/pysec-bundle/osv-pypi-database.sha256").write_text(
    f"{digest}  /opt/osv-db/osv-scanner/PyPI/all.zip\n",
    encoding="utf-8",
)
PY

COPY pyproject.toml README.md /opt/pysec-suite/
COPY src /opt/pysec-suite/src
COPY containers/scanner/pysec.toml /opt/pysec-suite/pysec.toml

RUN python -m pip install --no-deps /opt/pysec-suite \
    && python -m pip freeze --all | sort > /opt/pysec-bundle/python-packages.txt

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
