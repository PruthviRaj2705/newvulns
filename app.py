from flask import Flask, render_template, request, jsonify, session
from dotenv import load_dotenv
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
load_dotenv()
app = Flask(__name__)
# ============================================================
# FRONTEND PAGE ROUTES
# ============================================================

@app.route("/login")
def login_page():
    return render_template("pages/login.html")


@app.route("/signup")
def signup_page():
    return render_template("pages/signup.html")


@app.route("/dashboard")
def dashboard_page():
    return render_template("pages/dashboard.html")


@app.route("/projects")
def projects_page():
    return render_template("pages/projects.html")


@app.route("/scan")
def scan_page():
    return render_template("pages/scan.html")


@app.route("/findings")
def findings_page():
    return render_template("pages/findings.html")


@app.route("/remediation")
def remediation_page():
    return render_template("pages/remediation.html")


@app.route("/verification")
def verification_page():
    return render_template("pages/verification.html")


@app.route("/flow")
def flow_page():
    return render_template("pages/flow.html")


@app.route("/history")
def history_page():
    return render_template("pages/history.html")


@app.route("/reports")
def reports_page():
    return render_template("pages/reports.html")


@app.route("/profile")
def profile_page():
    return render_template("pages/profile.html")


@app.route("/settings")
def settings_page():
    return render_template("pages/settings.html")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")

if not FLASK_SECRET_KEY:
    # Fail safe: never fall back to a fixed key that is visible in
    # source control (it would let anyone forge session cookies).
    # A random per-process key means sessions reset on restart until
    # FLASK_SECRET_KEY is configured.
    FLASK_SECRET_KEY = secrets.token_hex(32)
    print(
        "WARNING: FLASK_SECRET_KEY is not set. Using a random, "
        "process-local key. Set FLASK_SECRET_KEY for stable sessions."
    )

app.secret_key = FLASK_SECRET_KEY

# =========================================================
# CONFIGURATION
# =========================================================

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/interactions"
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")
GEMINI_REQUEST_TIMEOUT = int(os.environ.get("GEMINI_REQUEST_TIMEOUT", "240"))
GEMINI_MAX_RETRIES = int(os.environ.get("GEMINI_MAX_RETRIES", "2"))
MAX_REMEDIATION_ATTEMPTS = 5
# Temporary verified remediation workspaces.
# workspace_id -> workspace information
REMEDIATION_WORKSPACES = {}

# Automatically remove abandoned workspaces after this many seconds.
REMEDIATION_WORKSPACE_TTL = 3600
IGNORED_DIRECTORIES = {
    ".git",
    ".scannerwork",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
}

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".java", ".go", ".php", ".cs",
    ".cpp", ".c", ".h", ".rb",
    ".html", ".css", ".sql",
    ".sh", ".yml", ".yaml",
    ".xml", ".json", ".properties",
}


# =========================================================
# SECURITY HELPERS
# =========================================================

def redact_secrets(value):
    """Redact common API keys/tokens before sending data to Gemini."""
    if isinstance(value, dict):
        return {key: redact_secrets(val) for key, val in value.items()}

    if isinstance(value, list):
        return [redact_secrets(item) for item in value]

    if isinstance(value, str):
        patterns = [
            r"gsk_[A-Za-z0-9_-]+",
            r"AIza[A-Za-z0-9_-]+",
            r"sk-[A-Za-z0-9_-]+",
            r"ghp_[A-Za-z0-9_]+",
            r"github_pat_[A-Za-z0-9_]+",
            r"xox[baprs]-[A-Za-z0-9-]+",
        ]
        for pattern in patterns:
            value = re.sub(pattern, "[REDACTED_SECRET]", value)
        return value

    return value


def safe_extract_zip(zip_path, destination):
    """Extract a ZIP while preventing path traversal."""
    destination = os.path.abspath(destination)

    with zipfile.ZipFile(zip_path, "r") as archive:
        for member in archive.infolist():
            member_path = os.path.abspath(
                os.path.join(destination, member.filename)
            )

            if not member_path.startswith(destination + os.sep):
                raise ValueError(
                    "Unsafe ZIP file: path traversal detected."
                )

        archive.extractall(destination)


# =========================================================
# GITHUB
# =========================================================

def clone_github_repository(url, destination):
    """
    Clone a public GitHub repository for analysis.

    No GitHub token is required for the initial analysis.
    Authentication is handled separately when the user
    explicitly chooses to update GitHub.
    """
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP/HTTPS GitHub URLs are supported.")

    if parsed.netloc.lower() not in (
        "github.com",
        "www.github.com",
    ):
        raise ValueError("Please provide a GitHub repository URL.")

    result = subprocess.run(
        ["git", "clone", "--depth", "1", url, destination],
        capture_output=True,
        text=True,
        timeout=180,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Git clone failed:\n" + result.stderr[-3000:]
        )
# =========================================================
# GITHUB REMEDIATION PUSH
# =========================================================

def github_auth_url(url, token):
    """
    Create an authenticated GitHub URL for Git operations.

    The token is supplied at runtime and is never written
    to the project source code or .env file.
    """
    parsed = urllib.parse.urlparse(url)

    if parsed.netloc.lower() not in (
        "github.com",
        "www.github.com",
    ):
        raise ValueError("Invalid GitHub repository URL.")

    if not token or not token.strip():
        raise ValueError("GitHub token is required.")

    # Keep credentials out of logs.
    safe_path = parsed.path.rstrip("/")

    return (
        "https://x-access-token:"
        + urllib.parse.quote(token.strip(), safe="")
        + "@github.com"
        + safe_path
    )


def create_github_remediation_branch(
    project_directory,
    repository_url,
    github_token,
):
    """
    Create a remediation branch and push the verified project.

    The GitHub token is supplied only for this operation.
    It is passed to Git through GIT_ASKPASS instead of being
    stored in the Git remote URL.
    """

    if not github_token:
        raise ValueError(
            "GitHub token is required."
        )

    parsed = urllib.parse.urlparse(
        repository_url
    )

    if parsed.netloc.lower() not in (
        "github.com",
        "www.github.com",
    ):
        raise ValueError(
            "Invalid GitHub repository URL."
        )

    branch_name = (
        "security-ai-fix-"
        + time.strftime("%Y%m%d-%H%M%S")
    )

    def run_git(
        args,
        env=None,
    ):
        result = subprocess.run(
            ["git"] + args,
            cwd=project_directory,
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "Git command failed:\n"
                + result.stderr[-3000:]
            )

        return result.stdout.strip()

    # -------------------------------------------------
    # Create temporary GIT_ASKPASS script
    # -------------------------------------------------

    askpass_file = tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        suffix=".cmd",
        encoding="utf-8",
    )

    try:

        askpass_file.write(
            "@echo off\n"
            "echo %GITHUB_TOKEN%\n"
        )

        askpass_file.close()

        git_env = os.environ.copy()

        git_env[
            "GIT_ASKPASS"
        ] = askpass_file.name

        git_env[
            "GIT_TERMINAL_PROMPT"
        ] = "0"

        git_env[
            "GITHUB_TOKEN"
        ] = github_token

        # -------------------------------------------------
        # Create remediation branch
        # -------------------------------------------------

        run_git(
            [
                "checkout",
                "-b",
                branch_name,
            ],
            env=git_env,
        )

        # -------------------------------------------------
        # Configure a local commit identity for this workspace
        # -------------------------------------------------
        run_git(
            [
                "config",
                "user.name",
                "Security Analyzer",
            ],
            env=git_env,
        )

        run_git(
            [
                "config",
                "user.email",
                "security-analyzer@localhost",
            ],
            env=git_env,
        )

        # -------------------------------------------------
        # Stage changes
        # -------------------------------------------------

        run_git(
            [
                "add",
                "-A",
            ],
            env=git_env,
        )

        # -------------------------------------------------
        # Confirm changes exist
        # -------------------------------------------------

        status = run_git(
            [
                "status",
                "--porcelain",
            ],
            env=git_env,
        )

        if not status:
            raise RuntimeError(
                "No remediation changes were found."
            )

        # -------------------------------------------------
        # Commit
        # -------------------------------------------------

        run_git(
            [
                "commit",
                "-m",
                "fix: apply AI security remediation",
            ],
            env=git_env,
        )

        # -------------------------------------------------
        # Push branch
        # -------------------------------------------------

        remote_url = (
            repository_url.rstrip("/")
        )

        if remote_url.endswith(".git"):
            remote_url = remote_url[:-4]

        remote_url += ".git"

        run_git(
            [
                "push",
                "--set-upstream",
                remote_url,
                branch_name,
            ],
            env=git_env,
        )

        return {
            "branch": branch_name,
            "repository": (
                repository_url.rstrip("/")
                .removesuffix(".git")
            ),
            "success": True,
        }

    finally:

        # -------------------------------------------------
        # Delete temporary authentication script
        # -------------------------------------------------

        try:
            os.unlink(
                askpass_file.name
            )
        except OSError:
            pass

        # Remove token from the environment object.
        git_env = None   


# =========================================================
# SOURCE COLLECTION
# =========================================================
# =========================================================
# SOURCE COLLECTION
# =========================================================

def collect_source_code(project_directory, max_total_size=120_000):
    """
    Collect relevant source files for Gemini.
    Secrets are redacted and oversized projects are truncated.
    """
    source = {}
    total_size = 0

    for root, dirs, files in os.walk(project_directory):
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in IGNORED_DIRECTORIES
        ]

        for filename in files:
            full_path = os.path.join(root, filename)
            lower_name = filename.lower()
            extension = os.path.splitext(filename)[1].lower()

            if (
                extension not in SOURCE_EXTENSIONS
                and lower_name not in ("dockerfile", "jenkinsfile")
            ):
                continue

            try:
                if os.path.getsize(full_path) > 150_000:
                    continue

                with open(
                    full_path,
                    "r",
                    encoding="utf-8",
                    errors="ignore",
                ) as file:
                    content = file.read()

                if total_size + len(content) > max_total_size:
                    continue

                relative_path = os.path.relpath(
                    full_path,
                    project_directory,
                )

                source[relative_path] = redact_secrets(content)
                total_size += len(content)

            except (OSError, UnicodeError):
                continue

    return source


# =========================================================
# TRIVY
# =========================================================

def run_trivy(project_directory):
    output_file = os.path.join(
        project_directory,
        "trivy-report.json",
    )

    trivy_command = shutil.which("trivy")

    if trivy_command:
        command = [
            trivy_command,
            "fs",
            "--scanners",
            "vuln,secret",
            "--format",
            "json",
            "--output",
            output_file,
            project_directory,
        ]
    else:
        docker_command = shutil.which("docker")

        if not docker_command:
            raise RuntimeError(
                "Trivy was not found and Docker is not available."
            )

        command = [
            docker_command,
            "run",
            "--rm",
            "-v",
            f"{os.path.abspath(project_directory)}:/src",
            "aquasec/trivy:0.74.0",
            "fs",
            "--scanners",
            "vuln,secret",
            "--format",
            "json",
            "--output",
            "/src/trivy-report.json",
            "/src",
        ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=600,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Trivy scan failed:\n" + result.stderr[-3000:]
        )

    if not os.path.exists(output_file):
        raise RuntimeError(
            "Trivy completed but did not create a report."
        )

    with open(output_file, "r", encoding="utf-8") as file:
        return json.load(file)


def summarize_trivy(report):
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "secrets": 0,
    }

    for result in report.get("Results", []) or []:
        for vulnerability in result.get("Vulnerabilities", []) or []:
            severity = str(
                vulnerability.get("Severity", "")
            ).upper()

            if severity in counts:
                counts[severity.lower()] += 1

        for secret in result.get("Secrets", []) or []:
            counts["secrets"] += 1

            severity = str(
                secret.get("Severity", "")
            ).upper()

            if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                counts[severity.lower()] += 1

    return counts


# =========================================================
# SONARQUBE
# =========================================================

def sonar_api_request(url, token):
    """
    SonarQube token authentication:
    token as HTTP Basic username and empty password.
    """
    credentials = f"{token}:".encode("utf-8")
    encoded = base64.b64encode(credentials).decode("ascii")

    request = urllib.request.Request(url)
    request.add_header("Authorization", "Basic " + encoded)
    request.add_header("Accept", "application/json")

    return request


def sonar_api_get_json(url, token):
    request = sonar_api_request(url, token)

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(
                response.read().decode("utf-8")
            )

    except urllib.error.HTTPError as error:
        body = ""
        try:
            body = error.read().decode(
                "utf-8",
                errors="replace",
            )
        except Exception:
            pass

        raise RuntimeError(
            f"SonarQube API request failed: HTTP {error.code}: "
            f"{body[:800]}"
        )

    except urllib.error.URLError as error:
        raise RuntimeError(
            f"SonarQube connection failed: {error}"
        )


def run_sonarqube(project_directory):
    sonar_token = os.environ.get("SONAR_TOKEN")

    if not sonar_token:
        raise RuntimeError(
            "SONAR_TOKEN environment variable is not set."
        )

    sonar_api_url = os.environ.get(
        "SONAR_API_URL",
        "http://localhost:9000",
    ).rstrip("/")

    sonar_scanner_url = os.environ.get(
        "SONAR_SCANNER_URL",
        "http://host.docker.internal:9000",
    ).rstrip("/")

    # A temporary workspace changes every run, so derive a short
    # project key from the source path for this scan.
    project_hash = hashlib.sha256(
        os.path.abspath(project_directory).encode("utf-8")
    ).hexdigest()[:16]

    project_key = "security-analysis-" + project_hash

    properties_file = os.path.join(
        project_directory,
        "sonar-project.properties",
    )

    with open(properties_file, "w", encoding="utf-8") as file:
        file.write(f"sonar.projectKey={project_key}\n")
        file.write("sonar.sources=/usr/src\n")
        file.write(f"sonar.host.url={sonar_scanner_url}\n")
        file.write(
            "sonar.exclusions="
            "**/.git/**,"
            "**/.scannerwork/**,"
            "**/__pycache__/**,"
            "**/*.pyc,"
            "**/node_modules/**,"
            "**/trivy-report.json\n"
        )
        file.write("sonar.scm.disabled=true\n")

    docker_command = shutil.which("docker")

    if not docker_command:
        raise RuntimeError(
            "Docker is required for SonarQube scanning."
        )

    command = [
        docker_command,
        "run",
        "--rm",
        "-e",
        "SONAR_TOKEN",
        "-v",
        f"{os.path.abspath(project_directory)}:/usr/src",
        "sonarsource/sonar-scanner-cli",
    ]

    print("Starting SonarQube scan...")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=900,
        env=os.environ.copy(),
    )

    scanner_output = result.stdout + "\n" + result.stderr

    if result.returncode != 0:
        raise RuntimeError(
            "SonarQube scan failed:\n"
            + scanner_output[-6000:]
        )

    print("SonarQube scan completed.")

    task_file = os.path.join(
        project_directory,
        ".scannerwork",
        "report-task.txt",
    )

    task_id = None

    if os.path.exists(task_file):
        with open(
            task_file,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            for line in file:
                if line.startswith("ceTaskId="):
                    task_id = line.split("=", 1)[1].strip()
                    break

    if not task_id:
        for line in scanner_output.splitlines():
            if "/api/ce/task?id=" in line:
                task_id = line.split(
                    "/api/ce/task?id=",
                    1,
                )[1].strip().rstrip(".,)")
                break

    if not task_id:
        raise RuntimeError(
            "SonarQube completed but the analysis task ID "
            "was not found."
        )

    task_url = (
        sonar_api_url
        + "/api/ce/task?id="
        + urllib.parse.quote(task_id)
    )

    print("Waiting for SonarQube processing...")

    for _ in range(90):
        task_data = sonar_api_get_json(
            task_url,
            sonar_token,
        )

        task = task_data.get("task", {})
        status = str(
            task.get("status", "")
        ).upper()

        print("SonarQube task status:", status)

        if status == "SUCCESS":
            break

        if status in ("FAILED", "CANCELED"):
            raise RuntimeError(
                "SonarQube analysis "
                + status
                + ": "
                + str(
                    task.get(
                        "errorMessage",
                        "Unknown error",
                    )
                )
            )

        time.sleep(2)
    else:
        raise RuntimeError(
            "Timed out waiting for SonarQube analysis."
        )

    params = urllib.parse.urlencode({
        "componentKeys": project_key,
        "resolved": "false",
        "types": "VULNERABILITY",
        "ps": "500",
    })

    issues_url = (
        sonar_api_url
        + "/api/issues/search?"
        + params
    )

    data = sonar_api_get_json(
        issues_url,
        sonar_token,
    )

    print(
        "SonarQube vulnerabilities retrieved:",
        len(data.get("issues", [])),
    )

    return data


def summarize_sonarqube(report):
    counts = {
        "blocker": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for issue in report.get("issues", []) or []:
        issue_type = str(
            issue.get("type", "")
        ).upper()

        if issue_type != "VULNERABILITY":
            continue

        severity = str(
            issue.get("severity", "")
        ).upper()

        if severity == "BLOCKER":
            counts["blocker"] += 1
        elif severity == "CRITICAL":
            counts["critical"] += 1
        elif severity == "MAJOR":
            counts["high"] += 1
        elif severity == "MINOR":
            counts["medium"] += 1
        elif severity == "INFO":
            counts["low"] += 1

    return counts

def get_sonarqube_details(report):
    """
    Convert raw SonarQube vulnerability issues into
    frontend-friendly security finding objects.
    """

    details = []

    for issue in report.get("issues", []) or []:

        issue_type = str(
            issue.get("type", "")
        ).upper()

        if issue_type != "VULNERABILITY":
            continue

        component = str(
            issue.get("component") or ""
        )

        # SonarQube component normally looks like:
        # projectKey:path/to/file.py
        if ":" in component:
            component = component.split(":", 1)[1]

        component = (
            component
            .replace("\\", "/")
            .lstrip("./")
        )

        details.append({
            "id": issue.get("key"),
            "scanner": "SonarQube",
            "severity": str(
                issue.get("severity") or "UNKNOWN"
            ).upper(),
            "rule": issue.get("rule"),
            "message": issue.get("message"),
            "file": component or None,
            "line": issue.get("line"),
            "type": issue.get("type"),
            "status": issue.get("status"),
        })

    return details

# =========================================================
# GEMINI AI REMEDIATION
# =========================================================

GEMINI_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string"},
                    "source": {"type": "string"},
                    "file": {"type": ["string", "null"]},
                    "line": {"type": ["integer", "null"]},
                    "issue": {"type": "string"},
                    "explanation": {"type": "string"},
                    "vulnerable_code": {"type": ["string", "null"]},
                    "secure_code": {"type": ["string", "null"]},
                    "why_fix_works": {"type": "string"},
                    "developer_action": {"type": "string"},
                },
                "required": [
                    "severity",
                    "source",
                    "file",
                    "line",
                    "issue",
                    "explanation",
                    "vulnerable_code",
                    "secure_code",
                    "why_fix_works",
                    "developer_action",
                ],
            },
        }
    },
    "required": ["findings"],
}


def extract_gemini_text(result):
    """Extract model text from an Interactions API response."""
    output_text = result.get("output_text")

    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    pieces = []

    for step in result.get("steps", []) or []:
        if step.get("type") != "model_output":
            continue

        for content in step.get("content", []) or []:
            if content.get("type") == "text":
                text = content.get("text", "")
                if text:
                    pieces.append(text)

    return "\n".join(pieces).strip()


def analyze_with_gemini(
    sonar_report,
    trivy_report,
    source_code
):
    """
    Generate structured remediation for scanner findings.

    Gemini provides remediation guidance only.
    SonarQube and Trivy remain the source of truth
    for the Security Gate.
    """

    api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key:
        return {
            "findings": [],
            "error": "GEMINI_API_KEY is not configured."
        }

    safe_sonar = redact_secrets(sonar_report)
    safe_trivy = redact_secrets(trivy_report)
    safe_source = redact_secrets(source_code)

    prompt = f"""
You are an expert DevSecOps security remediation assistant.

Analyze the REAL security findings reported by SonarQube and Trivy.

SONARQUBE FINDINGS:
{json.dumps(safe_sonar, indent=2)}

TRIVY FINDINGS:
{json.dumps(safe_trivy, indent=2)}

PROJECT SOURCE CODE:
{json.dumps(safe_source, indent=2)}

Your task is to create remediation guidance for EVERY
security finding reported by the scanners.

IMPORTANT RULES:

1. Do NOT ignore a scanner security finding.

2. Do NOT invent CVEs.

3. Do NOT invent files or line numbers.

4. If the exact source location is unknown, use null.

5. If source code is available, show the relevant vulnerable
   code and provide corrected secure code.

6. If the finding is a dependency vulnerability, explain the
   package/version upgrade required.

7. If the finding is a configuration vulnerability, explain
   the configuration change required.

8. NEVER reproduce API keys, passwords, tokens, or secrets.

9. For password storage, recommend Argon2id, bcrypt, or PBKDF2.

10. Gemini is providing remediation guidance only.
    It does NOT decide whether the pipeline passes or fails.

11. Every scanner security finding must result in a remediation
    object whenever possible.

12. Return ONLY valid JSON.

Use exactly this structure:

{{
    "findings": [
        {{
            "severity": "CRITICAL",
            "source": "SonarQube",
            "file": "example.py",
            "line": null,
            "issue": "Security vulnerability",
            "explanation": "Explain the vulnerability.",
            "vulnerable_code": null,
            "secure_code": null,
            "why_fix_works": "Explain why the remediation is safer.",
            "developer_action": "Specific action the developer should take."
        }}
    ]
}}

If there are three scanner security findings,
return three remediation objects.

Do not return an empty findings array when scanner
security findings are present.
"""

    payload = {
    "model": GEMINI_MODEL,
    "input": prompt,
    "response_format": {
        "type": "text",
        "mime_type": "application/json",
        "schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "severity": {
                                "type": "string"
                            },
                            "source": {
                                "type": "string"
                            },
                            "file": {
                                "type": [
                                    "string",
                                    "null"
                                ]
                            },
                            "line": {
                                "type": [
                                    "integer",
                                    "null"
                                ]
                            },
                            "issue": {
                                "type": "string"
                            },
                            "explanation": {
                                "type": "string"
                            },
                            "vulnerable_code": {
                                "type": [
                                    "string",
                                    "null"
                                ]
                            },
                            "secure_code": {
                                "type": [
                                    "string",
                                    "null"
                                ]
                            },
                            "why_fix_works": {
                                "type": "string"
                            },
                            "developer_action": {
                                "type": "string"
                            }
                        },
                        "required": [
                            "severity",
                            "source",
                            "file",
                            "line",
                            "issue",
                            "explanation",
                            "vulnerable_code",
                            "secure_code",
                            "why_fix_works",
                            "developer_action"
                        ]
                    }
                }
            },
            "required": [
                "findings"
            ]
        }
    }
}

    request = urllib.request.Request(
        GEMINI_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-goog-api-key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        method="POST"
    )

    try:

        print("")
        print("========================================")
        print("Starting Gemini AI remediation...")
        print("========================================")

        with urllib.request.urlopen(
            request,
            timeout=120
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

    except urllib.error.HTTPError as error:

        body = error.read().decode(
            "utf-8",
            errors="replace"
        )

        print(
            f"Gemini API error: HTTP {error.code}"
        )

        print(body[:3000])

        return {
            "findings": [],
            "error": (
                f"Gemini API returned HTTP {error.code}"
            )
        }

    except Exception as error:

        print(
            "Gemini connection error:",
            str(error)
        )

        return {
            "findings": [],
            "error": str(error)
        }

    # -----------------------------------------------------
    # Extract Gemini text response
    # -----------------------------------------------------

    response_text = ""

    for step in result.get(
        "steps",
        []
    ) or []:

        if step.get("type") != "model_output":
            continue

        for content in step.get(
            "content",
            []
        ) or []:

            if content.get("type") == "text":

                text = content.get(
                    "text",
                    ""
                )

                if text:
                    response_text += text

    # -----------------------------------------------------
    # Fallback for output-based responses
    # -----------------------------------------------------

    if not response_text:

        output = result.get(
            "output"
        )

        if isinstance(
            output,
            str
        ):

            response_text = output

        elif isinstance(
            output,
            list
        ):

            parts = []

            for item in output:

                if isinstance(
                    item,
                    str
                ):

                    parts.append(item)

                elif isinstance(
                    item,
                    dict
                ):

                    if item.get("type") == "text":

                        parts.append(
                            item.get(
                                "text",
                                ""
                            )
                        )

            response_text = "\n".join(
                parts
            )

    response_text = response_text.strip()

    print("")
    print("========== GEMINI RAW RESPONSE ==========")
    print(response_text[:10000])
    print("==========================================")

    if not response_text:

        print(
            "Gemini returned no text response."
        )

        return {
            "findings": [],
            "error": "Gemini returned no text response."
        }

    # -----------------------------------------------------
    # Remove accidental markdown fences
    # -----------------------------------------------------

    if response_text.startswith("```"):

        lines = response_text.splitlines()

        if lines:
            lines = lines[1:]

        if (
            lines
            and lines[-1].strip() == "```"
        ):

            lines = lines[:-1]

        response_text = "\n".join(
            lines
        ).strip()

    # -----------------------------------------------------
    # Parse JSON
    # -----------------------------------------------------

    try:

        report = json.loads(
            response_text
        )

    except json.JSONDecodeError:

        print(
            "Gemini returned invalid JSON."
        )

        return {
            "findings": [],
            "error": "Gemini returned invalid JSON.",
            "raw_report": response_text
        }

    # -----------------------------------------------------
    # Normalize response
    # -----------------------------------------------------

    if not isinstance(
        report,
        dict
    ):

        return {
            "findings": [],
            "error": (
                "Gemini returned an invalid JSON object."
            )
        }

    findings = report.get(
        "findings",
        []
    )

    if not isinstance(
        findings,
        list
    ):

        findings = []

    normalized_findings = []

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):
            continue

        normalized_findings.append({
            "severity": finding.get(
                "severity",
                "UNKNOWN"
            ),
            "source": finding.get(
                "source",
                "Gemini"
            ),
            "file": finding.get(
                "file"
            ),
            "line": finding.get(
                "line"
            ),
            "issue": finding.get(
                "issue",
                "Security finding"
            ),
            "explanation": finding.get(
                "explanation",
                ""
            ),
            "vulnerable_code": finding.get(
                "vulnerable_code"
            ),
            "secure_code": finding.get(
                "secure_code"
            ),
            "why_fix_works": finding.get(
                "why_fix_works",
                ""
            ),
            "developer_action": finding.get(
                "developer_action",
                ""
            )
        })

    report = {
        "findings": redact_secrets(
            normalized_findings
        )
    }

    print("")
    print(
        "Gemini remediation findings:",
        len(
            report["findings"]
        )
    )

    print("")
    print(
        "========== GEMINI STRUCTURED REPORT =========="
    )

    print(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False
        )
    )

    print(
        "=============================================="
    )

    return report

# =========================================================
# GEMINI AUTOMATIC CODE REMEDIATION
# =========================================================

def call_gemini_remediation(payload, api_key):
    """
    Send a remediation request to Gemini with bounded retry handling.

    429 responses are retried using Gemini's suggested retry delay when
    available. Temporary 408/5xx responses and socket timeouts are also
    retried. Secrets are never printed.
    """
    last_error = None

    for attempt in range(GEMINI_MAX_RETRIES + 1):
        request = urllib.request.Request(
            GEMINI_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "x-goog-api-key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=GEMINI_REQUEST_TIMEOUT,
            ) as response:
                return json.loads(
                    response.read().decode("utf-8")
                )

        except urllib.error.HTTPError as error:
            body = error.read().decode(
                "utf-8",
                errors="replace",
            )
            last_error = error

            retryable = error.code == 429 or 500 <= error.code < 600
            if not retryable or attempt >= GEMINI_MAX_RETRIES:
                if error.code == 429:
                    raise RuntimeError(
                        "Gemini API quota/rate limit reached. "
                        "Please wait and try remediation again. "
                        "The scanner results are still valid."
                    )
                raise RuntimeError(
                    f"Gemini API error: HTTP {error.code}: "
                    f"{body[:2000]}"
                )

            delay = 10.0

            # Gemini commonly returns: "retry in 7.4s".
            match = re.search(
                r"retry in\s+([0-9]+(?:\.[0-9]+)?)s",
                body,
                flags=re.IGNORECASE,
            )
            if match:
                delay = min(float(match.group(1)) + 1.0, 60.0)
            else:
                delay = min(
                    10.0 * (2 ** attempt),
                    60.0,
                )

            print(
                f"Gemini temporary HTTP {error.code}; "
                f"retrying in {delay:.1f}s "
                f"({attempt + 1}/{GEMINI_MAX_RETRIES})..."
            )
            time.sleep(delay)

        except (TimeoutError, urllib.error.URLError) as error:
            last_error = error

            if attempt >= GEMINI_MAX_RETRIES:
                raise RuntimeError(
                    "Gemini connection timed out or could not be reached "
                    "after multiple attempts. "
                    "Please try remediation again."
                )

            delay = min(
                5.0 * (2 ** attempt),
                30.0,
            )
            print(
                "Gemini connection problem; "
                f"retrying in {delay:.1f}s "
                f"({attempt + 1}/{GEMINI_MAX_RETRIES})..."
            )
            time.sleep(delay)

        except Exception as error:
            last_error = error
            raise RuntimeError(
                f"Gemini connection error: {error}"
            )

    raise RuntimeError(
        f"Gemini request failed: {last_error}"
    )


def select_remediation_source(sonar_report, trivy_report, source_code):
    """
    Send only files relevant to scanner findings to Gemini.

    This keeps remediation prompts much smaller and reduces latency/quota
    usage while preserving the exact source needed for safe replacements.
    """
    relevant = set()

    for issue in sonar_report.get("issues", []) or []:
        component = str(issue.get("component") or "")
        if ":" in component:
            component = component.split(":", 1)[1]
        component = component.replace("\\", "/").lstrip("./")
        if component:
            relevant.add(component)

    for result in trivy_report.get("Results", []) or []:
        target = str(result.get("Target") or "")
        target = target.replace("\\", "/").lstrip("./")
        if target:
            relevant.add(target)

        for vulnerability in result.get("Vulnerabilities", []) or []:
            target = str(vulnerability.get("PkgPath") or "")
            target = target.replace("\\", "/").lstrip("./")
            if target:
                relevant.add(target)

    selected = {}

    for path, content in source_code.items():
        normalized = path.replace("\\", "/").lstrip("./")

        if (
            normalized in relevant
            or normalized.lstrip("./") in relevant
            or any(
                normalized.endswith("/" + item)
                for item in relevant
            )
        ):
            selected[path] = content

    # If scanner paths cannot be mapped, fall back to the collected source
    # rather than sending Gemini an empty source set.
    return selected if selected else source_code


def build_current_remediation_findings(sonar_report, trivy_report):
    """Return detailed, current scanner findings for the AI retry loop."""
    findings = []

    for issue in (sonar_report.get("issues", []) or []):
        if str(issue.get("type", "")).upper() != "VULNERABILITY":
            continue

        component = str(issue.get("component") or "")
        if ":" in component:
            component = component.split(":", 1)[1]
        component = component.replace("\\", "/").lstrip("./")

        findings.append({
            "scanner": "SonarQube",
            "id": issue.get("key"),
            "rule": issue.get("rule"),
            "severity": str(issue.get("severity") or "UNKNOWN").upper(),
            "message": issue.get("message"),
            "file": component or None,
            "line": issue.get("line"),
            "status": issue.get("status"),
        })

    for result in (trivy_report.get("Results", []) or []):
        target = str(result.get("Target") or "").replace("\\", "/").lstrip("./")
        for vuln in (result.get("Vulnerabilities", []) or []):
            findings.append({
                "scanner": "Trivy",
                "id": vuln.get("VulnerabilityID"),
                "rule": vuln.get("PkgName"),
                "severity": str(vuln.get("Severity") or "UNKNOWN").upper(),
                "message": vuln.get("Title") or vuln.get("Description"),
                "file": vuln.get("PkgPath") or target or None,
                "line": None,
                "status": "UNRESOLVED",
            })

    return findings


def build_source_context(source_code, findings, radius=8):
    """Give Gemini focused source context around the latest findings."""
    context = {}
    for finding in findings:
        file_path = finding.get("file")
        if not file_path:
            continue
        normalized = str(file_path).replace("\\", "/").lstrip("./")
        matches = []
        for path, content in source_code.items():
            path_norm = str(path).replace("\\", "/").lstrip("./")
            if path_norm == normalized or path_norm.endswith("/" + normalized) or normalized.endswith("/" + path_norm):
                matches.append((path, content))

        if not matches:
            continue

        path, content = matches[0]
        line = finding.get("line")
        lines = content.splitlines()
        if isinstance(line, int) and line > 0 and line <= len(lines):
            start = max(1, line - radius)
            end = min(len(lines), line + radius)
            snippet = "\\n".join(
                f"{n}: {lines[n-1]}" for n in range(start, end + 1)
            )
        else:
            snippet = content[:12000]

        context[path] = snippet

    return context


def generate_remediation_patch(
    sonar_report,
    trivy_report,
    source_code,
    selected_finding=None,
):
    """
    Ask Gemini to generate machine-applicable file changes.

    Gemini suggests the exact replacement content, but the
    independent scanners remain the authority for verification.
    """

    api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured."
        )

    safe_sonar = redact_secrets(sonar_report)
    safe_trivy = redact_secrets(trivy_report)

    current_findings = build_current_remediation_findings(
        sonar_report,
        trivy_report,
    )

    # On retries, the remaining scanner findings are the ONLY authoritative
    # targets. Do not keep sending the original UI-selected finding.
    relevant_source = select_remediation_source(
        sonar_report,
        trivy_report,
        source_code,
    )
    focused_context = build_source_context(
        relevant_source,
        current_findings,
    )
    safe_source = redact_secrets(relevant_source)
    safe_context = redact_secrets(focused_context)

    print("Current scanner findings for Gemini:")
    for finding in current_findings:
        print(
            f"  [{finding.get('scanner')}] "
            f"{finding.get('severity')} "
            f"rule={finding.get('rule')} "
            f"file={finding.get('file')} "
            f"line={finding.get('line')} "
            f"message={finding.get('message')}"
        )

    prompt = f"""
    CURRENT REMAINING SCANNER FINDINGS (AUTHORITATIVE):
{json.dumps(redact_secrets(current_findings), indent=2)}

The UI-selected finding below is only historical context. NEVER prioritize it
over the current scanner findings above, especially on remediation retries.
UI-SELECTED CONTEXT:
{json.dumps(redact_secrets(selected_finding or {}), indent=2)}

IMPORTANT:
Remediate the CURRENT remaining findings above. On every retry, assume earlier
patches have already been applied to the source. Do not regenerate or repeat
an earlier patch unless the current scanner evidence still requires it.

1. Fix as many current scanner findings as can be safely and confidently fixed.
2. Do not introduce unrelated changes.
3. Only modify files that exist in the supplied source.
4. The file path must exactly match the supplied relative path.
5. old_code must exactly match the supplied source.
6. Never invent source code.
7. Keep every change as small and targeted as possible.
8. If a previous attempt already changed a line and the scanner still reports
   that same rule, create a materially different fix that addresses the rule's
   actual message; do not simply rewrite the same code.
9. If the remaining finding is on a different line/rule, target that exact line.

RULE-SPECIFIC REMEDIATION GUIDANCE:
- python:S4502 (CSRF): If the finding is caused by explicitly disabling CSRF
  (for example WTF_CSRF_ENABLED=False), remove the disabling configuration
  and restore the framework's default protection when possible. Do not merely
  rename the setting, move it, or add another bypass. If an API endpoint truly
  requires an exemption, do not claim it is fixed; mark it unfixable unless
  the supplied source contains a complete, safe CSRF design that can be
  implemented without breaking the application.
- python:S4507: remove production debug mode or make it configurable with a
  secure default of False.
- python:S8392: bind to 127.0.0.1 unless the supplied deployment architecture
  explicitly requires another interface; do not use 0.0.0.0 as a workaround.
- docker:S6470: avoid broad recursive COPY instructions that can include
  secrets. Prefer a narrowly scoped COPY of required application files. If a
  .dockerignore file is required but cannot be safely created from the supplied
  source, mark the finding unfixable rather than pretending it is fixed.
- docker:S6471: create/use a non-root application user and switch to USER.
- python:S2245: replace security-sensitive pseudorandom generation with
  secrets.SystemRandom or secrets module APIs where appropriate.

You are an expert secure-code remediation engineer.

You must remediate REAL vulnerabilities detected by
SonarQube and Trivy.

SONARQUBE FINDINGS:
{json.dumps(safe_sonar, indent=2)}

TRIVY FINDINGS:
{json.dumps(safe_trivy, indent=2)}

SOURCE CODE:
{json.dumps(safe_source, indent=2)}

FOCUSED SOURCE CONTEXT AROUND CURRENT FINDINGS:
{json.dumps(safe_context, indent=2)}

TASK:

For each vulnerability that can be safely fixed in source code,
produce an exact file modification.

Return ONLY valid JSON.

Use exactly this structure:

{{
  "changes": [
    {{
      "file": "relative/path/to/file.py",
      "operation": "replace",
      "old_code": "EXACT vulnerable code from the supplied source",
      "new_code": "EXACT corrected secure code",
      "reason": "Why this change fixes the scanner finding"
    }}
  ],
  "unfixable": [
    {{
      "file": "relative/path",
      "issue": "Issue that cannot safely be fixed automatically",
      "reason": "Why human intervention is required"
    }}
  ]
}}

STRICT RULES:

1. Only modify files that exist in the supplied source code.

2. The "file" value must exactly match a supplied relative file path.

3. "old_code" must be copied EXACTLY from the supplied source.

4. Never invent source code that was not supplied.

5. Never modify unrelated code.

6. Keep the change as small as possible.

7. Do not reproduce secrets, API keys, passwords or tokens.

8. Never replace a secret with another hardcoded secret.

9. For hardcoded secrets, use environment variables or an
   appropriate secret-management mechanism.

10. For dependency vulnerabilities, update the dependency version
    only when the required version is supported by the evidence.

11. Do not invent CVEs or vulnerability identifiers.

12. If you cannot confidently create a safe automatic fix,
    put the finding in "unfixable" instead.

13. Do not claim that a vulnerability is fixed merely because
    you generated a change.

14. The changes will be independently verified by SonarQube
    and Trivy after they are applied.

15. For every applied change, the backend will preserve old_code, new_code,
    and reason for the developer-facing remediation report. Make reason
    specific to the exact scanner rule and source change.

16. Return JSON only. No markdown. No explanations outside JSON.
"""

    payload = {
        "model": GEMINI_MODEL,
        "input": prompt,
        "response_format": {
            "type": "text",
            "mime_type": "application/json",
        },
    }

    result = call_gemini_remediation(
        payload,
        api_key,
    )

    response_text = extract_gemini_text(result)

    if not response_text:
        raise RuntimeError(
            "Gemini returned no remediation response."
        )

    if response_text.startswith("```"):
        lines = response_text.splitlines()

        if lines and lines[0].startswith("```"):
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        response_text = "\n".join(lines).strip()

        response_text = "\n".join(lines).strip()

    # -------------------------------------------------
    # PARSE GEMINI JSON
    # -------------------------------------------------

    try:
        patch = json.loads(response_text)

    except json.JSONDecodeError as first_error:

        print(
            "Gemini response was not a single JSON object."
        )

        print(
            "Attempting to extract a valid JSON object..."
        )

        decoder = json.JSONDecoder()
        patch = None

        for position, character in enumerate(
            response_text
        ):

            if character != "{":
                continue

            try:
                candidate, end_position = (
                    decoder.raw_decode(
                        response_text[position:]
                    )
                )

                if isinstance(candidate, dict):
                    patch = candidate

                    print(
                        "Valid Gemini JSON object extracted."
                    )

                    break

            except json.JSONDecodeError:
                continue

        if patch is None:

            print(
                "Gemini raw remediation response:"
            )

            print(response_text)

            raise RuntimeError(
                "Gemini returned invalid remediation JSON: "
                + str(first_error)
            )

    # -------------------------------------------------
    # VALIDATE GEMINI REMEDIATION
    # -------------------------------------------------

    if not isinstance(patch, dict):
        raise RuntimeError(
            "Gemini remediation response is not an object."
        )

    changes = patch.get(
        "changes",
        [],
    )

    if not isinstance(changes, list):
        raise RuntimeError(
            "Gemini remediation 'changes' is not a list."
        )

    unfixable = patch.get(
        "unfixable",
        [],
    )

    if not isinstance(unfixable, list):
        unfixable = []

    print(
        "Gemini remediation changes:",
        len(changes),
    )

    return {
        "changes": changes,
        "unfixable": unfixable,
    }

def apply_remediation_changes(
    project_directory,
    remediation,
):
    """
    Apply Gemini-generated exact replacements.

    A change is applied only when old_code exists exactly once
    in the target file. This prevents accidental broad replacements.
    """

    if not isinstance(remediation, dict):
        return {
            "applied": [],
            "rejected": [{
                "reason": "Gemini returned no usable remediation object."
            }],
            "unfixable": [],
        }

    applied = []
    rejected = []

    for change in remediation.get(
        "changes",
        [],
    ):
        if not isinstance(change, dict):
            rejected.append({
                "reason": "Invalid change object."
            })
            continue

        relative_file = change.get("file")
        operation = change.get("operation")
        old_code = change.get("old_code")
        new_code = change.get("new_code")

        if not all([
            isinstance(relative_file, str),
            isinstance(old_code, str),
            isinstance(new_code, str),
        ]):
            rejected.append({
                "file": relative_file,
                "reason": "Missing or invalid change fields.",
            })
            continue

        if operation != "replace":
            rejected.append({
                "file": relative_file,
                "reason": "Unsupported operation.",
            })
            continue

        target = os.path.abspath(
            os.path.join(
                project_directory,
                relative_file,
            )
        )

        project_root = os.path.abspath(
            project_directory
        )

        if not target.startswith(
            project_root + os.sep
        ):
            rejected.append({
                "file": relative_file,
                "reason": "Unsafe file path.",
            })
            continue

        if not os.path.isfile(target):
            rejected.append({
                "file": relative_file,
                "reason": "File does not exist.",
            })
            continue

        try:
            with open(
                target,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as file:
                original = file.read()

            occurrences = original.count(
                old_code
            )

            if occurrences != 1:
                rejected.append({
                    "file": relative_file,
                    "reason": (
                        "old_code must occur exactly once; "
                        f"found {occurrences} occurrences."
                    ),
                })
                continue

            updated = original.replace(
                old_code,
                new_code,
                1,
            )

            # Reject AI patches that would leave a Python file
            # uncompilable, before anything is written to disk.
            if target.endswith(".py"):
                try:
                    compile(updated, target, "exec")
                except SyntaxError as syntax_error:
                    rejected.append({
                        "file": relative_file,
                        "reason": (
                            "Patch rejected: it would introduce a "
                            f"syntax error ({syntax_error.msg}, "
                            f"line {syntax_error.lineno})."
                        ),
                    })
                    continue

            with open(
                target,
                "w",
                encoding="utf-8",
            ) as file:
                file.write(updated)

            reason = change.get(
                "reason",
                "Gemini-generated security remediation applied."
            )

            applied.append({
                "file": relative_file,
                "operation": operation,
                "old_code": old_code,
                "new_code": new_code,
                "vulnerable_code": old_code,
                "secure_code": new_code,
                "reason": reason,
                "why_fix_works": reason,
                "developer_action": "Review the generated secure change and rerun the security gate.",
                "status": "applied",
            })

        except Exception as error:
            rejected.append({
                "file": relative_file,
                "reason": str(error),
            })

    return {
        "applied": applied,
        "rejected": rejected,
        "unfixable": remediation.get(
            "unfixable",
            [],
        ),
    }
    
def combine_findings(trivy_findings, sonar_findings):
    return {
        "critical": (
            trivy_findings["critical"]
            + sonar_findings["critical"]
            + sonar_findings["blocker"]
        ),
        "high": (
            trivy_findings["high"]
            + sonar_findings["high"]
        ),
        "medium": (
            trivy_findings["medium"]
            + sonar_findings["medium"]
        ),
        "low": (
            trivy_findings["low"]
            + sonar_findings["low"]
        ),
        "secrets": trivy_findings["secrets"],
    }


def is_security_blocked(findings):
    """
    Current project policy:
    any scanner security finding blocks the pipeline/application.
    """
    return any(
        findings.get(key, 0) > 0
        for key in (
            "critical",
            "high",
            "medium",
            "low",
            "secrets",
        )
    )


# =========================================================
# ROUTES
# =========================================================

@app.route("/")
def dashboard():
    findings = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "secrets": 0,
    }

    return render_template(
        "index.html",
        findings=findings,
        blocked=False,
    )


@app.route(
    "/api/analyze/github",
    methods=["POST"],
)
def analyze_github():
    data = request.get_json(
        silent=True
    ) or {}

    url = str(
        data.get("url", "")
    ).strip()

    if not url:
        return jsonify({
            "success": False,
            "error": "GitHub URL is required.",
        }), 400

    return analyze_project(
        source_type="github",
        source=url,
    )
# =========================================================
# AUTOMATIC GITHUB REMEDIATION
# =========================================================

@app.route("/api/remediate/github", methods=["POST"])
def remediate_github():
    """
    Clone a GitHub repository, scan it with SonarQube and Trivy,
    optionally apply a Gemini-generated remediation, independently
    verify the modified workspace, and keep the workspace available
    for the final GitHub push.

    No GitHub token is requested during analysis/remediation.
    """

    workspace = None

    try:
        data = request.get_json(silent=True) or {}

        repository_url = str(data.get("url") or "").strip()
        selected_finding = data.get("finding") or {}

        if not repository_url:
            return jsonify({
                "success": False,
                "error": "GitHub repository URL is required.",
            }), 400

        # -------------------------------------------------
        # Create isolated workspace
        # -------------------------------------------------
        workspace = tempfile.mkdtemp(
            prefix="security-remediation-"
        )

        # -------------------------------------------------
        # Clone repository
        # -------------------------------------------------
        clone_github_repository(
            repository_url,
            workspace,
        )

        # -------------------------------------------------
        # Initial SonarQube scan
        # -------------------------------------------------
        sonar_report = run_sonarqube(workspace)
        sonar_findings = summarize_sonarqube(sonar_report)

        # -------------------------------------------------
        # Initial Trivy scan
        # -------------------------------------------------
        trivy_report = run_trivy(workspace)
        trivy_findings = summarize_trivy(trivy_report)

        # -------------------------------------------------
        # Combine findings
        # -------------------------------------------------
        findings = combine_findings(
            trivy_findings,
            sonar_findings,
        )

        ai_report = {
            "findings": [],
            "changes_applied": [],
            "rejected_changes": [],
            "unfixable": [],
            "remediation_attempts": 0,
            "history": [],
        }

        # -------------------------------------------------
        # CASE 1: Repository already passes the Security Gate
        # -------------------------------------------------
        if not is_security_blocked(findings):
            verified = True
            blocked = False

            print("")
            print("=" * 60)
            print("INITIAL SECURITY GATE PASSED")
            print("No scanner security findings require remediation.")
            print("=" * 60)

        # -------------------------------------------------
        # CASE 2: Repository is blocked and needs remediation
        # -------------------------------------------------
        else:
            verified = False

            for attempt in range(
                1,
                MAX_REMEDIATION_ATTEMPTS + 1,
            ):
                print("")
                print("=" * 60)
                print(
                    f"REMEDIATION ATTEMPT "
                    f"{attempt}/{MAX_REMEDIATION_ATTEMPTS}"
                )
                print("=" * 60)

                if not is_security_blocked(findings):
                    verified = True
                    break

                # -------------------------------------------------
                # Collect current source code
                # -------------------------------------------------
                source_code = collect_source_code(workspace)

                # -------------------------------------------------
                # Ask Gemini for exact changes
                # -------------------------------------------------
                remediation = generate_remediation_patch(
                    sonar_report,
                    trivy_report,
                    source_code,
                    selected_finding=selected_finding,
                )

                if not isinstance(remediation, dict):
                    raise RuntimeError(
                        "Gemini remediation returned no usable changes."
                    )

                remediation.setdefault("changes", [])
                remediation.setdefault("unfixable", [])

                # -------------------------------------------------
                # Apply Gemini changes safely
                # -------------------------------------------------
                application_result = apply_remediation_changes(
                    workspace,
                    remediation,
                )

                applied = application_result.get("applied", [])
                rejected = application_result.get("rejected", [])
                unfixable = application_result.get("unfixable", [])

                # -------------------------------------------------
                # Update AI report
                # -------------------------------------------------
                ai_report["remediation_attempts"] = attempt

                ai_report["findings"].extend(
                    remediation.get("changes", [])
                )

                ai_report["changes_applied"].extend(applied)
                ai_report["rejected_changes"].extend(rejected)
                ai_report["unfixable"].extend(unfixable)

                ai_report["history"].append({
                    "attempt": attempt,
                    "generated_changes": len(
                        remediation.get("changes", [])
                    ),
                    "applied_changes": len(applied),
                    "rejected_changes": len(rejected),
                    "unfixable": len(unfixable),
                })

                # -------------------------------------------------
                # Stop if Gemini could not safely modify anything
                # -------------------------------------------------
                if not applied:
                    print(
                        "No safe remediation changes were applied."
                    )
                    verified = False
                    break

                print("")
                print("AI remediation changes applied.")
                print("Running independent verification...")

                # -------------------------------------------------
                # INDEPENDENT SONARQUBE VERIFICATION
                # -------------------------------------------------
                verification_sonar_report = run_sonarqube(workspace)
                verification_sonar_findings = summarize_sonarqube(
                    verification_sonar_report
                )

                # -------------------------------------------------
                # INDEPENDENT TRIVY VERIFICATION
                # -------------------------------------------------
                verification_trivy_report = run_trivy(workspace)
                verification_trivy_findings = summarize_trivy(
                    verification_trivy_report
                )

                # -------------------------------------------------
                # FINAL SECURITY GATE AFTER REMEDIATION
                # -------------------------------------------------
                verification_findings = combine_findings(
                    verification_trivy_findings,
                    verification_sonar_findings,
                )

                verified = not is_security_blocked(
                    verification_findings
                )

                verification_details = get_sonarqube_details(
                    verification_sonar_report
                )

                print("Verification SonarQube:", verification_sonar_findings)
                print("Remaining SonarQube vulnerabilities:")
                for finding in verification_details:
                    print(
                        f"  - severity={finding.get('severity')} "
                        f"rule={finding.get('rule')} "
                        f"file={finding.get('file')} "
                        f"line={finding.get('line')} "
                        f"message={finding.get('message')}"
                    )
                print(
                    "Verification Trivy:",
                    verification_trivy_findings,
                )
                print(
                    "Verification Security Gate:",
                    "PASSED" if verified else "BLOCKED",
                )

                # The latest scanner state is now authoritative.
                findings = verification_findings
                sonar_findings = verification_sonar_findings
                trivy_findings = verification_trivy_findings
                sonar_report = verification_sonar_report
                trivy_report = verification_trivy_report

                ai_report["verification"] = {
                    "verified": verified,
                    "sonarqube": verification_sonar_findings,
                    "sonarqube_details": verification_details,
                    "trivy": verification_trivy_findings,
                    "findings": verification_findings,
                }

                if verified:
                    print("Security Gate PASSED after remediation.")
                    break

                if attempt < MAX_REMEDIATION_ATTEMPTS:
                    print(
                        "Security Gate still BLOCKED. "
                        "Continuing with another AI remediation attempt..."
                    )
                    # Continue with the latest scanner reports and modified
                    # source workspace. Gemini will receive the remaining
                    # findings on the next iteration.
                    continue

                print("Maximum remediation attempts reached.")
                break

            blocked = is_security_blocked(findings)

        # -------------------------------------------------
        # Final security status
        # -------------------------------------------------
        blocked = is_security_blocked(findings)

        # The final scanner state is the source of truth.
        verified = not blocked

        print("")
        print(
            "Final remediation status:",
            "PASSED" if verified else "BLOCKED",
        )

        # Keep complete remediation details available to the frontend.
        ai_report["changes_applied"] = [
            change for change in ai_report.get("changes_applied", [])
            if isinstance(change, dict)
        ]

        # -------------------------------------------------
        # Save workspace for GitHub update
        # -------------------------------------------------
        workspace_id = secrets.token_urlsafe(32)

        REMEDIATION_WORKSPACES[workspace_id] = {
            "workspace": workspace,
            "repository": repository_url,
            "created_at": time.time(),
            "verified": verified,
            "selected_finding": selected_finding,
            "initial_findings": findings,
            "verification": ai_report.get("verification"),
        }

        session["remediation_workspace_id"] = workspace_id

        # -------------------------------------------------
        # Return result
        # -------------------------------------------------
        return jsonify({
            "success": True,
            "source": "github",
            "findings": findings,
            "blocked": blocked,
            "verified": verified,
            "repository": repository_url,
            "workspace_id": workspace_id,
            "ai_report": ai_report,
            "sonarqube": sonar_findings,
            "trivy": trivy_findings,
            "remediation_ready": verified,
        })

    except Exception as error:
        error_text = str(error)

        print(
            "Automatic remediation error:",
            error_text,
        )

        # Do not leave failed temporary workspaces behind.
        if workspace:
            shutil.rmtree(
                workspace,
                ignore_errors=True,
            )

        status_code = (
            429
            if "quota/rate limit" in error_text.lower()
            else 500
        )

        return jsonify({
            "success": False,
            "error": error_text,
            "retryable": status_code == 429,
        }), status_code

# =========================================================
# VERIFY APPROVED REMEDIATION
# =========================================================

@app.route(
    "/api/verify/remediation",
    methods=["POST"],
)
def verify_remediation():
    """
    Independently verify the AI-remediated workspace.

    Gemini is NOT trusted as the verification authority.
    SonarQube and Trivy independently scan the modified workspace.
    The workspace becomes pushable only when the complete Security
    Gate passes.
    """

    try:
        data = request.get_json(silent=True) or {}

        workspace_id = (
            str(data.get("workspace_id") or "").strip()
            or str(session.get("remediation_workspace_id") or "").strip()
        )

        if not workspace_id:
            return jsonify({
                "success": False,
                "verified": False,
                "error": (
                    "Remediation workspace is missing. "
                    "Please generate remediation again."
                ),
            }), 400

        workspace_info = REMEDIATION_WORKSPACES.get(workspace_id)

        if not workspace_info:
            return jsonify({
                "success": False,
                "verified": False,
                "error": (
                    "Remediation workspace was not found "
                    "or has expired."
                ),
            }), 404

        # -------------------------------------------------
        # WORKSPACE EXPIRATION
        # -------------------------------------------------
        if (
            time.time()
            - workspace_info.get("created_at", 0)
            > REMEDIATION_WORKSPACE_TTL
        ):
            REMEDIATION_WORKSPACES.pop(
                workspace_id,
                None,
            )

            if session.get("remediation_workspace_id") == workspace_id:
                session.pop(
                    "remediation_workspace_id",
                    None,
                )

            return jsonify({
                "success": False,
                "verified": False,
                "error": (
                    "Remediation workspace has expired. "
                    "Please run AI remediation again."
                ),
            }), 404

        project_directory = workspace_info.get("workspace")

        if not project_directory:
            return jsonify({
                "success": False,
                "verified": False,
                "error": "Remediation workspace path is missing.",
            }), 500

        if not os.path.isdir(project_directory):
            return jsonify({
                "success": False,
                "verified": False,
                "error": (
                    "Remediation workspace is no longer available."
                ),
            }), 404

        print("")
        print("=" * 60)
        print("INDEPENDENT SECURITY VERIFICATION")
        print("=" * 60)

        # -------------------------------------------------
        # SONARQUBE VERIFICATION
        # -------------------------------------------------
        print("")
        print("Running SonarQube verification...")

        sonar_report = run_sonarqube(project_directory)

        sonar_findings = get_sonarqube_details(
            sonar_report
        )

        sonar_summary = summarize_sonarqube(
            sonar_report
        )

        sonar_vulnerabilities = len(
            sonar_findings
        )

        print(
            "SonarQube verification vulnerabilities:",
            sonar_vulnerabilities,
        )

        # -------------------------------------------------
        # TRIVY VERIFICATION
        # -------------------------------------------------
        print("")
        print("Running Trivy verification...")

        trivy_report = run_trivy(project_directory)

        trivy_summary = summarize_trivy(
            trivy_report
        )

        trivy_vulnerabilities = 0
        trivy_secrets = 0

        for result in (
            trivy_report.get("Results", []) or []
        ):
            trivy_vulnerabilities += len(
                result.get("Vulnerabilities", []) or []
            )

            trivy_secrets += len(
                result.get("Secrets", []) or []
            )

        print(
            "Trivy vulnerabilities:",
            trivy_vulnerabilities,
        )

        print(
            "Trivy secrets:",
            trivy_secrets,
        )

        # -------------------------------------------------
        # COMPLETE SECURITY GATE
        # -------------------------------------------------
        verification_findings = combine_findings(
            trivy_summary,
            summarize_sonarqube(sonar_report),
        )

        verified = not is_security_blocked(
            verification_findings
        )

        # -------------------------------------------------
        # STORE VERIFICATION RESULT
        # -------------------------------------------------
        workspace_info["verified"] = verified

        workspace_info["verification"] = {
            "verified": verified,
            "sonarqube": {
                "passed": sonar_vulnerabilities == 0,
                "vulnerabilities": sonar_vulnerabilities,
                "summary": sonar_summary,
                "findings": sonar_findings,
            },
            "trivy": {
                "passed": (
                    trivy_vulnerabilities == 0
                    and trivy_secrets == 0
                ),
                "vulnerabilities": trivy_vulnerabilities,
                "secrets": trivy_secrets,
                "summary": trivy_summary,
            },
            "security_gate": {
                "passed": verified,
                "findings": verification_findings,
            },
            "verified_at": time.time(),
        }

        # -------------------------------------------------
        # ALLOW PUSH ONLY AFTER SUCCESS
        # -------------------------------------------------
        if verified:
            session["remediation_workspace_id"] = workspace_id

            print("")
            print("SECURITY VERIFICATION PASSED")
            print("Remediation is safe to push.")
        else:
            print("")
            print("SECURITY VERIFICATION FAILED")
            print("Remediation cannot be pushed.")

        print("=" * 60)

        return jsonify({
            "success": True,
            "verified": verified,
            "blocked": not verified,
            "workspace_id": workspace_id,
            "repository": workspace_info.get(
                "repository"
            ),
            "sonarqube": {
                "passed": sonar_vulnerabilities == 0,
                "vulnerabilities": sonar_vulnerabilities,
                "summary": sonar_summary,
                "findings": sonar_findings,
            },
            "trivy": {
                "passed": (
                    trivy_vulnerabilities == 0
                    and trivy_secrets == 0
                ),
                "vulnerabilities": trivy_vulnerabilities,
                "secrets": trivy_secrets,
                "summary": trivy_summary,
            },
            "security_gate": {
                "passed": verified,
                "findings": verification_findings,
            },
        })

    except Exception as error:
        print(
            "Independent verification error:",
            str(error),
        )

        return jsonify({
            "success": False,
            "verified": False,
            "error": str(error),
        }), 500

# =========================================================
# PUSH VERIFIED REMEDIATION TO GITHUB
# =========================================================

@app.route(
    "/api/github/push-fix",
    methods=["POST"],
)
def push_github_fix():
    """
    Push an already verified remediation workspace to a new GitHub branch.

    The GitHub token is supplied by the user only at this stage.
    It is not stored in the project .env file and is not retained
    after the request.
    """

    workspace_id = None
    token = None
    push_succeeded = False

    try:
        data = request.get_json(silent=True) or {}

        workspace_id = str(
            data.get("workspace_id") or ""
        ).strip()

        token = str(
            data.get("github_token") or ""
        ).strip()

        # Recover the workspace from the browser session if the
        # frontend does not send its workspace_id.
        if not workspace_id:
            workspace_id = str(
                session.get("remediation_workspace_id") or ""
            ).strip()

        if not workspace_id:
            return jsonify({
                "success": False,
                "error": (
                    "Remediation workspace is missing. "
                    "Run AI remediation again before pushing."
                ),
            }), 400

        if not token:
            return jsonify({
                "success": False,
                "error": "GitHub Personal Access Token is required.",
            }), 400

        workspace_info = REMEDIATION_WORKSPACES.get(
            workspace_id
        )

        if not workspace_info:
            return jsonify({
                "success": False,
                "error": (
                    "Remediation workspace was not found "
                    "or has expired."
                ),
            }), 404

        # -------------------------------------------------
        # WORKSPACE EXPIRATION
        # -------------------------------------------------
        if (
            time.time()
            - workspace_info.get("created_at", 0)
            > REMEDIATION_WORKSPACE_TTL
        ):
            REMEDIATION_WORKSPACES.pop(
                workspace_id,
                None,
            )

            if session.get("remediation_workspace_id") == workspace_id:
                session.pop(
                    "remediation_workspace_id",
                    None,
                )

            return jsonify({
                "success": False,
                "error": (
                    "Remediation workspace has expired. "
                    "Run AI remediation again."
                ),
            }), 404

        # -------------------------------------------------
        # SECURITY GATE CHECK
        # -------------------------------------------------
        if not workspace_info.get("verified"):
            return jsonify({
                "success": False,
                "error": (
                    "The remediation has not passed "
                    "security verification."
                ),
            }), 403

        project_directory = workspace_info.get(
            "workspace"
        )

        repository_url = workspace_info.get(
            "repository"
        )

        if not project_directory or not repository_url:
            return jsonify({
                "success": False,
                "error": "Verified remediation workspace data is incomplete.",
            }), 500

        if not os.path.isdir(project_directory):
            return jsonify({
                "success": False,
                "error": (
                    "Verified remediation workspace "
                    "is no longer available."
                ),
            }), 404

        print("")
        print("=" * 60)
        print("PUSHING VERIFIED REMEDIATION TO GITHUB")
        print("=" * 60)

        result = create_github_remediation_branch(
            project_directory,
            repository_url,
            token,
        )

        push_succeeded = True

        # Only remove the workspace after a successful push.
        REMEDIATION_WORKSPACES.pop(
            workspace_id,
            None,
        )

        if session.get("remediation_workspace_id") == workspace_id:
            session.pop(
                "remediation_workspace_id",
                None,
            )

        print("GitHub remediation branch:", result["branch"])
        print("=" * 60)

        return jsonify({
            "success": True,
            "branch": result["branch"],
            "repository": result["repository"],
            "message": (
                "Verified remediation was pushed "
                "to GitHub successfully."
            ),
        })

    except Exception as error:
        print(
            "GitHub push error:",
            str(error),
        )

        return jsonify({
            "success": False,
            "error": str(error),
        }), 500

    finally:
        # Never keep the token in application state.
        token = None

        # A failed GitHub push deliberately keeps the verified workspace
        # so the user can correct the token and retry.
        if push_succeeded and workspace_id:
            workspace_info = REMEDIATION_WORKSPACES.pop(
                workspace_id,
                None,
            )

            if workspace_info:
                shutil.rmtree(
                    workspace_info.get("workspace", ""),
                    ignore_errors=True,
                )

@app.route(
    "/api/analyze/upload",
    methods=["POST"],
)
def analyze_upload():
    uploaded_file = request.files.get("project")

    if not uploaded_file:
        return jsonify({
            "success": False,
            "error": "Please upload a ZIP file.",
        }), 400

    filename = uploaded_file.filename or ""

    if not filename.lower().endswith(".zip"):
        return jsonify({
            "success": False,
            "error": "Only ZIP files are supported.",
        }), 400

    temporary_zip = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".zip",
    )
    temporary_zip.close()

    uploaded_file.save(
        temporary_zip.name
    )

    try:
        return analyze_project(
            source_type="zip",
            source=temporary_zip.name,
        )
    finally:
        try:
            os.unlink(temporary_zip.name)
        except OSError:
            pass


# =========================================================
# MAIN ANALYSIS
# =========================================================

def analyze_project(source_type, source):
    workspace = tempfile.mkdtemp(
        prefix="security-analysis-"
    )

    try:
        project_directory = os.path.join(
            workspace,
            "project",
        )

        os.makedirs(project_directory)

        # -------------------------------------------------
        # PREPARE PROJECT
        # -------------------------------------------------

        if source_type == "github":
            print("Cloning GitHub repository...")
            clone_github_repository(
                source,
                project_directory,
            )
        else:
            print("Extracting uploaded ZIP...")
            safe_extract_zip(
                source,
                project_directory,
            )

        print(
            "Project prepared:",
            project_directory,
        )

        # -------------------------------------------------
        # SONARQUBE
        # -------------------------------------------------

        sonar_report = run_sonarqube(
            project_directory
        )

        sonar_findings = summarize_sonarqube(
            sonar_report
        )

        sonar_details = get_sonarqube_details(
            sonar_report
        )

        print(
            "SonarQube detailed findings:",
            len(sonar_details),
        )

        # -------------------------------------------------
        # TRIVY
        # -------------------------------------------------

        trivy_report = run_trivy(
            project_directory
        )

        trivy_findings = summarize_trivy(
            trivy_report
        )

        print(
            "Trivy findings:",
            trivy_findings,
        )

        # -------------------------------------------------
        # COMBINED FINDINGS
        # -------------------------------------------------

        findings = combine_findings(
            trivy_findings,
            sonar_findings,
        )

        print(
            "Combined findings:",
            findings,
        )

               # -------------------------------------------------
        # INITIAL ANALYSIS ONLY
        # -------------------------------------------------
        # Do not call Gemini during the normal analysis request.
        # Gemini is invoked only by /api/remediate/github after the
        # user explicitly starts remediation. This prevents duplicate
        # Gemini calls and avoids exhausting the free-tier request quota.
        ai_report = {
            "findings": [],
            "changes_applied": [],
            "rejected_changes": [],
            "unfixable": [],
            "remediation_attempts": 0,
            "history": [],
        }

        print("")
        print("Analysis complete.")
        print("Gemini automatic remediation is waiting for user action.")

        # -------------------------------------------------
        # FINAL SECURITY GATE
        # -------------------------------------------------

        blocked = is_security_blocked(
            findings
        )

        print("")
        print(
            "Final Security Gate:",
            "BLOCKED" if blocked else "PASSED",
        )

        # -------------------------------------------------
        # RETURN
        # -------------------------------------------------
       
        return jsonify({
    "success": True,
    "source": source_type,
    "repository": source if source_type == "github" else None,
    "findings": findings,
    "blocked": blocked,
    "ai_report": ai_report,

    "sonarqube": sonar_findings,
    "sonarqube_details": sonar_details,

    "trivy": trivy_findings,
})

    except Exception as error:
        print(
            "Analysis error:",
            str(error),
        )

        return jsonify({
            "success": False,
            "error": str(error),
        }), 500

    finally:
        shutil.rmtree(
            workspace,
            ignore_errors=True,
        )


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":
    # The Werkzeug debugger allows code execution from the browser,
    # so debug mode is opt-in only.
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in (
        "1", "true", "yes",
    )

    if debug_mode:
        print("WARNING: FLASK_DEBUG is enabled. Local development only.")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=debug_mode,
    )
