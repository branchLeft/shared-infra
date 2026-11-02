#!/usr/bin/python
"""Write the two environment files of the mx1 stack, on the host, without a value leaving it.

``mint`` creates Stalwart's ``.env`` once, with a Prometheus secret made here, and never
replaces a file that is there. ``shim`` renders the mailgun-shim's environment file from the
drain token the credentials file already holds, and never makes that token. ``check_token``
says whether the credentials file holds the drain token, so the role can refuse before it
writes anything.

Every secret is read and written on the host. The module returns key names, booleans and the
SHA-256 of a file, never a value, and in check mode it writes nothing.

The shim's file is rendered exactly as ``mail/provision/render_shim_env.py`` renders it, so
the repository's hand route and this module agree; ``ansible/checks/test_mx1_stack_agree.py``
holds them together.
"""

import hashlib
import os
import re
import secrets
import tempfile

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: mx1_stack_envfile
short_description: Write the mx1 stack's environment files on the host
description:
  - C(mint) creates a file holding one secret, only when the file is absent. An existing file
    is valid if it has exactly one non-empty line for the key, whatever its length or characters,
    because the owner may have pasted it by hand.
  - C(shim) renders the mailgun-shim's environment file from the drain token in the credentials
    file, replacing it atomically at mode 0600 only when the content differs. It never makes
    the token.
  - C(check_token) reads the credentials file and reports whether it holds the token.
  - C(reserved_keys) names the keys of a file that start with a prefix (Compose reads C(COMPOSE_*)
    from a C(.env) file), and never a value.
  - Never returns a secret. Results carry key names, booleans and a SHA-256.
version_added: "1.0.0"
author:
  - branchLeft
options:
  action:
    description: What to do.
    type: str
    required: true
    choices: [mint, shim, check_token, reserved_keys]
  path:
    description: The environment file to write (C(mint), C(shim)) or to read (C(reserved_keys)).
    type: path
  prefix:
    description: The key prefix C(reserved_keys) looks for.
    type: str
    default: COMPOSE_
  key:
    description: The variable the C(mint) file holds.
    type: str
    default: STALWART_PROMETHEUS_SECRET
  credentials_path:
    description: The flat C(label:secret) file that holds the drain token (C(shim), C(check_token)).
    type: path
  label:
    description: The label of the drain token in the credentials file.
    type: str
    default: shim-drain-token
attributes:
  check_mode:
    support: full
    description: Reports the change it would make and writes nothing.
  diff_mode:
    support: none
    description: The files hold secrets, so no diff is shown.
"""

EXAMPLES = r"""
- name: Make Stalwart's environment file, once
  mx1_stack_envfile:
    action: mint
    path: /opt/stalwart/.env
"""

RETURN = r"""
created:
  description: Whether C(mint) made the file.
  returned: when action is mint
  type: bool
valid:
  description: Whether the file holds exactly one non-empty line for the key.
  returned: when action is mint
  type: bool
found:
  description: Whether the credentials file holds the token.
  returned: when action is check_token
  type: bool
found_keys:
  description: The keys that start with the prefix, sorted. Never a value.
  returned: when action is reserved_keys
  type: list
  elements: str
sha256:
  description: The SHA-256 of the environment file as it is, or as it would be.
  returned: when action is mint or shim
  type: str
"""

# The shim's fixed configuration, the same values as render_shim_env.py. PORT matches the
# container side of shim-compose.yml's mapping and its healthcheck.
SHIM_PORT = "8080"
SHIM_DB_PATH = "/data/shim.db"
SHIM_THROTTLE_PATH = "/data/throttle.json"
SHIM_TOKEN_KEY = "SHIM_DRAIN_TOKEN"  # noqa: S105
SECRET_LENGTH = 48
ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
FILE_MODE = 0o600
KEY_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")
TOKEN_FORBIDDEN = re.compile(r"[\s\x00-\x1f\x7f]")

OWNER_STEP = (
    "the drain token is made once by the owner, on the host, and recorded in the credentials "
    "file under that label; this role never makes it"
)


class EnvFileError(Exception):
    """A refusal. Names a file, a label, a key or a line number, never a value."""


def sha256_of(text: str) -> str:
    """Return the SHA-256 of ``text`` as UTF-8."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def render_shim_env(token: str) -> str:
    """Return the exact text of the shim's environment file for a drain token."""
    lines = [
        f"PORT={SHIM_PORT}",
        f"SHIM_DB_PATH={SHIM_DB_PATH}",
        f"SHIM_THROTTLE_PATH={SHIM_THROTTLE_PATH}",
        f"{SHIM_TOKEN_KEY}={token}",
    ]
    return "\n".join(lines) + "\n"


def find_token(credentials_text: str, label: str, path: str) -> str | None:
    """Return the secret recorded under ``label``, or None.

    The file is flat ``label:secret`` lines, as the hand route's 6x scripts share it.

    Raises:
        EnvFileError: A line has no separator (a disk-full append or a hand edit).
    """
    for number, raw in enumerate(credentials_text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        if ":" not in line:
            message = f"{path} line {number} is malformed (no ':' separator)"
            raise EnvFileError(message)
        found, secret = line.split(":", 1)
        if found == label:
            return secret
    return None


def read_credentials(path: str) -> str:
    """Return the credentials file's text; a missing file is an empty one.

    Raises:
        EnvFileError: The file exists and cannot be read.
    """
    if not os.path.lexists(path):
        return ""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        message = f"{path} cannot be read"
        raise EnvFileError(message) from None


def drain_token(credentials_path: str, label: str) -> str | None:
    """Return the drain token, or None when the credentials file does not hold it.

    Raises:
        EnvFileError: The file is unreadable or malformed, or holds a token that cannot be
            one line of an environment file.
    """
    token = find_token(read_credentials(credentials_path), label, credentials_path)
    if token is None:
        return None
    if not token or TOKEN_FORBIDDEN.search(token) is not None:
        message = (
            f"the token under label {label} in {credentials_path} is empty or holds whitespace"
        )
        raise EnvFileError(message)
    return token


def validate_key(key: str) -> None:
    """Refuse a key that is not an upper-case variable name.

    Raises:
        EnvFileError: The key is not.
    """
    if KEY_PATTERN.fullmatch(key) is None:
        message = "the key is not an upper-case variable name"
        raise EnvFileError(message)


def valid_for_key(text: str, key: str) -> bool:
    """Return whether the text has exactly one non-empty line for the key.

    No length or character set is assumed: the owner may have pasted the value by hand.
    Other lines are not judged here.
    """
    matches = [
        line.partition("=")[2]
        for line in text.splitlines()
        if line.partition("=")[0].strip() == key and "=" in line
    ]
    return len(matches) == 1 and matches[0].strip() != ""


def new_secret() -> str:
    """Return a new secret: 48 letters and digits."""
    return "".join(secrets.choice(ALPHANUMERIC) for _ in range(SECRET_LENGTH))


def create_exclusive(path: str, text: str) -> None:
    """Create ``path`` with ``text`` at mode 0600, failing if the file exists.

    The file is never readable by anyone else, not even for an instant.

    Raises:
        EnvFileError: The file appeared between the check and the write.
    """
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
    except FileExistsError:
        message = f"{path} appeared while it was being made"
        raise EnvFileError(message) from None
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def replace_atomic(path: str, text: str) -> None:
    """Replace ``path`` with ``text`` at mode 0600, through a temporary file beside it."""
    directory = os.path.dirname(path) or "."
    descriptor, temporary = tempfile.mkstemp(prefix=".mx1-env.", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, FILE_MODE)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read_text(path: str) -> str | None:
    """Return a file's text, or None when there is no such file.

    Raises:
        EnvFileError: The path is not a regular file, or cannot be read.
    """
    if not os.path.lexists(path):
        return None
    if os.path.islink(path) or not os.path.isfile(path):
        message = f"{path} is not a regular file"
        raise EnvFileError(message)
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        message = f"{path} cannot be read"
        raise EnvFileError(message) from None


def mint(path: str, key: str, *, check_mode: bool) -> dict[str, object]:
    """Make the file if it is absent; judge it if it is there.

    Raises:
        EnvFileError: The key is malformed, or an existing file lacks exactly one line for it.
    """
    validate_key(key)
    existing = read_text(path)
    if existing is not None:
        if not valid_for_key(existing, key):
            message = f"{path} must hold exactly one non-empty {key} line, and does not"
            raise EnvFileError(message)
        return {"changed": False, "created": False, "valid": True, "sha256": sha256_of(existing)}
    text = f"{key}={new_secret()}\n"
    if not check_mode:
        create_exclusive(path, text)
    # The hash of a secret that does not exist yet is not known in check mode.
    return {
        "changed": True,
        "created": not check_mode,
        "valid": True,
        "sha256": "" if check_mode else sha256_of(text),
    }


def shim(path: str, credentials_path: str, label: str, *, check_mode: bool) -> dict[str, object]:
    """Render the shim's environment file from the token, writing only when it differs.

    Raises:
        EnvFileError: The credentials file does not hold the drain token.
    """
    token = drain_token(credentials_path, label)
    if token is None:
        message = f"{credentials_path} holds no entry labelled {label}: {OWNER_STEP}"
        raise EnvFileError(message)
    text = render_shim_env(token)
    current = read_text(path)
    mode_ok = current is not None and os.stat(path).st_mode & 0o777 == FILE_MODE
    changed = current != text or not mode_ok
    if changed and not check_mode:
        replace_atomic(path, text)
    return {"changed": changed, "sha256": sha256_of(text)}


def check_token(credentials_path: str, label: str) -> dict[str, object]:
    """Say whether the credentials file holds the drain token."""
    return {"changed": False, "found": drain_token(credentials_path, label) is not None}


def reserved_keys(path: str, prefix: str) -> dict[str, object]:
    """Return the keys of an environment file that start with ``prefix``, and no value.

    A file that is absent has none.
    """
    text = read_text(path)
    keys: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.strip().removeprefix("export ").strip()
        key = line.partition("=")[0].strip()
        if "=" in line and key.startswith(prefix):
            keys.add(key)
    return {"changed": False, "found_keys": sorted(keys)}


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["mint", "shim", "check_token", "reserved_keys"],
            },
            "path": {"type": "path"},
            "prefix": {"type": "str", "default": "COMPOSE_", "no_log": False},
            "key": {"type": "str", "default": "STALWART_PROMETHEUS_SECRET", "no_log": False},
            "credentials_path": {"type": "path"},
            "label": {"type": "str", "default": "shim-drain-token", "no_log": False},
        },
        required_if=[
            ("action", "mint", ["path"]),
            ("action", "shim", ["path", "credentials_path"]),
            ("action", "check_token", ["credentials_path"]),
            ("action", "reserved_keys", ["path"]),
        ],
        supports_check_mode=True,
    )
    action = str(module.params["action"])
    try:
        if action == "mint":
            result = mint(
                str(module.params["path"]), str(module.params["key"]), check_mode=module.check_mode
            )
        elif action == "shim":
            result = shim(
                str(module.params["path"]),
                str(module.params["credentials_path"]),
                str(module.params["label"]),
                check_mode=module.check_mode,
            )
        elif action == "reserved_keys":
            result = reserved_keys(str(module.params["path"]), str(module.params["prefix"]))
        else:
            result = check_token(
                str(module.params["credentials_path"]), str(module.params["label"])
            )
    except EnvFileError as error:
        module.fail_json(msg=f"mx1 {action}: {error}")
    else:
        module.exit_json(**result)


if __name__ == "__main__":
    main()
