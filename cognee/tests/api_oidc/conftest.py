"""OIDC API tests need AUTH_MODE=oidc in the process environment.

The app and its auth dependencies are built when cognee is imported, which the
parent conftest does before any test module runs, so the mode cannot be set
from inside the tests. Run them with the variables in oidc.env:

    env $(grep -v '^#' cognee/tests/api_oidc/oidc.env | xargs) \\
        uv run pytest cognee/tests/api_oidc -q

Without them the directory is not collected (a password-mode run of
cognee/tests would otherwise fail every test here for the wrong reason).
"""

import os

collect_ignore_glob = [] if os.environ.get("AUTH_MODE") == "oidc" else ["test_*.py"]
