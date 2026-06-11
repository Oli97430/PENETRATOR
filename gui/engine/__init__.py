"""Pure-logic helpers used by GUI tool frames.

These functions don't print or prompt - they take inputs and call the provided
``log(msg, tag)`` callback. That makes them trivial to wire into any UI.

This package was split from a single module; every public name is re-exported
here so ``from gui.engine import X`` still works.
"""
from gui.engine._core import *        # noqa: F401,F403
from gui.engine.recon import *         # noqa: F401,F403
from gui.engine.recon import _check_port  # noqa: F401  # needed by tests
from gui.engine.passwords import *     # noqa: F401,F403
from gui.engine.web import *           # noqa: F401,F403
from gui.engine.forensic import *      # noqa: F401,F403
from gui.engine.osint import *         # noqa: F401,F403
from gui.engine.network import *       # noqa: F401,F403
from gui.engine.async_scan import *    # noqa: F401,F403
from gui.engine.advanced import *      # noqa: F401,F403
from gui.engine.automation import *    # noqa: F401,F403
from gui.engine.integrations import *  # noqa: F401,F403
from gui.engine.defense import *       # noqa: F401,F403
from gui.engine.auth import *          # noqa: F401,F403
from gui.engine.discovery import *     # noqa: F401,F403
from gui.engine.reporting import *     # noqa: F401,F403
