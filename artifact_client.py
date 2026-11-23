"""
Compatibility alias for `artifact_mcp.artifact_client`.

Author: Pawan Gunjkar (pawangunjkar@gmail.com)

`import artifact_client` returns the package module itself, so there is a single
implementation and patches in tests apply to the code that actually runs.
"""

import sys

from artifact_mcp import artifact_client as _impl

sys.modules[__name__] = _impl
