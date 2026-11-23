"""
Compatibility alias for `artifact_mcp.credential_store`.

Author: Pawan Gunjkar (pawangunjkar@gmail.com)

`import credential_store` returns the package module itself, so there is a single
implementation of the credential store.
"""

import sys

from artifact_mcp import credential_store as _impl

sys.modules[__name__] = _impl
