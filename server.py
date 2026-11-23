"""
Artifact Registry MCP Server — compatibility entry point.

Author: Pawan Gunjkar (pawangunjkar@gmail.com)

The implementation lives in the `artifact_mcp` package. This file keeps
`uv run server.py`, `mcp dev server.py`, and `import server` working without
keeping a second copy of the code.
"""

import sys

from artifact_mcp import server as _impl

if __name__ == "__main__":
    _impl.main()
else:
    sys.modules[__name__] = _impl
