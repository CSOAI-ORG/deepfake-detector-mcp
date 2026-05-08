<div align="center">

# Deepfake Detector MCP

**MCP server for deepfake detector mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-deepfake-detector-mcp)](https://pypi.org/project/meok-deepfake-detector-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Deepfake Detector MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `detect_deepfake` | Analyze image/video metadata and characteristics for manipulation indicators. |
| `analyze_audio_authenticity` | Check audio for synthesis artifacts and manipulation indicators. |
| `check_image_provenance` | Verify image source chain and provenance integrity. |
| `generate_authenticity_report` | Generate a comprehensive authenticity report on content. |

## Installation

```bash
pip install meok-deepfake-detector-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "deepfake-detector": {
      "command": "python",
      "args": ["-m", "meok_deepfake_detector_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 4 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
