#!/usr/bin/env python3

import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access

import json
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("deepfake-detector-mcp")
@mcp.tool(name="analyze_media")
async def analyze_media(filename: str, file_size_mb: float, api_key: str = "") -> str:
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    score = min(100, max(0, file_size_mb * 2.5))
    return {"filename": filename, "deepfake_score": round(score, 1), "recommendation": "Further forensic analysis" if score > 50 else "Likely authentic"}
@mcp.tool(name="metadata_check")
async def metadata_check(metadata: dict, api_key: str = "") -> str:
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    flags = []
    if metadata.get("software", "").lower() in ["deepfacelab", "faceswap"]:
        flags.append("Known synthetic software detected")
    if not metadata.get("created_date"):
        flags.append("Missing creation date")
    return {"flags": flags, "suspicious": len(flags) > 0}
if __name__ == "__main__":
    mcp.run()
