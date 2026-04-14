#!/usr/bin/env python3
import json
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("deepfake-detector-mcp")
@mcp.tool(name="analyze_media")
async def analyze_media(filename: str, file_size_mb: float) -> str:
    score = min(100, max(0, file_size_mb * 2.5))
    return json.dumps({"filename": filename, "deepfake_score": round(score, 1), "recommendation": "Further forensic analysis" if score > 50 else "Likely authentic"})
@mcp.tool(name="metadata_check")
async def metadata_check(metadata: dict) -> str:
    flags = []
    if metadata.get("software", "").lower() in ["deepfacelab", "faceswap"]:
        flags.append("Known synthetic software detected")
    if not metadata.get("created_date"):
        flags.append("Missing creation date")
    return json.dumps({"flags": flags, "suspicious": len(flags) > 0})
if __name__ == "__main__":
    mcp.run()
