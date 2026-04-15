# Deepfake Detector MCP Server

> By [MEOK AI Labs](https://meok.ai) — Analyze images, videos, and audio for deepfake manipulation artifacts

## Installation

```bash
pip install deepfake-detector-mcp
```

## Usage

```bash
python server.py
```

## Tools

This server analyzes media for manipulation artifacts including:

- Image metadata and provenance analysis
- Detection of synthetic software signatures (DeepFaceLab, FaceSwap, Stable Diffusion, Midjourney, DALL-E)
- Camera manufacturer verification for legitimate provenance
- Audio synthesis artifact detection (spectral gaps, phase discontinuity, formant regularity, breathing absence)
- Room tone mismatch analysis

## Authentication

Free tier: 15 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs
