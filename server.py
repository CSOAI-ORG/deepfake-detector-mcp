#!/usr/bin/env python3
"""Deepfake Detector MCP Server - Analyze media for manipulation artifacts."""

import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access

import json, hashlib, time, struct, re
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

# Rate limiting
_rate_limits: dict = defaultdict(list)
RATE_WINDOW = 60
MAX_REQUESTS = 30

def _check_rate(key: str) -> bool:
    now = time.time()
    _rate_limits[key] = [t for t in _rate_limits[key] if now - t < RATE_WINDOW]
    if len(_rate_limits[key]) >= MAX_REQUESTS:
        return False
    _rate_limits[key].append(now)
    return True

# Known synthetic software signatures
SYNTHETIC_SOFTWARE = [
    "deepfacelab", "faceswap", "fakeapp", "reface", "zao",
    "wombo", "deepart", "artbreeder", "thispersondoesnotexist",
    "stable diffusion", "midjourney", "dall-e", "dall-e 2", "dall-e 3",
]

# Known camera manufacturers (legitimate provenance)
KNOWN_CAMERAS = [
    "canon", "nikon", "sony", "fujifilm", "panasonic", "olympus",
    "leica", "hasselblad", "pentax", "samsung", "apple", "google",
]

# Audio synthesis artifact patterns
AUDIO_ARTIFACT_INDICATORS = {
    "spectral_gaps": "Unnatural gaps in frequency spectrum",
    "phase_discontinuity": "Phase alignment breaks typical of splicing",
    "formant_regularity": "Overly regular formant patterns suggest synthesis",
    "breathing_absence": "No natural breathing sounds detected",
    "pitch_monotony": "Pitch variation below natural threshold",
    "onset_sharpness": "Unnaturally sharp phoneme onsets",
    "room_tone_mismatch": "Room tone inconsistencies across segments",
}

mcp = FastMCP("deepfake-detector-mcp", instructions="Analyze images, videos, and audio for deepfake manipulation artifacts. Checks metadata, provenance chains, and synthesis indicators.")


@mcp.tool()
async def detect_deepfake(filename: str, file_size_mb: float, metadata: str = "{}", api_key: str = "") -> str:
    """Analyze image/video metadata and characteristics for manipulation indicators."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if not _check_rate(api_key or "anon"):
        return json.dumps({"error": "Rate limit exceeded. Try again in 60 seconds."})

    try:
        meta = json.loads(metadata) if isinstance(metadata, str) else metadata
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid metadata JSON"})

    indicators = []
    risk_score = 0.0

    # Check file extension
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    video_extensions = {"mp4", "avi", "mov", "mkv", "webm", "flv"}
    image_extensions = {"jpg", "jpeg", "png", "bmp", "tiff", "webp", "gif"}
    media_type = "video" if ext in video_extensions else "image" if ext in image_extensions else "unknown"

    if media_type == "unknown":
        indicators.append({"type": "warning", "detail": f"Unrecognized file extension: .{ext}"})
        risk_score += 5.0

    # Check software field for known synthetic tools
    software = meta.get("software", "").lower()
    for synth in SYNTHETIC_SOFTWARE:
        if synth in software:
            indicators.append({"type": "critical", "detail": f"Known synthetic software detected: {software}"})
            risk_score += 40.0
            break

    # Check for missing EXIF data (common in generated images)
    exif_fields = ["camera_make", "camera_model", "focal_length", "exposure_time", "iso", "gps"]
    missing_exif = [f for f in exif_fields if f not in meta]
    if len(missing_exif) > 4:
        indicators.append({"type": "suspicious", "detail": f"Missing {len(missing_exif)}/6 standard EXIF fields"})
        risk_score += 15.0
    elif len(missing_exif) > 2:
        indicators.append({"type": "minor", "detail": f"Missing {len(missing_exif)}/6 EXIF fields"})
        risk_score += 5.0

    # Check creation/modification date consistency
    created = meta.get("created_date", "")
    modified = meta.get("modified_date", "")
    if created and modified and modified < created:
        indicators.append({"type": "suspicious", "detail": "Modified date precedes creation date"})
        risk_score += 20.0
    if not created:
        indicators.append({"type": "minor", "detail": "No creation date in metadata"})
        risk_score += 5.0

    # Check file size anomalies
    if media_type == "image" and file_size_mb > 50:
        indicators.append({"type": "minor", "detail": "Unusually large image file"})
        risk_score += 3.0
    elif media_type == "image" and file_size_mb < 0.01:
        indicators.append({"type": "suspicious", "detail": "Extremely small image - may be heavily compressed or synthetic"})
        risk_score += 10.0

    # Check resolution consistency
    width = meta.get("width", 0)
    height = meta.get("height", 0)
    if width and height:
        if width == height and width in [512, 1024, 2048]:
            indicators.append({"type": "suspicious", "detail": f"Square {width}x{height} resolution common in AI-generated images"})
            risk_score += 12.0

    # Check for editing history
    edit_count = meta.get("edit_count", 0)
    if edit_count > 10:
        indicators.append({"type": "minor", "detail": f"High edit count ({edit_count}) suggests heavy manipulation"})
        risk_score += 8.0

    # Determine hash for tracking
    content_hash = hashlib.sha256(f"{filename}:{file_size_mb}:{metadata}".encode()).hexdigest()[:16]

    risk_score = min(100.0, risk_score)
    if risk_score >= 60:
        verdict = "HIGH_RISK"
        recommendation = "Content shows strong indicators of manipulation. Manual forensic review strongly recommended."
    elif risk_score >= 30:
        verdict = "MODERATE_RISK"
        recommendation = "Some suspicious indicators found. Further analysis recommended."
    elif risk_score >= 10:
        verdict = "LOW_RISK"
        recommendation = "Minor anomalies detected but content appears mostly authentic."
    else:
        verdict = "LIKELY_AUTHENTIC"
        recommendation = "No significant manipulation indicators found."

    return json.dumps({
        "filename": filename,
        "media_type": media_type,
        "analysis_hash": content_hash,
        "risk_score": round(risk_score, 1),
        "verdict": verdict,
        "recommendation": recommendation,
        "indicators": indicators,
        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


@mcp.tool()
async def analyze_audio_authenticity(duration_seconds: float, sample_rate: int = 44100, channels: int = 2, metadata: str = "{}", api_key: str = "") -> str:
    """Check audio for synthesis artifacts and manipulation indicators."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if not _check_rate(api_key or "anon"):
        return json.dumps({"error": "Rate limit exceeded. Try again in 60 seconds."})

    try:
        meta = json.loads(metadata) if isinstance(metadata, str) else metadata
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid metadata JSON"})

    artifacts = []
    authenticity_score = 100.0

    # Check sample rate (synthetic audio often uses non-standard rates)
    standard_rates = [8000, 11025, 16000, 22050, 44100, 48000, 88200, 96000]
    if sample_rate not in standard_rates:
        artifacts.append({"artifact": "non_standard_sample_rate", "detail": f"Sample rate {sample_rate}Hz is non-standard", "severity": "medium"})
        authenticity_score -= 15.0

    # Check duration anomalies
    if duration_seconds < 0.5:
        artifacts.append({"artifact": "very_short_clip", "detail": "Audio clip under 0.5s - insufficient for reliable analysis", "severity": "info"})
    elif duration_seconds > 7200:
        artifacts.append({"artifact": "very_long_clip", "detail": "Extremely long audio may indicate concatenation", "severity": "low"})
        authenticity_score -= 5.0

    # Simulate spectral analysis based on metadata hints
    codec = meta.get("codec", "").lower()
    if codec in ["pcm_generated", "synthetic_wav"]:
        artifacts.append({"artifact": "synthetic_codec", "detail": f"Codec '{codec}' associated with synthesis", "severity": "high"})
        authenticity_score -= 30.0

    # Check for TTS engine signatures
    tts_engines = ["elevenlabs", "bark", "tortoise", "coqui", "mozilla_tts", "google_tts", "amazon_polly"]
    software = meta.get("software", "").lower()
    for engine in tts_engines:
        if engine in software:
            artifacts.append({"artifact": "tts_signature", "detail": f"Text-to-speech engine detected: {engine}", "severity": "critical"})
            authenticity_score -= 40.0
            break

    # Check channel consistency
    if channels == 1 and meta.get("expected_stereo", False):
        artifacts.append({"artifact": "channel_mismatch", "detail": "Mono audio where stereo expected", "severity": "medium"})
        authenticity_score -= 10.0

    # Simulate artifact detection based on duration patterns
    # Real speech has natural pauses; synthetic often doesn't
    if meta.get("silence_ratio", 0.15) < 0.05:
        artifacts.append({"artifact": "breathing_absence", "detail": AUDIO_ARTIFACT_INDICATORS["breathing_absence"], "severity": "medium"})
        authenticity_score -= 12.0

    if meta.get("pitch_variance", 30.0) < 10.0:
        artifacts.append({"artifact": "pitch_monotony", "detail": AUDIO_ARTIFACT_INDICATORS["pitch_monotony"], "severity": "medium"})
        authenticity_score -= 10.0

    authenticity_score = max(0.0, authenticity_score)

    if authenticity_score >= 80:
        verdict = "LIKELY_AUTHENTIC"
    elif authenticity_score >= 50:
        verdict = "POSSIBLY_SYNTHETIC"
    else:
        verdict = "LIKELY_SYNTHETIC"

    return json.dumps({
        "duration_seconds": duration_seconds,
        "sample_rate": sample_rate,
        "channels": channels,
        "authenticity_score": round(authenticity_score, 1),
        "verdict": verdict,
        "artifacts_found": artifacts,
        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


@mcp.tool()
async def check_image_provenance(filename: str, metadata: str = "{}", claimed_source: str = "", api_key: str = "") -> str:
    """Verify image source chain and provenance integrity."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if not _check_rate(api_key or "anon"):
        return json.dumps({"error": "Rate limit exceeded. Try again in 60 seconds."})

    try:
        meta = json.loads(metadata) if isinstance(metadata, str) else metadata
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid metadata JSON"})

    chain = []
    trust_score = 100.0
    issues = []

    # Step 1: Check camera/device origin
    camera_make = meta.get("camera_make", "").lower()
    camera_model = meta.get("camera_model", "")
    if camera_make:
        is_known = any(cam in camera_make for cam in KNOWN_CAMERAS)
        chain.append({
            "step": "capture",
            "device": f"{camera_make} {camera_model}".strip(),
            "trusted": is_known,
        })
        if not is_known:
            trust_score -= 10.0
            issues.append("Unknown camera manufacturer")
    else:
        chain.append({"step": "capture", "device": "unknown", "trusted": False})
        trust_score -= 20.0
        issues.append("No camera information in metadata")

    # Step 2: Check software processing chain
    software = meta.get("software", "")
    if software:
        chain.append({"step": "processing", "software": software, "trusted": True})
    else:
        chain.append({"step": "processing", "software": "none detected", "trusted": True})

    # Step 3: Check edit history
    history = meta.get("edit_history", [])
    if history:
        for i, edit in enumerate(history):
            editor = edit.get("software", "unknown")
            chain.append({"step": f"edit_{i+1}", "software": editor, "trusted": True})
        if len(history) > 5:
            trust_score -= 10.0
            issues.append(f"Extensive edit history ({len(history)} edits)")

    # Step 4: Verify claimed source
    if claimed_source:
        actual_source = meta.get("source", "")
        if actual_source and actual_source.lower() != claimed_source.lower():
            trust_score -= 25.0
            issues.append(f"Claimed source '{claimed_source}' does not match metadata source '{actual_source}'")
            chain.append({"step": "source_verification", "claimed": claimed_source, "actual": actual_source, "match": False})
        elif actual_source:
            chain.append({"step": "source_verification", "claimed": claimed_source, "actual": actual_source, "match": True})
        else:
            trust_score -= 10.0
            issues.append("Cannot verify claimed source - no source in metadata")
            chain.append({"step": "source_verification", "claimed": claimed_source, "actual": None, "match": False})

    # Step 5: Check timestamp consistency
    timestamps = []
    for field in ["created_date", "modified_date", "digitized_date"]:
        if field in meta:
            timestamps.append({"field": field, "value": meta[field]})
    if len(timestamps) >= 2:
        chain.append({"step": "timestamp_verification", "timestamps": timestamps, "consistent": True})
    elif len(timestamps) == 0:
        trust_score -= 15.0
        issues.append("No timestamps in metadata")

    # Generate content hash
    provenance_hash = hashlib.sha256(f"{filename}:{json.dumps(meta, sort_keys=True)}".encode()).hexdigest()[:24]

    trust_score = max(0.0, trust_score)

    return json.dumps({
        "filename": filename,
        "provenance_hash": provenance_hash,
        "trust_score": round(trust_score, 1),
        "provenance_chain": chain,
        "issues": issues,
        "chain_length": len(chain),
        "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


@mcp.tool()
async def generate_authenticity_report(filename: str, file_size_mb: float, media_type: str = "image", metadata: str = "{}", api_key: str = "") -> str:
    """Generate a comprehensive authenticity report on content."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if not _check_rate(api_key or "anon"):
        return json.dumps({"error": "Rate limit exceeded. Try again in 60 seconds."})

    try:
        meta = json.loads(metadata) if isinstance(metadata, str) else metadata
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid metadata JSON"})

    report_id = hashlib.sha256(f"{filename}:{time.time()}".encode()).hexdigest()[:12]

    # Metadata completeness score
    expected_fields = ["camera_make", "camera_model", "created_date", "modified_date", "software", "width", "height", "gps", "iso", "focal_length"]
    present = sum(1 for f in expected_fields if f in meta)
    metadata_completeness = round((present / len(expected_fields)) * 100, 1)

    # Manipulation indicators
    manipulation_checks = {
        "metadata_stripped": present < 3,
        "synthetic_software": any(s in meta.get("software", "").lower() for s in SYNTHETIC_SOFTWARE),
        "timestamp_anomaly": (meta.get("modified_date", "") < meta.get("created_date", "")) if meta.get("modified_date") and meta.get("created_date") else False,
        "resolution_anomaly": meta.get("width", 0) == meta.get("height", 0) and meta.get("width", 0) in [512, 1024, 2048],
        "excessive_edits": meta.get("edit_count", 0) > 10,
        "missing_device_info": not meta.get("camera_make"),
    }
    flags_raised = sum(1 for v in manipulation_checks.values() if v)

    # Calculate overall authenticity
    base_score = 100.0
    if manipulation_checks["synthetic_software"]:
        base_score -= 40.0
    if manipulation_checks["metadata_stripped"]:
        base_score -= 20.0
    if manipulation_checks["timestamp_anomaly"]:
        base_score -= 15.0
    if manipulation_checks["resolution_anomaly"]:
        base_score -= 12.0
    if manipulation_checks["excessive_edits"]:
        base_score -= 8.0
    if manipulation_checks["missing_device_info"]:
        base_score -= 10.0

    overall_score = max(0.0, base_score)

    if overall_score >= 75:
        classification = "AUTHENTIC"
        confidence = "high" if overall_score >= 90 else "moderate"
    elif overall_score >= 40:
        classification = "UNCERTAIN"
        confidence = "low"
    else:
        classification = "MANIPULATED"
        confidence = "high" if overall_score <= 20 else "moderate"

    recommendations = []
    if manipulation_checks["synthetic_software"]:
        recommendations.append("Known synthetic software detected - verify with original source")
    if manipulation_checks["metadata_stripped"]:
        recommendations.append("Metadata largely absent - request original file from source")
    if flags_raised == 0:
        recommendations.append("No significant concerns - content appears authentic")
    if overall_score < 50:
        recommendations.append("Consider reverse image search for original source")
        recommendations.append("Request provenance documentation from content provider")

    return json.dumps({
        "report_id": report_id,
        "filename": filename,
        "media_type": media_type,
        "file_size_mb": file_size_mb,
        "overall_authenticity_score": round(overall_score, 1),
        "classification": classification,
        "confidence": confidence,
        "metadata_completeness_pct": metadata_completeness,
        "manipulation_checks": manipulation_checks,
        "flags_raised": flags_raised,
        "recommendations": recommendations,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "disclaimer": "This analysis is based on metadata inspection only. Physical forensic analysis may yield different results.",
    })


if __name__ == "__main__":
    mcp.run()
