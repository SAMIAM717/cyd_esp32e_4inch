#!/usr/bin/env python3
"""CyberSentinel Pro REST API entrypoint."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Add scanner directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'scanner'))

try:
    from scanner.network_scanner import NetworkScanner
    from scanner.web_scanner import WebScanner
    from scanner.ai_analyzer import AIAnalyzer
except ImportError as e:
    print(f"Error importing scanner modules: {e}")
    print("Please ensure all scanner modules are properly installed.")
    sys.exit(1)

LOGGER = logging.getLogger("cybersentinel.api")

app = FastAPI(title="CyberSentinel Pro API", version="1.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results (in production, use database)
scan_results: Dict[str, Any] = {}
scan_tasks: Dict[str, Dict[str, Any]] = {}
active_scan_jobs: Dict[str, asyncio.Task] = {}

class ScanRequest(BaseModel):
    """Request payload for launching a scan."""

    target: str
    scan_type: Optional[str] = "comprehensive"
    options: Optional[Dict[str, Any]] = {}

class AIAnalysisRequest(BaseModel):
    """Payload containing data to feed the AI analyzer."""

    scan_data: Dict[str, Any]

class OpenAIKey(BaseModel):
    """Payload to configure OpenAI API key at runtime."""

    api_key: str

@app.on_event("startup")
async def startup_event():
    """Initialize scanners on startup"""
    LOGGER.info("🔧 Initializing CyberSentinel Pro scanners...")

    network_scanner: Optional[NetworkScanner] = None
    web_scanner: Optional[WebScanner] = None
    ai_analyzer: Optional[AIAnalyzer] = None

    try:
        network_scanner = NetworkScanner()
        LOGGER.info("✅ Network scanner initialized")
    except (RuntimeError, ValueError, OSError) as exc:
        LOGGER.exception("❌ Network scanner initialization failed", exc_info=exc)

    try:
        web_scanner = WebScanner()
        LOGGER.info("✅ Web scanner initialized")
    except (RuntimeError, ValueError, OSError) as exc:
        LOGGER.exception("❌ Web scanner initialization failed", exc_info=exc)

    try:
        ai_analyzer = AIAnalyzer()
        LOGGER.info("✅ AI analyzer initialized")
    except (RuntimeError, ValueError) as exc:
        LOGGER.exception("❌ AI analyzer initialization failed", exc_info=exc)

    app.state.network_scanner = network_scanner
    app.state.web_scanner = web_scanner
    app.state.ai_analyzer = ai_analyzer

    if not any((network_scanner, web_scanner, ai_analyzer)):
        LOGGER.warning("⚠️  Warning: No scanners initialized successfully")
    else:
        LOGGER.info("🚀 CyberSentinel Pro API Server ready!")


def _get_network_scanner(raise_for_client: bool = True) -> Optional[NetworkScanner]:
    """Return the network scanner instance."""

    scanner: Optional[NetworkScanner] = getattr(app.state, "network_scanner", None)
    if scanner is None and raise_for_client:
        raise HTTPException(status_code=503, detail="Network scanner not available")
    return scanner


def _get_web_scanner(raise_for_client: bool = True) -> Optional[WebScanner]:
    """Return the web scanner instance."""

    scanner: Optional[WebScanner] = getattr(app.state, "web_scanner", None)
    if scanner is None and raise_for_client:
        raise HTTPException(status_code=503, detail="Web scanner not available")
    return scanner


def _get_ai_analyzer(raise_for_client: bool = True) -> Optional[AIAnalyzer]:
    """Return the AI analyzer instance."""

    analyzer: Optional[AIAnalyzer] = getattr(app.state, "ai_analyzer", None)
    if analyzer is None and raise_for_client:
        raise HTTPException(status_code=503, detail="AI analyzer not available")
    return analyzer

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    scanner_status = {
        "network_scanner": getattr(app.state, "network_scanner", None) is not None,
        "web_scanner": getattr(app.state, "web_scanner", None) is not None,
        "ai_analyzer": getattr(app.state, "ai_analyzer", None) is not None,
    }

    return {
        "status": "healthy" if any(scanner_status.values()) else "degraded",
        "timestamp": datetime.now().isoformat(),
        "scanners": scanner_status,
        "active_scans": len(scan_tasks)
    }

@app.post("/config/openai")
async def set_openai_key(payload: OpenAIKey):
    """Set or update the OpenAI API key at runtime.

    This allows the AI analyzer to use the real OpenAI API without restarting the server.
    """
    try:
        analyzer = _get_ai_analyzer(raise_for_client=False)
        if analyzer is None:
            # Initialize a fresh analyzer if it wasn't available
            analyzer = AIAnalyzer(api_key=payload.api_key)
            app.state.ai_analyzer = analyzer
        else:
            analyzer.set_api_key(payload.api_key)

        # Minimal confirmation payload, avoid echoing secrets
        return {"status": "updated", "timestamp": datetime.now().isoformat()}
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=500, detail=f"Failed to set OpenAI API key: {exc}") from exc

@app.post("/scan/network")
async def network_scan(request: ScanRequest):
    """Initiate network scan"""
    _get_network_scanner()

    try:
        # Validate target
        if not request.target:
            raise HTTPException(status_code=400, detail="Target is required")

        # Generate task ID
        task_id = f"network_{datetime.now().timestamp()}"

        # Initialize task status
        scan_tasks[task_id] = {
            "status": "running",
            "type": "network",
            "target": request.target,
            "started_at": datetime.now().isoformat(),
            "progress": 0
        }

        # Start scan in background
        active_scan_jobs[task_id] = asyncio.create_task(
            run_network_scan(task_id, request.target, request.scan_type)
        )

        return {
            "task_id": task_id,
            "status": "started",
            "target": request.target,
            "scan_type": request.scan_type,
            "message": "Network scan initiated"
        }

    except (RuntimeError, ValueError, OSError) as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start network scan: {exc}") from exc

@app.post("/scan/web")
async def web_scan(request: ScanRequest):
    """Initiate web vulnerability scan"""
    _get_web_scanner()

    try:
        # Validate target
        if not request.target:
            raise HTTPException(status_code=400, detail="Target URL is required")

        # Generate task ID
        task_id = f"web_{datetime.now().timestamp()}"

        # Initialize task status
        scan_tasks[task_id] = {
            "status": "running",
            "type": "web",
            "target": request.target,
            "started_at": datetime.now().isoformat(),
            "progress": 0
        }

        # Start scan in background
        active_scan_jobs[task_id] = asyncio.create_task(run_web_scan(task_id, request.target))

        return {
            "task_id": task_id,
            "status": "started",
            "target": request.target,
            "message": "Web vulnerability scan initiated"
        }

    except (RuntimeError, ValueError, OSError) as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start web scan: {exc}") from exc

@app.post("/ai/analyze")
async def ai_analyze(request: AIAnalysisRequest):
    """AI-powered analysis of scan results"""
    ai_analyzer = _get_ai_analyzer()

    try:
        if not request.scan_data:
            raise HTTPException(status_code=400, detail="Scan data is required")

        # Perform AI analysis
        analysis = await ai_analyzer.analyze_scan_results(request.scan_data)

        return {
            "analysis": analysis,
            "timestamp": datetime.now().isoformat(),
            "status": "completed"
        }

    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {exc}") from exc

@app.get("/scan/status/{task_id}")
async def get_scan_status(task_id: str):
    """Get status of a scan task"""
    if task_id not in scan_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    task = scan_tasks[task_id]

    # If scan is completed, return results
    if task["status"] == "completed" and task_id in scan_results:
        result = scan_results[task_id]
        return {
            "task_id": task_id,
            "status": task["status"],
            "progress": 100,
            "result": result,
            "completed_at": task.get("completed_at")
        }

    return {
        "task_id": task_id,
        "status": task["status"],
        "progress": task.get("progress", 0),
        "target": task.get("target"),
        "started_at": task.get("started_at"),
        "error": task.get("error")
    }

@app.get("/scan/results/{task_id}")
async def get_scan_results(task_id: str):
    """Get results of a completed scan"""
    if task_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")

    return scan_results[task_id]

@app.get("/scans")
async def list_scans():
    """List all scan tasks"""
    return {
        "total_scans": len(scan_tasks),
        "active_scans": len([t for t in scan_tasks.values() if t["status"] == "running"]),
        "completed_scans": len([t for t in scan_tasks.values() if t["status"] == "completed"]),
        "failed_scans": len([t for t in scan_tasks.values() if t["status"] == "failed"]),
        "scans": scan_tasks
    }

@app.delete("/scan/{task_id}")
async def cancel_scan(task_id: str):
    """Cancel a running scan"""
    if task_id not in scan_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    task = scan_tasks[task_id]
    if task["status"] == "running":
        job = active_scan_jobs.get(task_id)

        if job and not job.done():
            job.cancel()
            try:
                await job
            except asyncio.CancelledError:
                pass

        task["status"] = "cancelled"
        task["cancelled_at"] = datetime.now().isoformat()
        task["error"] = "Cancelled by user"
        task["progress"] = 0
        active_scan_jobs.pop(task_id, None)
        return {"message": "Scan cancelled successfully"}
    else:
        raise HTTPException(status_code=400, detail="Scan is not running")

async def run_network_scan(task_id: str, target: str, scan_type: str):
    """Run network scan in background"""
    try:
        # Update progress
        scan_tasks[task_id]["progress"] = 10

        # Determine ports based on scan type
        if scan_type == "quick":
            ports = "1-100"
        elif scan_type == "full":
            ports = "1-65535"
        else:  # comprehensive
            ports = "1-1000"

        # Update progress
        scan_tasks[task_id]["progress"] = 25

        # Run the scan
        scanner = _get_network_scanner(raise_for_client=False)
        if scanner is None:
            raise RuntimeError("Network scanner unavailable")
        results = await scanner.scan_network(target, ports)

        # Update progress
        scan_tasks[task_id]["progress"] = 90

        # Store results
        scan_results[task_id] = results
        scan_tasks[task_id]["status"] = "completed"
        scan_tasks[task_id]["completed_at"] = datetime.now().isoformat()
        scan_tasks[task_id]["progress"] = 100
        LOGGER.info("✅ Network scan %s completed successfully", task_id)

    except asyncio.CancelledError:
        LOGGER.info("⚠️  Network scan %s cancelled", task_id)
        scan_tasks[task_id]["status"] = "cancelled"
        scan_tasks[task_id]["completed_at"] = datetime.now().isoformat()
        scan_tasks[task_id]["progress"] = 0
        raise
    except (RuntimeError, ValueError, OSError) as exc:
        LOGGER.exception("❌ Network scan %s failed", task_id)
        scan_tasks[task_id]["status"] = "failed"
        scan_tasks[task_id]["error"] = str(exc)
        scan_tasks[task_id]["progress"] = 0

    finally:
        active_scan_jobs.pop(task_id, None)

async def run_web_scan(task_id: str, target: str):
    """Run web scan in background"""
    try:
        # Update progress
        scan_tasks[task_id]["progress"] = 10

        # Run the scan
        scanner = _get_web_scanner(raise_for_client=False)
        if scanner is None:
            raise RuntimeError("Web scanner unavailable")
        results = await scanner.scan_website(target)

        # Update progress
        scan_tasks[task_id]["progress"] = 90

        # Store results
        scan_results[task_id] = results
        scan_tasks[task_id]["status"] = "completed"
        scan_tasks[task_id]["completed_at"] = datetime.now().isoformat()
        scan_tasks[task_id]["progress"] = 100
        LOGGER.info("✅ Web scan %s completed successfully", task_id)

    except asyncio.CancelledError:
        LOGGER.info("⚠️  Web scan %s cancelled", task_id)
        scan_tasks[task_id]["status"] = "cancelled"
        scan_tasks[task_id]["completed_at"] = datetime.now().isoformat()
        scan_tasks[task_id]["progress"] = 0
        raise
    except (RuntimeError, ValueError, OSError) as exc:
        LOGGER.exception("❌ Web scan %s failed", task_id)
        scan_tasks[task_id]["status"] = "failed"
        scan_tasks[task_id]["error"] = str(exc)
        scan_tasks[task_id]["progress"] = 0

    finally:
        active_scan_jobs.pop(task_id, None)

if __name__ == "__main__":
    print("🚀 Starting CyberSentinel Pro API Server...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
