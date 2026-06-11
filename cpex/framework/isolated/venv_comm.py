# -*- coding: utf-8 -*-
"""
Location: ./cpex/framework/isolated/venv_comm.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo, Ted Habeck
"""

import logging
import os
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Optional

import orjson

logger = logging.getLogger(__name__)


class VenvProcessCommunicator:
    """Handles communication with a long-running child process in a different virtual environment."""

    def __init__(self, venv_path: str) -> None:
        """
        Initialize communicator with target virtual environment.

        Args:
            venv_path (str): Path to the virtual environment directory
        """
        self.venv_path = Path(venv_path)
        self.python_executable = self._get_python_executable()
        self.process: Optional[subprocess.Popen] = None
        self.reader_thread: Optional[threading.Thread] = None
        self.stderr_thread: Optional[threading.Thread] = None
        self.response_queues: dict[str, Queue] = {}
        self.lock = threading.Lock()
        self.running = False
        logger.info("cwd: %s", os.getcwd())

    def _get_python_executable(self):
        """Get the Python executable path for the target venv."""
        if sys.platform == "win32":
            python_exe = self.venv_path / "Scripts" / "python.exe"
        else:
            python_exe = self.venv_path / "bin" / "python"

        if not python_exe.exists():
            raise FileNotFoundError(f"Python executable not found at {python_exe}")

        return str(python_exe)

    def upgrade_pip(self) -> None:
        """Upgrade pip in the target venv."""
        try:
            subprocess.check_call([self.python_executable, "-m", "pip", "install", "--upgrade", "pip"])
        except Exception as e:
            raise RuntimeError("Failed to upgrade pip") from e

    def install_requirements(self, requirements_file: str) -> None:
        """
        Install Python requirements from a file in the target venv.
        Args:
            requirements_file (str): Path to the requirements file.
        """
        requirements_path = Path(requirements_file)
        if requirements_path.exists():
            try:
                self.upgrade_pip()
                subprocess.check_call([self.python_executable, "-m", "pip", "install", "-r", requirements_file])
            except Exception as e:
                raise RuntimeError(f"Failed to install requirements from {requirements_file}") from e

    def start_worker(self, script_path: str) -> None:
        """
        Start the long-running worker process.

        Args:
            script_path (str): Path to the worker script
        """
        if self.running:
            logger.warning("Worker process already running")
            return

        try:
            # Start child process
            self.process = subprocess.Popen(
                [self.python_executable, script_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
                cwd=os.getcwd(),
                env={"PLUGINS_CONFIG_FILE": os.environ.get("PLUGINS_CONFIG_FILE", "plugins/config.yaml")},
            )

            self.running = True

            # Start reader thread to handle responses
            self.reader_thread = threading.Thread(target=self._read_responses, daemon=True)
            self.reader_thread.start()

            # Start stderr reader thread to capture errors
            self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
            self.stderr_thread.start()

            logger.info("Worker process started with PID: %s", self.process.pid)

        except Exception as e:
            self.running = False
            raise RuntimeError(f"Failed to start worker process: {e}") from e

    def _read_stderr(self) -> None:
        """Background thread to read and log stderr from worker process."""
        if not self.process or not self.process.stderr:
            return

        while self.running and self.process and self.process.stderr:
            try:
                line = self.process.stderr.readline()
                if not line:
                    break
                # Log stderr output from worker
                logger.debug("Worker stderr: %s", line.strip())
            except Exception as e:
                logger.error("Error reading stderr: %s", e)
                break

    def _read_responses(self) -> None:
        """Background thread to read responses from worker process."""
        while self.running and self.process and self.process.stdout:
            try:
                line = self.process.stdout.readline()
                if not line:
                    # Process has terminated
                    logger.warning("Worker process stdout closed")
                    break

                line = line.strip()
                if not line:
                    # Empty line, skip
                    continue

                try:
                    response = orjson.loads(line)
                    request_id = response.get("request_id")

                    if request_id:
                        with self.lock:
                            if request_id in self.response_queues:
                                self.response_queues[request_id].put(response)
                                logger.debug("Response queued for request_id: %s", request_id)
                            else:
                                logger.warning("Received response for unknown request_id: %s", request_id)
                    else:
                        logger.warning("Received response without request_id: %s", line[:100])

                except orjson.JSONDecodeError as e:
                    logger.error("Failed to decode response: %s, line: %s", e, line[:200])

            except Exception as e:
                logger.exception("Error reading response: %s", e)
                break

        self.running = False
        logger.info("Response reader thread terminated")

    def send_task(
        self, script_path: str, task_data: Any, timeout: float = 30.0, max_content_size: int = 10000000
    ) -> Any:
        """
        Send a task to the long-running worker process and get response.

        Args:
            script_path (str): Path to the child script (used for worker initialization)
            task_data (dict): Data to send to child process
            timeout (float): Timeout in seconds for waiting for response

        Returns:
            dict: Response from child process
        """
        # Start worker if not running
        if not self.running:
            self.start_worker(script_path)

        # Generate unique request ID
        request_id = str(uuid.uuid4())
        task_data["request_id"] = request_id

        # Create response queue for this request
        response_queue: Queue = Queue()
        with self.lock:
            self.response_queues[request_id] = response_queue

        try:
            # Send task to worker
            input_json = orjson.dumps(task_data).decode()
            if len(input_json) > max_content_size:
                # remove the request_id from the response queue and raise
                self.response_queues.pop(request_id)
                raise RuntimeError(f"task_data exceeds max_content_size.  {len(input_json)}")
            if self.process and self.process.stdin:
                self.process.stdin.write(input_json + "\n")
                self.process.stdin.flush()
            else:
                raise RuntimeError("Worker process stdin not available")

            # Wait for response
            try:
                response = response_queue.get(timeout=timeout)

                # Check for errors in response
                if response.get("status") == "error":
                    raise RuntimeError(f"Worker process error: {response.get('message')}")

                # Remove request_id from response before returning
                response.pop("request_id", None)
                return response

            except Empty:
                raise RuntimeError(f"Worker process timed out after {timeout} seconds")

        finally:
            # Clean up response queue
            with self.lock:
                self.response_queues.pop(request_id, None)

    def stop_worker(self) -> None:
        """Stop the long-running worker process."""
        if not self.running:
            return

        self.running = False

        try:
            if self.process:
                # Send shutdown signal
                if self.process.stdin:
                    try:
                        shutdown_task = {"task_type": "shutdown", "request_id": "shutdown"}
                        self.process.stdin.write(orjson.dumps(shutdown_task).decode() + "\n")
                        self.process.stdin.flush()
                    except Exception as e:
                        logger.warning("Failed to send shutdown signal: %s", e)

                # Wait for process to terminate gracefully
                try:
                    self.process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    logger.warning("Worker process did not terminate gracefully, killing it")
                    self.process.kill()
                    self.process.wait()

                logger.info("Worker process stopped")

        except Exception as e:
            logger.error("Error stopping worker process: %s", e)

        finally:
            self.process = None
            if self.reader_thread and self.reader_thread.is_alive():
                self.reader_thread.join(timeout=2.0)
            self.reader_thread = None
            if self.stderr_thread and self.stderr_thread.is_alive():
                self.stderr_thread.join(timeout=2.0)
            self.stderr_thread = None

    def is_alive(self) -> bool:
        """Check if the worker process is alive and running."""
        return self.running and self.process is not None and self.process.poll() is None

    def __del__(self):
        """Cleanup when object is destroyed."""
        if hasattr(self, "running"):
            self.stop_worker()
