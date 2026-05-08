# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/isolated/test_venv_comm.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

Unit tests for VenvProcessCommunicator.
"""

import subprocess
import sys
from pathlib import Path
from queue import Queue
from unittest.mock import MagicMock, Mock, patch

import pytest

from cpex.framework.isolated.venv_comm import VenvProcessCommunicator


class TestVenvProcessCommunicator:
    """Test suite for VenvProcessCommunicator class."""

    @pytest.fixture
    def mock_venv_path(self, tmp_path):
        """Create a mock venv directory structure."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()

        # Create appropriate bin/Scripts directory based on platform
        if sys.platform == "win32":
            scripts_dir = venv_path / "Scripts"
            scripts_dir.mkdir()
            python_exe = scripts_dir / "python.exe"
        else:
            bin_dir = venv_path / "bin"
            bin_dir.mkdir()
            python_exe = bin_dir / "python"

        # Create a dummy python executable
        python_exe.touch()
        python_exe.chmod(0o755)

        return venv_path

    @pytest.fixture
    def communicator(self, mock_venv_path):
        """Create a VenvProcessCommunicator instance with mock venv."""
        return VenvProcessCommunicator(str(mock_venv_path))

    def test_init_valid_venv(self, mock_venv_path):
        """Test initialization with valid venv path."""
        comm = VenvProcessCommunicator(str(mock_venv_path))
        assert comm.venv_path == mock_venv_path
        assert comm.python_executable is not None
        assert Path(comm.python_executable).exists()

    def test_init_invalid_venv(self, tmp_path):
        """Test initialization with invalid venv path raises error."""
        invalid_path = tmp_path / "nonexistent"
        with pytest.raises(FileNotFoundError, match="Python executable not found"):
            VenvProcessCommunicator(str(invalid_path))

    def test_get_python_executable_unix(self, tmp_path):
        """Test getting Python executable path on Unix-like systems."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        bin_dir = venv_path / "bin"
        bin_dir.mkdir()
        python_exe = bin_dir / "python"
        python_exe.touch()

        with patch("sys.platform", "linux"):
            comm = VenvProcessCommunicator(str(venv_path))
            assert comm.python_executable == str(python_exe)

    def test_get_python_executable_windows(self, tmp_path):
        """Test getting Python executable path on Windows."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        scripts_dir = venv_path / "Scripts"
        scripts_dir.mkdir()
        python_exe = scripts_dir / "python.exe"
        python_exe.touch()

        with patch("sys.platform", "win32"):
            comm = VenvProcessCommunicator(str(venv_path))
            assert comm.python_executable == str(python_exe)

    @patch("subprocess.check_call")
    def test_install_requirements_success(self, mock_check_call, communicator, tmp_path):
        """Test successful requirements installation."""
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text("pytest>=7.0.0\n")

        mock_check_call.return_value = 0

        communicator.install_requirements(str(requirements_file))

        mock_check_call.assert_called_once_with(
            [communicator.python_executable, "-m", "pip", "install", "-r", str(requirements_file)]
        )

    @patch("subprocess.check_call")
    def test_install_requirements_failure(self, mock_check_call, communicator, tmp_path):
        """Test requirements installation failure."""
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text("invalid-package-name-xyz\n")

        # Simulate subprocess.check_call raising an exception
        mock_check_call.side_effect = subprocess.CalledProcessError(1, "pip install")

        with pytest.raises(RuntimeError, match=f"Failed to install requirements from {requirements_file}"):
            communicator.install_requirements(str(requirements_file))

    def test_install_requirements_nonexistent_file(self, communicator):
        """Test install_requirements with nonexistent file does nothing."""
        # Should not raise an error if file doesn't exist
        communicator.install_requirements("nonexistent_requirements.txt")

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    @patch("cpex.framework.isolated.venv_comm.Queue")
    def test_send_task_success(self, mock_queue_class, mock_thread, mock_popen, communicator):
        """Test successful task sending and response."""
        task_data = {"task_type": "info", "data": "test"}

        # Mock the process
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        # Mock the thread
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # Mock the Queue to return our response
        mock_queue_instance = MagicMock()
        mock_queue_instance.get.return_value = {"status": "success", "result": "ok", "request_id": "test-id"}
        mock_queue_class.return_value = mock_queue_instance

        # Manually start the worker to set up the infrastructure
        communicator.start_worker("test_script.py")

        result = communicator.send_task("test_script.py", task_data)

        # Request ID should be removed from response
        assert result == {"status": "success", "result": "ok"}

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    @patch("cpex.framework.isolated.venv_comm.Queue")
    def test_send_task_process_failure(self, mock_queue_class, mock_thread, mock_popen, communicator):
        """Test task sending with process failure."""
        task_data = {"task_type": "test"}

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # Mock the Queue to return error response
        mock_queue_instance = MagicMock()
        mock_queue_instance.get.return_value = {"status": "error", "message": "Process failed", "request_id": "test-id"}
        mock_queue_class.return_value = mock_queue_instance

        # Start worker
        communicator.start_worker("test_script.py")

        with pytest.raises(RuntimeError, match="Worker process error: Process failed"):
            communicator.send_task("test_script.py", task_data)

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_send_task_timeout(self, mock_thread, mock_popen, communicator):
        """Test task sending with timeout."""
        task_data = {"task_type": "test"}

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # Don't put anything in the queue to simulate timeout

        with pytest.raises(RuntimeError, match="Worker process timed out"):
            communicator.send_task("test_script.py", task_data, timeout=0.1)

    @patch("subprocess.Popen")
    def test_send_task_communication_error(self, mock_popen, communicator):
        """Test task sending with communication error."""
        task_data = {"task_type": "test"}

        mock_popen.side_effect = OSError("Connection failed")

        with pytest.raises(RuntimeError, match="Failed to start worker process"):
            communicator.send_task("test_script.py", task_data)

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    @patch("cpex.framework.isolated.venv_comm.Queue")
    def test_send_task_with_complex_data(self, mock_queue_class, mock_thread, mock_popen, communicator):
        """Test sending task with complex nested data structures."""
        task_data = {
            "task_type": "load_and_run_hook",
            "config": {"nested": {"data": [1, 2, 3]}},
            "payload": {"args": {"key": "value"}},
            "context": {"state": {}, "metadata": {}},
        }

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # Mock the Queue to return response
        mock_queue_instance = MagicMock()
        mock_queue_instance.get.return_value = {
            "status": "success",
            "result": {"data": "processed"},
            "request_id": "test-id",
        }
        mock_queue_class.return_value = mock_queue_instance

        # Start worker
        communicator.start_worker("worker.py")

        result = communicator.send_task("worker.py", task_data)

        assert result == {"status": "success", "result": {"data": "processed"}}
        # Verify the task was serialized properly
        call_args = mock_popen.call_args
        assert call_args is not None

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    @patch("cpex.framework.isolated.venv_comm.Queue")
    @patch("os.getcwd")
    def test_send_task_maintains_cwd(self, mock_getcwd, mock_queue_class, mock_thread, mock_popen, communicator):
        """Test that send_task maintains current working directory."""
        mock_getcwd.return_value = "/test/path"
        task_data = {"task_type": "test"}

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # Mock the Queue to return response
        mock_queue_instance = MagicMock()
        mock_queue_instance.get.return_value = {"status": "ok", "request_id": "test-id"}
        mock_queue_class.return_value = mock_queue_instance

        # Start worker
        communicator.start_worker("test_script.py")

        communicator.send_task("test_script.py", task_data)

        # Verify cwd was passed to Popen
        call_kwargs = mock_popen.call_args[1]
        assert call_kwargs["cwd"] == "/test/path"

    def test_python_executable_property(self, communicator):
        """Test that python_executable property is accessible."""
        assert communicator.python_executable is not None
        assert isinstance(communicator.python_executable, str)
        assert Path(communicator.python_executable).exists()

    def test_venv_path_property(self, communicator, mock_venv_path):
        """Test that venv_path property is accessible."""
        assert communicator.venv_path == mock_venv_path
        assert isinstance(communicator.venv_path, Path)

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_start_worker_success(self, mock_thread, mock_popen, communicator):
        """Test successful worker process start."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        communicator.start_worker("test_script.py")

        assert communicator.running is True
        assert communicator.process is not None
        mock_popen.assert_called_once()
        # Should start two threads (stdout and stderr readers)
        assert mock_thread.call_count == 2

    @patch("subprocess.Popen")
    def test_start_worker_already_running(self, mock_popen, communicator):
        """Test starting worker when already running."""
        communicator.running = True
        communicator.process = MagicMock()

        communicator.start_worker("test_script.py")

        # Should not create new process
        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_start_worker_failure(self, mock_popen, communicator):
        """Test worker start failure."""
        mock_popen.side_effect = OSError("Failed to start")

        with pytest.raises(RuntimeError, match="Failed to start worker process"):
            communicator.start_worker("test_script.py")

        assert communicator.running is False

    def test_stop_worker_not_running(self, communicator):
        """Test stopping worker when not running."""
        communicator.running = False
        communicator.process = None

        # Should not raise error
        communicator.stop_worker()

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_stop_worker_success(self, mock_thread, mock_popen, communicator):
        """Test successful worker stop."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.wait.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread_instance.is_alive.return_value = False
        mock_thread.return_value = mock_thread_instance

        # Start worker first
        communicator.start_worker("test_script.py")

        # Stop worker
        communicator.stop_worker()

        assert communicator.running is False
        assert communicator.process is None
        mock_process.wait.assert_called()

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_stop_worker_timeout(self, mock_thread, mock_popen, communicator):
        """Test worker stop with timeout."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.wait.side_effect = subprocess.TimeoutExpired("cmd", 5)
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread_instance.is_alive.return_value = False
        mock_thread.return_value = mock_thread_instance

        # Start worker first
        communicator.start_worker("test_script.py")

        # Stop worker
        communicator.stop_worker()

        # Should kill process after timeout
        mock_process.kill.assert_called_once()

    def test_is_alive_not_running(self, communicator):
        """Test is_alive when worker not running."""
        communicator.running = False
        communicator.process = None

        assert communicator.is_alive() is False

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_is_alive_running(self, mock_thread, mock_popen, communicator):
        """Test is_alive when worker is running."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        communicator.start_worker("test_script.py")

        assert communicator.is_alive() is True

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_is_alive_process_terminated(self, mock_thread, mock_popen, communicator):
        """Test is_alive when process has terminated."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = 1  # Process terminated
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        communicator.start_worker("test_script.py")

        assert communicator.is_alive() is False

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_read_stderr_with_output(self, mock_thread, mock_popen, communicator):
        """Test _read_stderr method reads and logs stderr output."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()

        # Mock stderr with some output
        mock_stderr = MagicMock()
        mock_stderr.readline.side_effect = [
            "Error line 1\n",
            "Error line 2\n",
            "",  # Empty string signals end
        ]
        mock_process.stderr = mock_stderr
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # Start worker to trigger stderr thread
        communicator.start_worker("test_script.py")

        # Manually call _read_stderr to test it
        communicator._read_stderr()

        # Verify readline was called
        assert mock_stderr.readline.call_count >= 1

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_read_stderr_with_exception(self, mock_thread, mock_popen, communicator):
        """Test _read_stderr handles exceptions gracefully."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()

        # Mock stderr that raises exception
        mock_stderr = MagicMock()
        mock_stderr.readline.side_effect = Exception("Read error")
        mock_process.stderr = mock_stderr
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        communicator.start_worker("test_script.py")

        # Should not raise exception
        communicator._read_stderr()

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_read_stderr_no_process(self, mock_thread, mock_popen, communicator):
        """Test _read_stderr returns early when no process."""
        # Don't start worker, just call _read_stderr
        communicator._read_stderr()
        # Should return without error

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_read_responses_with_valid_json(self, mock_thread, mock_popen, communicator):
        """Test _read_responses processes valid JSON responses."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stderr = MagicMock()

        # Mock stdout with valid JSON responses
        mock_stdout = MagicMock()
        mock_stdout.readline.side_effect = [
            '{"status": "ok", "request_id": "test-123"}\n',
            "",  # Empty string signals end
        ]
        mock_process.stdout = mock_stdout
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # Create a response queue for the request
        communicator.response_queues["test-123"] = Queue()

        communicator.start_worker("test_script.py")

        # Manually call _read_responses
        communicator._read_responses()

        # Verify the response was queued
        assert not communicator.response_queues["test-123"].empty()

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_read_responses_with_empty_lines(self, mock_thread, mock_popen, communicator):
        """Test _read_responses skips empty lines."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stderr = MagicMock()

        # Mock stdout with empty lines
        mock_stdout = MagicMock()
        mock_stdout.readline.side_effect = [
            "\n",
            "   \n",
            '{"status": "ok", "request_id": "test-456"}\n',
            "",
        ]
        mock_process.stdout = mock_stdout
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        communicator.response_queues["test-456"] = Queue()
        communicator.start_worker("test_script.py")
        communicator._read_responses()

        assert not communicator.response_queues["test-456"].empty()

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_read_responses_with_invalid_json(self, mock_thread, mock_popen, communicator):
        """Test _read_responses handles invalid JSON gracefully."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stderr = MagicMock()

        # Mock stdout with invalid JSON
        mock_stdout = MagicMock()
        mock_stdout.readline.side_effect = [
            "not valid json\n",
            '{"incomplete": \n',
            "",
        ]
        mock_process.stdout = mock_stdout
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        communicator.start_worker("test_script.py")

        # Should not raise exception
        communicator._read_responses()

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_read_responses_without_request_id(self, mock_thread, mock_popen, communicator):
        """Test _read_responses handles responses without request_id."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stderr = MagicMock()

        # Mock stdout with response missing request_id
        mock_stdout = MagicMock()
        mock_stdout.readline.side_effect = [
            '{"status": "ok", "data": "test"}\n',
            "",
        ]
        mock_process.stdout = mock_stdout
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        communicator.start_worker("test_script.py")

        # Should log warning but not crash
        communicator._read_responses()

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_read_responses_unknown_request_id(self, mock_thread, mock_popen, communicator):
        """Test _read_responses handles unknown request_id."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stderr = MagicMock()

        # Mock stdout with unknown request_id
        mock_stdout = MagicMock()
        mock_stdout.readline.side_effect = [
            '{"status": "ok", "request_id": "unknown-999"}\n',
            "",
        ]
        mock_process.stdout = mock_stdout
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        communicator.start_worker("test_script.py")

        # Should log warning but not crash
        communicator._read_responses()

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_read_responses_with_exception(self, mock_thread, mock_popen, communicator):
        """Test _read_responses handles exceptions during reading."""
        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stderr = MagicMock()

        # Mock stdout that raises exception
        mock_stdout = MagicMock()
        mock_stdout.readline.side_effect = Exception("Read error")
        mock_process.stdout = mock_stdout
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        communicator.start_worker("test_script.py")

        # Should handle exception and set running to False
        communicator._read_responses()
        assert communicator.running is False

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    @patch("cpex.framework.isolated.venv_comm.Queue")
    def test_send_task_stdin_not_available(self, mock_queue_class, mock_thread, mock_popen, communicator):
        """Test send_task when stdin is not available."""
        task_data = {"task_type": "test"}

        mock_process = MagicMock()
        mock_process.stdin = None  # stdin not available
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        mock_queue_instance = MagicMock()
        mock_queue_class.return_value = mock_queue_instance

        communicator.start_worker("test_script.py")

        with pytest.raises(RuntimeError, match="Worker process stdin not available"):
            communicator.send_task("test_script.py", task_data)

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_stop_worker_send_shutdown_exception(self, mock_thread, mock_popen, communicator):
        """Test stop_worker handles exception when sending shutdown signal."""
        mock_process = MagicMock()
        mock_stdin = MagicMock()
        mock_stdin.write.side_effect = Exception("Write failed")
        mock_process.stdin = mock_stdin
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.wait.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread_instance.is_alive.return_value = False
        mock_thread.return_value = mock_thread_instance

        communicator.start_worker("test_script.py")

        # Should handle exception gracefully
        communicator.stop_worker()

        assert communicator.running is False
        assert communicator.process is None

    def test_del_method(self, communicator):
        """Test __del__ method calls stop_worker."""
        communicator.running = True
        communicator.process = MagicMock()

        # Call __del__ directly
        communicator.__del__()

        # Should have stopped the worker
        assert communicator.running is False

    def test_del_method_no_running_attribute(self):
        """Test __del__ handles missing running attribute."""
        # Create instance without proper initialization
        comm = object.__new__(VenvProcessCommunicator)

        # Should not raise exception
        comm.__del__()

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_send_task_exceeds_max_content_size(self, mock_thread, mock_popen, communicator):
        """Test send_task raises error when data exceeds max_content_size."""
        # Create a large task that will exceed the limit
        large_data = "x" * 5000
        task_data = {"task_type": "test", "data": large_data}

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        communicator.start_worker("test_script.py")

        # Set a very small max_content_size to trigger the error
        with pytest.raises(RuntimeError, match="task_data exceeds max_content_size"):
            communicator.send_task("test_script.py", task_data, max_content_size=100)

        # Verify the request_id was cleaned up from response_queues
        assert len(communicator.response_queues) == 0

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    @patch("uuid.uuid4")
    def test_send_task_at_max_content_size_boundary(self, mock_uuid, mock_thread, mock_popen, communicator):
        """Test send_task works when data is exactly at the limit."""
        # Use a fixed UUID to make size calculation predictable
        mock_uuid.return_value = Mock(hex="12345678123456781234567812345678")
        mock_uuid.return_value.__str__ = Mock(return_value="12345678-1234-5678-1234-567812345678")

        task_data = {"task_type": "test", "data": "small"}

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # Mock the Queue to return response
        with patch("cpex.framework.isolated.venv_comm.Queue") as mock_queue_class:
            mock_queue_instance = MagicMock()
            mock_queue_instance.get.return_value = {"status": "success", "result": "ok", "request_id": "test-id"}
            mock_queue_class.return_value = mock_queue_instance

            communicator.start_worker("test_script.py")

            # Calculate the exact size of the serialized data with the mocked UUID
            import orjson

            test_data_copy = task_data.copy()
            test_data_copy["request_id"] = "12345678-1234-5678-1234-567812345678"
            serialized_size = len(orjson.dumps(test_data_copy).decode())

            # Set max_content_size to exactly the serialized size
            result = communicator.send_task("test_script.py", task_data, max_content_size=serialized_size)

            assert result == {"status": "success", "result": "ok"}

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_send_task_with_custom_max_content_size(self, mock_thread, mock_popen, communicator):
        """Test send_task respects custom max_content_size parameter."""
        # Create task data that's moderately sized
        task_data = {"task_type": "test", "data": "x" * 1000, "metadata": {"key": "value"}}

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        with patch("cpex.framework.isolated.venv_comm.Queue") as mock_queue_class:
            mock_queue_instance = MagicMock()
            mock_queue_instance.get.return_value = {"status": "success", "result": "processed", "request_id": "test-id"}
            mock_queue_class.return_value = mock_queue_instance

            communicator.start_worker("test_script.py")

            # Should succeed with large max_content_size
            result = communicator.send_task("test_script.py", task_data, max_content_size=50000)
            assert result == {"status": "success", "result": "processed"}

            # Should fail with small max_content_size
            with pytest.raises(RuntimeError, match="task_data exceeds max_content_size"):
                communicator.send_task("test_script.py", task_data, max_content_size=500)

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_send_task_default_max_content_size(self, mock_thread, mock_popen, communicator):
        """Test send_task uses default max_content_size of 10MB."""
        # Create a task that's under 10MB
        task_data = {
            "task_type": "test",
            "data": "x" * 100000,  # 100KB
        }

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        with patch("cpex.framework.isolated.venv_comm.Queue") as mock_queue_class:
            mock_queue_instance = MagicMock()
            mock_queue_instance.get.return_value = {"status": "success", "result": "ok", "request_id": "test-id"}
            mock_queue_class.return_value = mock_queue_instance

            communicator.start_worker("test_script.py")

            # Should succeed with default max_content_size (10MB)
            result = communicator.send_task("test_script.py", task_data)
            assert result == {"status": "success", "result": "ok"}

    @patch("subprocess.Popen")
    @patch("threading.Thread")
    def test_send_task_very_large_data_exceeds_default_limit(self, mock_thread, mock_popen, communicator):
        """Test send_task fails when data exceeds default 10MB limit."""
        # Create a task that exceeds 10MB
        task_data = {
            "task_type": "test",
            "data": "x" * 11000000,  # ~11MB
        }

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        communicator.start_worker("test_script.py")

        # Should fail with default max_content_size
        with pytest.raises(RuntimeError, match="task_data exceeds max_content_size"):
            communicator.send_task("test_script.py", task_data)

        # Verify cleanup happened
        assert len(communicator.response_queues) == 0


# Made with Bob
