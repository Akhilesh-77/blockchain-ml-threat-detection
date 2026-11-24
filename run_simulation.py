"""
CyberNex — Orchestration Runner
Launches both the FastAPI backend and Next.js frontend in synchronized development mode.
"""

import os
import sys
import subprocess
import time
import signal

def print_banner():
    banner = r"""
   ______      __              _   __          
  / ____/_  __/ /_  ___  _____/ | / /__  _  __
 / /   / / / / __ \/ _ \/ ___/  |/ / _ \| |/_/
/ /___/ /_/ / /_/ /  __/ /  / /|  /  __/>  <  
\____/\__, /_.___/\___/_/  /_/ |_/\___/_/|_|  
     /____/                                   

  Intelligent Cybersecurity Monitoring
  AI-Powered Threat Detection with Blockchain-Audited Security Intelligence
================================================================================
"""
    print(banner)

def main():
    print_banner()
    root_dir = os.path.dirname(os.path.abspath(__file__))
    frontend_dir = os.path.join(root_dir, "frontend")

    print("[*] Checking Python environment...")
    python_exe = sys.executable
    print(f"    Python: {python_exe}")

    # Check database initialization
    db_file = os.path.join(root_dir, "cyber_nex.db")
    print(f"[*] Database file: {db_file}")

    print("\n[*] Starting CyberNex Services:")
    print("    -> Backend:  http://127.0.0.1:8000 (Docs: http://127.0.0.1:8000/docs)")
    print("    -> Frontend: http://localhost:3000")
    print("\n[!] Press Ctrl+C at any time to gracefully shut down both services.\n")

    processes = []
    try:
        # Start backend
        backend_cmd = [
            python_exe, "-m", "uvicorn", "backend.main:app",
            "--host", "127.0.0.1",
            "--port", "8000",
            "--reload"
        ]
        p_backend = subprocess.Popen(backend_cmd, cwd=root_dir)
        processes.append(("Backend", p_backend))

        # Start frontend
        # On Windows, npm is npm.cmd
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        p_frontend = subprocess.Popen([npm_cmd, "run", "dev"], cwd=frontend_dir)
        processes.append(("Frontend", p_frontend))

        # Monitor processes
        while True:
            for name, proc in processes:
                ret = proc.poll()
                if ret is not None:
                    print(f"[!] {name} process exited with code {ret}")
                    return
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Shutting down CyberNex services...")
    finally:
        for name, proc in processes:
            print(f"[*] Terminating {name}...")
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        print("[*] All services stopped cleanly.")

if __name__ == "__main__":
    main()

