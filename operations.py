# operations.py
# 極小變更版：補齊 check_images / pull_images_stream / wait_ready，並保留 start/stop
# 只做可靠的最少功能，不入侵 app.py 的其他行為

from __future__ import annotations
import os
import subprocess
import json
import time
import re
from pathlib import Path
from typing import Tuple, Dict, Any, List

try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
except Exception:
    urlopen = None

# 與 app.py 一致的根目錄（用你的 VULHUB_PATH）
VULHUB_PATH = Path(os.environ.get('VULHUB_PATH', './vulhub')).resolve()


class VulhubOperations:
    def __init__(self):
        self.compose_cmd = self._detect_compose_cmd()

    # ===== 公開 API =====

    def start(self, name: str) -> Tuple[bool, Dict[str, Any]]:
        env_dir = self._env_dir(name)
        if not env_dir:
            return False, {"error": f"找不到環境：{name}"}

        ok, out, err = self._run(self._cmd(['up', '-d']), cwd=env_dir)
        if not ok:
            info = {"error": (err.strip() or out.strip() or "啟動失敗")}
            if 'address already in use' in err.lower() or 'port is already allocated' in err.lower():
                info['port_conflict'] = True
            return False, info
        return True, {}

    def stop(self, name: str) -> Tuple[bool, Dict[str, Any]]:
        env_dir = self._env_dir(name)
        if not env_dir:
            return False, {"error": f"找不到環境：{name}"}
        ok, out, err = self._run(self._cmd(['down']), cwd=env_dir)
        if not ok:
            return False, {"error": (err.strip() or out.strip() or "停止失敗")}
        return True, {}

    def check_images(self, name: str) -> Tuple[bool, Dict[str, Any]]:
        """
        使用 `docker compose config --images` 取得所需 image。
        回傳 (True, {"missing": [...]})；True 代表 API 正常，不代表不缺。
        """
        env_dir = self._env_dir(name)
        if not env_dir:
            return True, {"missing": [], "warning": f"找不到環境：{name}（略過檢查）"}

        ok, out, _ = self._run(self._cmd(['config', '--images']), cwd=env_dir)
        images: List[str]
        if ok:
            images = [ln.strip() for ln in out.splitlines() if ln.strip()]
        else:
            images = self._fallback_parse_images(env_dir)

        missing: List[str] = []
        for img in images:
            ok2, _, _ = self._run(['docker', 'image', 'inspect', img])
            if not ok2:
                missing.append(img)

        return True, {"missing": missing}

    def pull_images_stream(self, name: str):
        """
        逐行輸出 `docker compose pull` 給 SSE。
        """
        env_dir = self._env_dir(name)
        if not env_dir:
            yield "[Error] 找不到環境"
            return

        cmd = self._cmd(['pull'])
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(env_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
        except FileNotFoundError:
            yield "[Error] 找不到 docker 指令，請確認已安裝 Docker 並在 PATH 中。"
            return

        if proc.stdout:
            for line in proc.stdout:
                yield line.rstrip('\n')
        proc.wait()

    def wait_ready(self, name: str, timeout: int = 20) -> Tuple[bool, Dict[str, Any]]:
        """
        在 timeout 內嘗試連到第一個對外的 host port；連上就回 ready=True。
        """
        if urlopen is None:
            return True, {"ready": False}

        env_dir = self._env_dir(name)
        if not env_dir:
            return True, {"ready": False}

        deadline = time.time() + max(1, int(timeout))
        chosen_port = None

        while time.time() < deadline:
            ports = self._pick_host_ports(env_dir)
            if ports:
                chosen_port = ports[0]
                for scheme in ('http', 'https'):
                    try:
                        req = Request(f"{scheme}://127.0.0.1:{chosen_port}", headers={'User-Agent': 'curl/8'})
                        with urlopen(req, timeout=2) as resp:
                            if 200 <= getattr(resp, 'status', 200) < 400:
                                return True, {"ready": True, "port": chosen_port}
                            return True, {"ready": True, "port": chosen_port}
                    except (URLError, HTTPError, Exception):
                        pass
            time.sleep(1.0)

        if chosen_port:
            return True, {"ready": False, "port": chosen_port}
        return True, {"ready": False}

    # ===== 私有工具 =====

    def _detect_compose_cmd(self) -> List[str]:
        ok, _, _ = self._run(['docker', 'compose', 'version'])
        if ok:
            return ['docker', 'compose']
        ok, _, _ = self._run(['docker-compose', 'version'])
        if ok:
            return ['docker-compose']
        return ['docker', 'compose']

    def _cmd(self, args: List[str]) -> List[str]:
        return self.compose_cmd + args

    def _env_dir(self, name: str) -> Path | None:
        if not name:
            return None
        p = (VULHUB_PATH / name).resolve()
        try:
            if VULHUB_PATH not in p.parents and p != VULHUB_PATH:
                return None
        except Exception:
            return None
        if not p.exists() or not (p / 'docker-compose.yml').exists():
            return None
        return p

    def _run(self, args: List[str], cwd: Path | None = None) -> Tuple[bool, str, str]:
        try:
            result = subprocess.run(
                args,
                cwd=str(cwd) if cwd else None,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.returncode == 0, result.stdout, result.stderr
        except FileNotFoundError as e:
            return False, "", str(e)
        except Exception as e:
            return False, "", str(e)

    def _fallback_parse_images(self, env_dir: Path) -> List[str]:
        images: List[str] = []
        compose_path = env_dir / 'docker-compose.yml'
        try:
            for ln in compose_path.read_text(encoding='utf-8', errors='ignore').splitlines():
                m = re.search(r'^\s*image\s*:\s*([^\s#]+)', ln)
                if m:
                    images.append(m.group(1).strip())
        except Exception:
            pass
        seen = set()
        uniq = []
        for x in images:
            if x not in seen:
                seen.add(x)
                uniq.append(x)
        return uniq

    def _pick_host_ports(self, env_dir: Path) -> List[int]:
        ok, out, _ = self._run(self._cmd(['ps', '--format', 'json']), cwd=env_dir)
        ports: List[int] = []
        if ok:
            try:
                lines = [json.loads(x) for x in out.splitlines() if x.strip()]
                for obj in lines:
                    pstr = obj.get('Ports') or ''
                    for hp in self._parse_ports_string(pstr):
                        if hp not in ports:
                            ports.append(hp)
            except Exception:
                pass
        return ports

    def _parse_ports_string(self, s: str) -> List[int]:
        host_ports: List[int] = []
        for part in s.split(','):
            m = re.search(r':(\d+)->\d+/(tcp|udp)', part)
            if m:
                try:
                    host_ports.append(int(m.group(1)))
                except Exception:
                    pass
        return host_ports
