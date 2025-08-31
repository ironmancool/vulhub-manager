#!/usr/bin/env python3
# coding: utf-8
from flask import Flask, render_template, jsonify, request
from pathlib import Path
import markdown
import base64
import os
import subprocess
import shlex
import json
import time
import hashlib

# 這兩個還是保留；operations 仍用你現有的邏輯啟停容器
try:
    from vulhub_manager import VulhubManager
except Exception:
    VulhubManager = None

from operations import VulhubOperations

app = Flask(__name__)

# === 基本設定 ===
VULHUB_PATH = Path(os.environ.get('VULHUB_PATH', './vulhub')).resolve()
CACHE_FILE = Path.home() / '.vulhub_manager_cache.json'  # 持久化快取檔案
CACHE_TTL_MS = 24 * 60 * 60 * 1000  # 快取有效期：24 小時

if VulhubManager:
    try:
        manager = VulhubManager(str(VULHUB_PATH))
    except Exception:
        manager = None
else:
    manager = None

ops = VulhubOperations()

# 內部快取（避免每次都跑全掃）
_env_cache = {
    "data": None,     # list[dict]
    "ts": 0           # epoch ms
}

# 可用時嘗試載入 PyYAML 解析 compose
try:
    import yaml
except Exception:
    yaml = None


# ====== 小工具 ======

def _now_ms():
    return int(time.time() * 1000)


def _read_text(p: Path):
    try:
        return p.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ''


def _calculate_vulhub_hash():
    """計算 Vulhub 目錄的簡單雜湊值，用於判斷是否有變化"""
    try:
        # 只計算 docker-compose.yml 檔案的數量和路徑
        compose_files = list(VULHUB_PATH.rglob('docker-compose.yml'))
        paths_str = ''.join(sorted([str(f.relative_to(VULHUB_PATH)) for f in compose_files]))
        return hashlib.md5(paths_str.encode()).hexdigest()
    except Exception:
        return None


def _load_persistent_cache():
    """從檔案載入持久化快取"""
    try:
        if CACHE_FILE.exists():
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
                
            # 檢查快取是否過期
            cache_ts = cache_data.get('timestamp', 0)
            if _now_ms() - cache_ts > CACHE_TTL_MS:
                print("快取已過期，需要重新掃描")
                return None
                
            # 檢查 Vulhub 目錄是否有變化
            saved_hash = cache_data.get('vulhub_hash')
            current_hash = _calculate_vulhub_hash()
            if saved_hash != current_hash:
                print("偵測到 Vulhub 目錄有變化，需要重新掃描")
                return None
                
            print(f"從持久化快取載入 {len(cache_data.get('environments', []))} 個環境")
            return cache_data.get('environments', [])
    except Exception as e:
        print(f"載入快取失敗: {e}")
    return None


def _save_persistent_cache(environments):
    """保存持久化快取到檔案"""
    try:
        cache_data = {
            'environments': environments,
            'timestamp': _now_ms(),
            'vulhub_hash': _calculate_vulhub_hash(),
            'vulhub_path': str(VULHUB_PATH)
        }
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)
        print(f"已保存 {len(environments)} 個環境到持久化快取")
    except Exception as e:
        print(f"保存快取失敗: {e}")


def _compose_parse_services_ports(compose_path: Path):
    """
    嘗試從 docker-compose.yml 解析 service 名稱與 host 端口（若沒裝 PyYAML 就回空）
    回傳: (services: list[str], ports_map: dict[str, str])
    """
    services, ports_map = [], {}
    if not compose_path.exists():
        return services, ports_map

    if yaml:
        try:
            data = yaml.safe_load(_read_text(compose_path)) or {}
            svcs = data.get('services') or {}
            for svc_name, svc_cfg in svcs.items():
                services.append(str(svc_name))
                port_list = svc_cfg.get('ports') or []
                host_ports = []
                for item in port_list:
                    # 可能是 "8080:80" 或 "127.0.0.1:8080:80" 或 dict
                    if isinstance(item, str):
                        # 取最左邊 host port（冒號前一段最後的數字）
                        parts = item.split(':')
                        if len(parts) >= 2:
                            # 127.0.0.1:8080:80 -> 取 -2 位置
                            try:
                                host_ports.append(str(int(parts[-2])))
                            except Exception:
                                # "8080:80" -> 取 -2 仍是 8080；若格式怪就忽略
                                pass
                        else:
                            # "8080" 這種，不太常見，直接塞
                            host_ports.append(parts[0])
                    elif isinstance(item, dict):
                        # {"target": 80, "published": 8080, "mode": "host", "protocol": "tcp"}
                        hp = item.get('published')
                        if hp:
                            host_ports.append(str(hp))
                if host_ports:
                    # 取第一個 host port 當代表
                    ports_map[svc_name] = host_ports[0]
        except Exception:
            pass

    return services, ports_map


def _has_exploit(env_dir: Path):
    # 粗略偵測：有 exploit/ 或 poc/ 目錄、或常見檔名
    for sub in ['exploit', 'exploits', 'poc', 'pocs']:
        if (env_dir / sub).exists():
            return True
    for pat in ['*exploit*.py', '*exploit*.sh', 'poc.py', 'poc.sh', 'exp.py', 'PoC.py']:
        if list(env_dir.glob(pat)):
            return True
    return False


def _image_files(env_dir: Path):
    exts = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg'}
    # 只拿目錄內第一層圖片（避免掃爆）
    return [p for p in env_dir.iterdir() if p.is_file() and p.suffix.lower() in exts]


def _check_docker_images_exist(compose_path: Path):
    """
    檢查 docker-compose.yml 中定義的映像是否已存在本地
    """
    images_to_check = []
    
    if yaml and compose_path.exists():
        try:
            data = yaml.safe_load(_read_text(compose_path)) or {}
            svcs = data.get('services') or {}
            for svc_name, svc_cfg in svcs.items():
                if 'image' in svc_cfg:
                    images_to_check.append(svc_cfg['image'])
        except Exception:
            pass
    
    # 如果無法解析 YAML，嘗試用正則表達式
    if not images_to_check:
        try:
            content = _read_text(compose_path)
            import re
            # 匹配 image: xxx 格式
            images = re.findall(r'^\s*image:\s*([^\s#]+)', content, re.MULTILINE)
            images_to_check = images
        except Exception:
            pass
    
    if not images_to_check:
        return False
    
    # 檢查所有映像是否存在
    all_exist = True
    for image in images_to_check:
        try:
            result = subprocess.run(
                ['docker', 'image', 'inspect', image],
                capture_output=True,
                timeout=2
            )
            if result.returncode != 0:
                all_exist = False
                break
        except Exception:
            all_exist = False
            break
    
    return all_exist


def _scan_environments_fs():
    """
    檔案系統掃描：尋找所有包含 docker-compose.yml 的資料夾
    產出前端需要的扁平資料
    """
    if not VULHUB_PATH.exists():
        raise FileNotFoundError(f"Vulhub path does not exist: {VULHUB_PATH}")

    envs = []
    compose_files = list(VULHUB_PATH.rglob('docker-compose.yml'))
    total = len(compose_files)
    print(f"找到 {total} 個環境，開始掃描...")

    for i, compose_path in enumerate(compose_files, 1):
        env_dir = compose_path.parent
        rel = env_dir.relative_to(VULHUB_PATH).as_posix()  # e.g. "nexus/CVE-2020-10199"
        parts = rel.split('/')
        category = parts[0] if parts else 'unknown'
        cve = parts[-1] if parts else 'unknown'

        services, ports_map = _compose_parse_services_ports(compose_path)
        has_readme = (env_dir / 'README.md').exists()
        has_readme_zh = (env_dir / 'README.zh-cn.md').exists() or (env_dir / 'README_zh.md').exists()
        imgs = _image_files(env_dir)
        
        # 檢查 Docker 映像是否已存在
        has_docker_images = _check_docker_images_exist(compose_path)

        envs.append({
            "name": rel,
            "category": category,
            "cve": cve,
            "status": "unknown",              # 由前端啟/停後更新
            "ports": ports_map,               # 盡量解析；失敗就空 dict
            "services": services,             # 盡量解析；失敗就空 list
            "has_exploit": _has_exploit(env_dir),
            "has_images": bool(imgs),
            "has_readme": has_readme,
            "has_readme_zh": has_readme_zh,
            "has_docker_images": has_docker_images,  # 新增：是否已有 Docker 映像
        })

        if i % 50 == 0 or i == total:
            print(f"已掃描 {i}/{total} 個環境...")

    envs.sort(key=lambda x: x["name"])
    print(f"掃描完成，共找到 {len(envs)} 個有效環境")
    return envs


def _get_env_dir_by_name(name: str) -> Path:
    # name 形如 "nexus/CVE-2020-10199"
    p = (VULHUB_PATH / name).resolve()
    # 防止越權
    if VULHUB_PATH not in p.parents and p != VULHUB_PATH:
        raise FileNotFoundError("Invalid env path")
    return p


def _get_exploit_files(env_dir: Path):
    """獲取 exploit 檔案列表"""
    exploit_files = []
    
    # 檢查 exploit 目錄
    for sub in ['exploit', 'exploits', 'poc', 'pocs']:
        sub_dir = env_dir / sub
        if sub_dir.exists() and sub_dir.is_dir():
            for f in sub_dir.iterdir():
                if f.is_file() and f.suffix in ['.py', '.sh', '.rb', '.go', '.c', '.cpp']:
                    exploit_files.append(f)
    
    # 檢查根目錄的 exploit 檔案
    for pattern in ['*exploit*.py', '*exploit*.sh', 'poc.py', 'poc.sh', 'exp.py', 'PoC.py']:
        for f in env_dir.glob(pattern):
            if f.is_file():
                exploit_files.append(f)
    
    return exploit_files


# ====== Pages ======
@app.route('/')
def index():
    return render_template('index.html')


# ====== APIs ======

@app.route('/api/scan')
def api_scan():
    """
    掃描 vulhub 目錄
    ?cache=true 使用記憶體快取（預設）
    ?cache=false 強制重新掃描
    """
    use_cache = request.args.get('cache', 'true').lower() == 'true'

    # 優先使用記憶體快取
    if use_cache and _env_cache["data"]:
        return jsonify(_env_cache["data"])

    # 嘗試從持久化快取載入
    if use_cache:
        cached_envs = _load_persistent_cache()
        if cached_envs:
            _env_cache["data"] = cached_envs
            _env_cache["ts"] = _now_ms()
            return jsonify(cached_envs)

    # 需要重新掃描
    print("執行完整掃描...")
    
    # 若你的 VulhubManager 有類似 .environments 可用，就先像它
    envs = None
    if manager is not None and hasattr(manager, 'environments'):
        try:
            envs = manager.environments
        except Exception:
            envs = None

    # envs 不是 list 就改用檔案系統掃描
    if not isinstance(envs, list) or not envs:
        envs = _scan_environments_fs()

    # 標準化輸出結構
    out = []
    for e in envs:
        # 如果是我自己掃描的，就已經是 dict；若是自訂物件，盡量抽取
        if isinstance(e, dict):
            out.append({
                "name": e.get("name"),
                "category": e.get("category"),
                "cve": e.get("cve"),
                "status": e.get("status", "unknown"),
                "ports": e.get("ports") or {},
                "services": e.get("services") or [],
                "has_exploit": bool(e.get("has_exploit")),
                "has_images": bool(e.get("has_images")),
                "has_readme": bool(e.get("has_readme")),
                "has_readme_zh": bool(e.get("has_readme_zh")),
                "has_docker_images": bool(e.get("has_docker_images", False)),
            })
        else:
            # 盡最大努力從物件取出欄位
            name = getattr(e, 'name', None) or getattr(e, 'path', None)
            if name and isinstance(name, str) and name.startswith(str(VULHUB_PATH)):
                rel = Path(name).resolve().relative_to(VULHUB_PATH).as_posix()
            else:
                rel = name
            category = getattr(e, 'category', None)
            cve = getattr(e, 'cve', None)
            status = getattr(e, 'status', 'unknown')
            ports = getattr(e, 'ports', {}) or {}
            services = getattr(e, 'services', []) or []
            has_exploit = bool(getattr(e, 'has_exploit', False))
            images = getattr(e, 'images', []) or []
            has_images = bool(images)
            has_readme = bool(getattr(e, 'has_readme', False))
            has_readme_zh = bool(getattr(e, 'has_readme_zh', False))
            has_docker_images = bool(getattr(e, 'has_docker_images', False))

            if (not category or not cve) and isinstance(rel, str):
                parts = rel.split('/')
                if not category and parts:
                    category = parts[0]
                if not cve and parts:
                    cve = parts[-1]

            out.append({
                "name": rel,
                "category": category or 'unknown',
                "cve": cve or 'unknown',
                "status": status or 'unknown',
                "ports": ports,
                "services": services,
                "has_exploit": has_exploit,
                "has_images": has_images,
                "has_readme": has_readme,
                "has_readme_zh": has_readme_zh,
                "has_docker_images": has_docker_images,
            })

    # 更新記憶體快取
    _env_cache["data"] = out
    _env_cache["ts"] = _now_ms()
    
    # 保存到持久化快取
    _save_persistent_cache(out)
    
    return jsonify(out)


@app.route('/api/stats')
def api_stats():
    data = _env_cache["data"] or []
    total = len(data)
    running = sum(1 for x in data if x.get("status") == "running")
    with_exploit = sum(1 for x in data if x.get("has_exploit"))
    with_images = sum(1 for x in data if x.get("has_docker_images"))
    cats = {}
    for x in data:
        cats[x["category"]] = cats.get(x["category"], 0) + 1
    return jsonify({
        "total": total,
        "running": running,
        "with_exploit": with_exploit,
        "with_images": with_images,
        "categories": cats
    })


@app.route('/api/env/<path:name>')
def api_env_detail(name: str):
    """
    取得單一環境細節（compose、images 列表等）
    不依賴 manager.get_environment；直接從檔案系統讀
    """
    try:
        env_dir = _get_env_dir_by_name(name)
    except Exception:
        return jsonify({"error": "not found"}), 404

    compose_path = env_dir / 'docker-compose.yml'
    compose_text = _read_text(compose_path)

    # 附圖（最多 5 張，<5MB）
    images_data = []
    for img_path in _image_files(env_dir)[:5]:
        try:
            if img_path.stat().st_size < 5 * 1024 * 1024:
                with open(img_path, 'rb') as f:
                    b64 = base64.b64encode(f.read()).decode()
                ext = (img_path.suffix or ".png")[1:].lower()
                images_data.append({
                    "name": img_path.name,
                    "data": f"data:image/{ext};base64,{b64}"
                })
        except Exception:
            pass

    # 粗略列出可能的 exploit 檔名
    exploit_files = [f.name for f in _get_exploit_files(env_dir)]

    parts = name.split('/')
    category = parts[0] if parts else 'unknown'
    cve = parts[-1] if parts else 'unknown'

    return jsonify({
        "name": name,
        "category": category,
        "cve": cve,
        "compose": compose_text,
        "images": images_data,
        "exploit_files": exploit_files
    })


@app.route('/api/readme/<path:name>')
def api_readme(name: str):
    """
    把 README 轉成 HTML 回傳（優先顯示中文版）
    """
    try:
        env_dir = _get_env_dir_by_name(name)
    except Exception:
        return jsonify({"html": ""})

    md_path = None
    # 優先中文版，然後才是英文版
    for cand in ['README.zh-cn.md', 'README.zh-CN.md', 'README_zh.md', 'README.md', 'README.MD']:
        p = env_dir / cand
        if p.exists():
            md_path = p
            break

    md_text = _read_text(md_path) if md_path else ""
    html = markdown.markdown(md_text, extensions=['extra', 'tables', 'fenced_code']) if md_text else ""
    return jsonify({"html": html})


@app.route('/api/exploit/<path:name>')
def api_exploit(name: str):
    """
    獲取 exploit 檔案內容
    """
    try:
        env_dir = _get_env_dir_by_name(name)
    except Exception:
        return jsonify([]), 404

    exploits = []
    for exploit_path in _get_exploit_files(env_dir):
        try:
            content = _read_text(exploit_path)
            if content:
                # 嘗試提取使用說明（從註釋中）
                usage = ""
                lines = content.splitlines()
                for line in lines[:20]:  # 只看前20行
                    if 'usage:' in line.lower() or 'example:' in line.lower():
                        usage = line
                        break
                
                exploits.append({
                    "filename": exploit_path.name,
                    "path": str(exploit_path.relative_to(env_dir)),
                    "content": content[:10000],  # 限制大小
                    "size": len(content),
                    "lines": len(lines),
                    "usage": usage
                })
        except Exception:
            pass

    return jsonify(exploits)


@app.route('/api/start', methods=['POST'])
def api_start():
    data = request.get_json(force=True)
    name = data.get('name')
    ok, info = ops.start(name)
    # 啟動成功後，更新快取中的 status
    if ok and _env_cache["data"]:
        for e in _env_cache["data"]:
            if e.get("name") == name:
                e["status"] = "running"
                break
    return jsonify({"success": ok, **(info or {})})


@app.route('/api/stop', methods=['POST'])
def api_stop():
    data = request.get_json(force=True)
    name = data.get('name')
    ok, info = ops.stop(name)
    if ok and _env_cache["data"]:
        for e in _env_cache["data"]:
            if e.get("name") == name:
                e["status"] = "stopped"
                break
    return jsonify({"success": ok, **(info or {})})


@app.route('/api/check-images')
def api_check_images():
    name = request.args.get('name', '')
    ok, info = ops.check_images(name)
    return jsonify({"success": ok, **(info or {})})


@app.route('/api/pull-stream')
def api_pull_stream():
    """
    SSE：拉取缺少的 images；由前端 /api/pull-stream 使用 EventSource 讀取
    """
    name = request.args.get('name', '')

    def gen():
        for line in ops.pull_images_stream(name):
            yield f"event: log\ndata: {line}\n\n"
        yield "event: done\ndata: ok\n\n"

    return app.response_class(gen(), mimetype='text/event-stream')


@app.route('/api/wait-ready')
def api_wait_ready():
    """
    等 web 服務可用（避免剛起來就打開 404）
    """
    name = request.args.get('name', '')
    timeout = int(request.args.get('timeout', '20'))
    ok, info = ops.wait_ready(name, timeout=timeout)
    return jsonify({"success": ok, **(info or {})})


# === /api/running：列出目前運行中的容器 ===
@app.route('/api/running')
def api_running():
    try:
        cmd = "docker ps --format {{json .}}"
        result = subprocess.run(
            shlex.split(cmd),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        containers = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                obj = {}
            containers.append({
                "id": (obj.get("ID") or "")[:12],
                "name": obj.get("Names") or "",
                "image": obj.get("Image") or "",
                "status": obj.get("Status") or "",
                "ports": obj.get("Ports") or ""
            })

        return jsonify({"success": True, "containers": containers})
    except subprocess.CalledProcessError as e:
        return jsonify({
            "success": False,
            "error": f"docker ps 失敗：{e.stderr.strip() or e.stdout.strip()}"
        }), 500
    except FileNotFoundError:
        return jsonify({
            "success": False,
            "error": "找不到 docker 指令，請確認已安裝 Docker 並在 PATH 中。"
        }), 500


@app.route('/api/refresh-cache', methods=['POST'])
def api_refresh_cache():
    """強制清除並重建快取"""
    try:
        # 清除記憶體快取
        _env_cache["data"] = None
        _env_cache["ts"] = 0
        
        # 刪除持久化快取檔案
        if CACHE_FILE.exists():
            CACHE_FILE.unlink()
            print("已刪除持久化快取檔案")
        
        # 重新掃描
        print("強制重新掃描所有環境...")
        envs = _scan_environments_fs()
        
        # 標準化輸出
        out = []
        for e in envs:
            out.append({
                "name": e.get("name"),
                "category": e.get("category"),
                "cve": e.get("cve"),
                "status": e.get("status", "unknown"),
                "ports": e.get("ports") or {},
                "services": e.get("services") or [],
                "has_exploit": bool(e.get("has_exploit")),
                "has_images": bool(e.get("has_images")),
                "has_readme": bool(e.get("has_readme")),
                "has_readme_zh": bool(e.get("has_readme_zh")),
                "has_docker_images": bool(e.get("has_docker_images", False)),
            })
        
        # 更新快取
        _env_cache["data"] = out
        _env_cache["ts"] = _now_ms()
        _save_persistent_cache(out)
        
        return jsonify({"success": True, "count": len(out)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == '__main__':
    # 啟動時嘗試載入持久化快取
    print(f"Vulhub 路徑: {VULHUB_PATH}")
    print(f"快取檔案: {CACHE_FILE}")
    
    cached_data = _load_persistent_cache()
    if cached_data:
        _env_cache["data"] = cached_data
        _env_cache["ts"] = _now_ms()
        print(f"成功載入持久化快取，共 {len(cached_data)} 個環境")
    else:
        print("未找到有效快取，將在首次請求時掃描")
    
    print(f"使用 Docker Compose 指令: docker compose")
    app.run(debug=True, host='0.0.0.0', port=5000)