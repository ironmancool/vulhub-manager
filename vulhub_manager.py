#!/usr/bin/env python3
import os
import json
import yaml
import subprocess
import hashlib
import re
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from datetime import datetime

@dataclass
class VulhubEnvironment:
    """漏洞環境資料結構"""
    name: str
    path: str
    category: str
    cve: str
    services: List[str]
    ports: Dict[str, str]
    status: str
    has_readme: bool
    has_readme_zh: bool
    has_images: bool
    images: List[str]
    has_exploit: bool
    exploit_files: List[str]
    compose_hash: str
    last_checked: str

class VulhubManager:
    def __init__(self, vulhub_root: str):
        self.root = Path(vulhub_root)
        if not self.root.exists():
            raise ValueError(f"Vulhub path does not exist: {vulhub_root}")
        
        self.environments = []
        self.cache_file = Path.home() / '.vulhub_manager_cache.json'
        self.docker_compose_cmd = self._detect_docker_compose()
        
    def _detect_docker_compose(self) -> List[str]:
        """檢測可用的 docker-compose 命令"""
        commands = [
            ['docker', 'compose'],  # 新版本
            ['docker-compose']       # 舊版本
        ]
        
        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd + ['version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    print(f"使用 Docker Compose 命令: {' '.join(cmd)}")
                    return cmd
            except:
                continue
        
        print("警告：無法檢測 Docker Compose，默認使用 'docker compose'")
        return ['docker', 'compose']
        
    def scan(self, use_cache: bool = True) -> List[VulhubEnvironment]:
        """掃描所有環境"""
        if use_cache and self.cache_file.exists():
            cache_age = datetime.now().timestamp() - self.cache_file.stat().st_mtime
            if cache_age < 3600:  # 快取 1 小時
                return self._load_from_cache()
        
        self.environments = []
        compose_files = list(self.root.rglob('docker-compose.yml'))
        
        print(f"找到 {len(compose_files)} 個環境，開始掃描...")
        
        for i, compose_file in enumerate(compose_files, 1):
            if i % 50 == 0:
                print(f"已掃描 {i}/{len(compose_files)} 個環境...")
            
            try:
                env = self._parse_environment(compose_file)
                if env:
                    self.environments.append(env)
            except Exception as e:
                print(f"Error parsing {compose_file}: {e}")
        
        print(f"掃描完成，共找到 {len(self.environments)} 個有效環境")
        self._save_to_cache()
        return self.environments
    
    def _parse_environment(self, compose_path: Path) -> Optional[VulhubEnvironment]:
        """解析單個環境"""
        env_dir = compose_path.parent
        rel_path = env_dir.relative_to(self.root)
        parts = rel_path.parts
        
        parts = rel_path.parts
        if len(parts) == 0:
            return None
        
        # 在路徑各段尋找 CVE
        cve_regex = re.compile(r'(?i)^(CVE-\d{4}-\d{4,7})')
        cve = None
        cve_idx = None
        for idx, seg in enumerate(parts):
            m = cve_regex.match(seg)
            if m:
                cve = m.group(1).upper()
                cve_idx = idx
                break
        
        if cve_idx is not None:
            # 分類 = CVE 前一段（就近父層）
            category = parts[cve_idx - 1] if cve_idx > 0 else parts[0]
        else:
            # 沒有 CVE：分類取就近父層、cve 以末段描述以示區分
            category = parts[-2] if len(parts) >= 2 else parts[0]
            cve = parts[-1] if len(parts) >= 1 else 'unknown'
        
        # 用完整相對路徑當唯一識別（避免多個環境同名）
        name = str(rel_path).replace('\\', '/')
        
        # 解析 docker-compose.yml
        try:
            with open(compose_path, 'r', encoding='utf-8') as f:
                compose_content = f.read()
                compose_config = yaml.safe_load(compose_content)
                compose_hash = hashlib.md5(compose_content.encode()).hexdigest()
        except Exception as e:
            print(f"無法解析 {compose_path}: {e}")
            return None
        
        # 檢查檔案
        readme_en = env_dir / 'README.md'
        readme_zh = env_dir / 'README.zh-cn.md'
        
        # 找出所有圖片（優化：限制數量）
        images = []
        for pattern in ['*.png', '*.jpg', '*.jpeg', '*.gif']:
            found_images = list(env_dir.glob(pattern))[:3]  # 最多3張圖
            images.extend([f.name for f in found_images])
        
        # 找出所有 exploit 檔案
        exploit_files = []
        for py_file in env_dir.glob('*.py'):
            filename = py_file.name.lower()
            if any(keyword in filename for keyword in ['exploit', 'poc', 'cve', 'exp']):
                exploit_files.append(py_file.name)
        
        services = list(compose_config.get('services', {}).keys())
        ports = self._extract_ports(compose_config)
        
        # 不在掃描時檢查狀態（提升性能）
        status = 'unknown'
        
        return VulhubEnvironment(
            name=name,
            path=str(env_dir),
            category=category,
            cve=cve,
            services=services,
            ports=ports,
            status=status,
            has_readme=readme_en.exists(),
            has_readme_zh=readme_zh.exists(),
            has_images=len(images) > 0,
            images=sorted(images),
            has_exploit=len(exploit_files) > 0,
            exploit_files=sorted(exploit_files),
            compose_hash=compose_hash,
            last_checked=datetime.now().isoformat()
        )
    
    def _extract_ports(self, config: dict) -> Dict[str, str]:
        """提取端口映射"""
        ports = {}
        for service_name, service in config.get('services', {}).items():
            if 'ports' in service:
                for port_mapping in service['ports']:
                    if ':' in str(port_mapping):
                        parts = str(port_mapping).split(':')
                        host_port = parts[0]
                        container_port = parts[1].split('/')[0]
                        ports[service_name] = host_port
                        break  # 只取第一個端口
        return ports
    
    def _check_status(self, env_path: Path) -> str:
        """檢查環境狀態"""
        try:
            result = subprocess.run(
                self.docker_compose_cmd + ['ps', '-q'],
                cwd=env_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            return 'running' if result.stdout.strip() else 'stopped'
        except:
            return 'unknown'
    
    def check_single_status(self, env_name: str) -> str:
        """檢查單個環境的狀態"""
        env = self.get_environment(env_name)
        if env:
            status = self._check_status(Path(env.path))
            env.status = status
            return status
        return 'unknown'
    
    def _save_to_cache(self):
        """保存到快取"""
        cache_data = [asdict(env) for env in self.environments]
        with open(self.cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)
    
    def _load_from_cache(self) -> List[VulhubEnvironment]:
        """從快取載入"""
        print("從快取載入環境資料...")
        
        with open(self.cache_file, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)
        
        self.environments = []
        for data in cache_data:
            self.environments.append(VulhubEnvironment(**data))
        
        print(f"從快取載入了 {len(self.environments)} 個環境")
        
        # 批量檢查運行中的環境狀態（優化性能）
        self._batch_check_status()
        
        return self.environments
    
    def _batch_check_status(self):
        """批量檢查環境狀態（只檢查可能運行的）"""
        print("檢查環境狀態...")
        
        # 先獲取所有運行中的容器
        try:
            result = subprocess.run(
                ['docker', 'ps', '--format', '{{.Labels}}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            running_projects = set()
            for line in result.stdout.splitlines():
                if 'com.docker.compose.project.working_dir=' in line:
                    # 提取項目路徑
                    parts = line.split('com.docker.compose.project.working_dir=')
                    if len(parts) > 1:
                        path = parts[1].split(',')[0]
                        running_projects.add(path)
            
            # 更新狀態
            for env in self.environments:
                if env.path in running_projects:
                    env.status = 'running'
                else:
                    env.status = 'stopped'
        except:
            # 如果批量檢查失敗，所有環境標記為 unknown
            for env in self.environments:
                env.status = 'unknown'
    
    def get_environment(self, name: str) -> Optional[VulhubEnvironment]:
        """獲取特定環境"""
        return next((env for env in self.environments if env.name == name), None)