import requests
from requests.auth import HTTPBasicAuth
import os
import platform
import sys
import json
import docker
import docker.errors
import threading
import argparse
import shutil
import random
import re
import time

log_mutex = threading.Lock()
def log(message):
    with log_mutex:
        print(message)

def load_config(path):
    with open(path, "rb") as f:
        return json.load(f)

def build_image(**kwargs):
    api = dc.api
    stream = api.build(**kwargs)
    if isinstance(stream, str):
        return dc.images.get(stream)
    last_event = None
    image_id = None
    for chunk in stream:
        chunk = json.loads(chunk.decode("utf-8", errors="ignore"))
        if "error" in chunk:
            raise docker.errors.BuildError(chunk["error"].strip(), "")
        if "stream" in chunk:
            line = chunk["stream"].strip()
            log(line)
            match = re.search(r"(^Successfully built |sha256:)([0-9a-f]+)$", line)
            if match:
                image_id = match.group(2)
        last_event = chunk
    if image_id:
        return dc.images.get(image_id)
    raise docker.errors.BuildError(last_event or "Unknown", "")

def retry_get(url, **kwargs):
    num_retries = 10
    for try_index in range(1 + num_retries):
        if try_index > 0:
            log(f"Retrying GET {url} ..{try_index}/{num_retries}")
        r = requests.get(url, **kwargs)
        if r.status_code in (429, 403):
            duration = 10.0 * 60.0
            try:
                ratelimit_reset = int(r.headers.get("x-ratelimit-reset"))
                duration = ratelimit_reset - time.time() + 10.0
            except:
                log("Failed to parse X-Ratelimit-Reset..")
            duration = max(duration, 10.0)
            duration = min(duration, 60.0*60.0)
            log(f"Waiting {duration/60.0:.1f}min for rate limit to recover..")
            time.sleep(duration)
            continue

        return r

def get_runner_version_and_checksums():
    r = retry_get("https://api.github.com/repos/actions/runner/releases/latest",
        headers={ "Accept": "application/vnd.github.v3+json" })
    r.raise_for_status()
    data = r.json()

    version = data["tag_name"]
    body = data["body"]

    assert version.startswith("v")
    version = version[1:]

    checksums = { }

    for m in re.finditer(r"<!-- BEGIN SHA ([a-z0-9_\-]+) -->([0-9a-f]+)<!-- END SHA ([a-z0-9_\-]+) -->", body):
        pre = m.group(1)
        sha = m.group(2)
        post = m.group(3)
        assert pre == post

        os_arch, *flags = pre.split("_")
        os_name, arch  = os_arch.split("-", maxsplit=1)
        flags = frozenset(flags)
        checksums[(os_name, arch, flags)] = sha
    return version, checksums

def build_runner(os_name, os_arch):
    version, checksums = get_runner_version_and_checksums()
    log(f"Found version: {version}")

    prefixes = {
        "x64": "amd64/",
        "arm": "arm32v7/",
        "arm64": "arm64v8/",
    }

    arch = config.get("arch", os_arch)
    cross = arch != os_arch

    if cross:
        prefix = prefixes[arch]
    else:
        prefix = ""

    desc = f"{os_name}-{os_arch}-{version}"

    flags = frozenset()
    checksum = checksums.get((os_name, arch, flags))
    if not checksum:
        raise RuntimeError(f"No known checksum for {desc}")

    log(f"-- Building runner for {desc}")
    path = os.path.join(self_path, "runner")
    return build_image(
        path=path,
        tag=f"{cluster}-runner",
        nocache=argv.rebuild,
        buildargs={
            "ARG_OS": os_name,
            "ARG_ARCH": arch,
            "ARG_VERSION": version,
            "ARG_CHECKSUM": checksum,
            "ARG_ARCH_PREFIX": prefix,
        },
    )

def build_proxy():
    log(f"-- Building proxy")
    path = os.path.join(self_path, "proxy")
    return build_image(
        path=path,
        nocache=argv.rebuild,
        tag=f"{cluster}-proxy",
    )

def detect_os_arch():
    platform_to_os = {
        "linux": "linux",
        "darwin": "osx",
    }
    os_name = platform_to_os.get(sys.platform)
    if not os_name:
        raise RuntimeError(f"Unsupported OS: {sys.platform}")

    machine_to_arch = {
        "i368": "x86",
        "i686": "x86",
        "x86_64": "x64",
        "aarch64_be": "arm64",
        "aarch64": "arm64",
        "armv8b": "arm64",
        "armv8l": "arm64",
    }
    os_arch = machine_to_arch.get(platform.machine())
    if not os_arch:
        raise RuntimeError(f"Unsupported architecture: {platform.machine()}")
    
    return os_name, os_arch

def start_runner():
    owner = config["repo"]["owner"]
    repo = config["repo"]["name"]
    auth = HTTPBasicAuth(config["auth"]["username"], config["auth"]["access-token"])
    r = requests.post(f"https://api.github.com/repos/{owner}/{repo}/actions/runners/registration-token", auth=auth, headers={
        "Accept": "application/vnd.github.v3+json",
    })
    r = r.json()
    token = r.get("token")
    if not token:
        log(repr(r))
        raise RuntimeError("Failed to register runner")

    volumes = config.get("volumes", {})

    url = f"https://github.com/{owner}/{repo}"
    container = None
    proxy_url = f"http://{cluster}-proxy:8080"

    labels = ",".join(config.get("labels", []))

    for n in range(64):
        name = random.choice(config["runner-names"])
        try:
            container = dc.containers.run(
                image=runner_image,
                command=[url, token, f"{cluster}-{name}", proxy_url, labels],
                auto_remove=True,
                detach=True,
                name=f"{cluster}-{name}",
                network=network.name,
                volumes=volumes,
                labels={ f"{cluster}.runner": "1" },
            )
            break
        except Exception as e:
            log(repr(e))
    return container

def remove_stale_runners(our_runners):
    names = set(r.name for r in our_runners)

    owner = config["repo"]["owner"]
    repo = config["repo"]["name"]
    auth = HTTPBasicAuth(config["auth"]["username"], config["auth"]["access-token"])
    r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/actions/runners", auth=auth, headers={
        "Accept": "application/vnd.github.v3+json",
    })
    runners = r.json()
    prefix = f"{cluster}-"
    for runner in runners.get("runners", []):
        name = runner["name"] 
        status = runner["status"]
        if name in names:
            continue
        if status == "offline" and name.startswith(prefix):
            id = runner["id"]
            log(f"Removing stale runner {name} ({id})")
            r = requests.delete(f"https://api.github.com/repos/{owner}/{repo}/actions/runners/{id}", auth=auth, headers={
                "Accept": "application/vnd.github.v3+json",
            })

g_event = threading.Event()

RE_BANNER = re.compile(r"^(([ .,'()|_\-\\/]*)|(\s*\|\s*Self-hosted runner registration\s*\|\s*))$")

g_num_worker_failures = 0

class Runner:
    def __init__(self, container):
        self.container = container
        self.name = container.name
        self.quit_event = threading.Event()
        self.work_event = threading.Event()
        self.working = False
        if container.status == "running" or container.status == "created":
            self.thread = threading.Thread(None, self.listen_on_thread)
            self.thread.start()
            self.running = True
        else:
            self.running = False

    def listen_on_thread(self):
        log(f"Listen: {self.name}")
        try:
            logs = self.container.logs(stream=True)
            name = self.name[len(cluster) + 1:]
            lineno = 0
            for chunk in logs:
                chunk = chunk.decode("utf-8", errors="ignore")
                chunk = chunk.splitlines()
                for line in chunk:
                    line = line.rstrip()
                    if "Running job:" in line:
                        self.work_event.set()
                        g_event.set()
                    hide = False
                    if lineno < 32 and RE_BANNER.match(line):
                        hide = True
                    if line.strip() and not hide:
                        log(f"{name}| {line}")
                    lineno += 1
            self.quit_event.set()
            g_event.set()
        except Exception as e:
            log(repr(e))
            self.quit_event.set()
            g_event.set()

    def poll(self):
        global g_num_worker_failures
        if self.running and not self.working and self.work_event.is_set():
            log(f"Got work: {self.name}")
            self.working = True
        if self.running and self.quit_event.is_set():
            log(f"Finished: {self.name}")
            self.thread.join()
            if not self.working:
                g_num_worker_failures += 1
            self.running = False
            self.working = False

    def __repr__(self):
        return f"Runner({self.name!r})"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run GitHub Actions in a bit more safe manner")
    parser.add_argument("--config", default="", help="Configuration file path")
    parser.add_argument("--rebuild", action="store_true", help="Rebuild all images")
    parser.add_argument("--recreate", action="store_true", help="Recreate all containers")
    parser.add_argument("--remove-runners", action="store_true", help="Remove existing runners")
    argv = parser.parse_args()

    self_path = os.path.dirname(__file__)

    dc = docker.from_env()

    config_root = argv.config if argv.config else os.path.join(self_path, "config")
    config_path = os.path.join(config_root, "config.json")
    config = load_config(config_path)
    cluster = config["cluster-name"]

    shutil.copy2(
        os.path.join(config_root, "runner-setup.sh"),
        os.path.join(self_path, "runner", "user-setup.sh"))

    os_name, os_arch = detect_os_arch()
    runner_image = build_runner(os_name, os_arch)
    proxy_image = build_proxy()

    # Find or create the network
    network_name = f"{cluster}-net"
    try:
        network = dc.networks.get(network_name)
    except docker.errors.NotFound:
        log(f"-- Creating network {network_name}")
        network = dc.networks.create(
            name=network_name,
            internal=True
        )

    # Find or create the proxy
    proxy_name = f"{cluster}-proxy"
    try:
        proxy = dc.containers.get(proxy_name)
        if proxy.image != proxy_image or argv.recreate:
            proxy.remove(force=True)
            proxy = None
        elif proxy.status != "running":
            log(f"-- Restarting proxy {proxy_name}")
            proxy.restart()
    except docker.errors.NotFound:
        proxy = None
    if not proxy:
        log(f"-- Creating proxy {proxy_name}")
        proxy = dc.containers.create(
            image=proxy_image,
            name=proxy_name,
        )
        network.connect(proxy)
        proxy.start()

    containers = dc.containers.list(filters={
        "label": f"{cluster}.runner=1",
    })

    if argv.remove_runners:
        for container in containers:
            container.remove(force=True)
        containers = []

    runners = [Runner(c) for c in containers]
    for runner in runners:
        log(f"Found: {runner}")
    
    last_remove_time = 0

    while True:
        now = time.time()
        if now - last_remove_time >= config["poll-interval"]["stale-runners"]:
            remove_stale_runners(runners)
            last_remove_time = now

        num_idle = sum(1 for r in runners if not r.working)
        num_total = len(runners)
        if num_idle == 0 and num_total < config["max-runners"]:
            container = start_runner()
            runner = Runner(container)
            log(f"Adding new runner {runner.name}")
            runners.append(runner)
            continue

        g_event.wait(timeout=config["poll-interval"]["main"])
        g_event.clear()
        for r in runners:
            r.poll()
        runners = [r for r in runners if r.running]

        if g_num_worker_failures > 20:
            log("Too many runner failures, exiting...")
            exit(1)
