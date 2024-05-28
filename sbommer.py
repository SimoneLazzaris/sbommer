import json
import subprocess
import re
import os
import socket
import sys
import requests
import uuid
import tempfile
import glob
import gzip
import datetime


def trivy_scan_base():
    try:
        (fnum,fname) = tempfile.mkstemp()
        os.close(fnum)
        result = subprocess.run(
            ['trivy', 'rootfs', '/', '--scanners=""', '--format=cyclonedx', "--output={}".format(fname)],
        )
        with open(fname, "r") as f:
            return json.load(f)
    finally:
        os.unlink(fname)


def trivy_scan_container(image):
    try:
        (fnum,fname) = tempfile.mkstemp()
        os.close(fnum)
        result = subprocess.run(
            ["trivy", "image", image, '--scanners=""', "--format=cyclonedx", "--output={}".format(fname)],
        )
        with open(fname, "r") as f:
            return json.load(f)
    finally:
        os.unlink(fname)


def list_tcp_udp_listening_processes():
    try:
        unique_entries = {}

        # Execute the 'ss' command to find all listening TCP and UDP sockets
        result = subprocess.run(
            ["ss", "-nlptun"],
            stdout=subprocess.PIPE,
            universal_newlines=True,
            stderr=subprocess.PIPE,
        )

        if result.stderr:
            print("Error:", result.stderr.strip())
            return

        # Parse the output, skipping the header line
        for line in result.stdout.strip().split("\n")[1:]:
            try:
                parts = line.split()

                protocol = parts[0].lower()  # Extract protocol type
                local_address_port = parts[4].split(
                    ":"
                )  # Split into address and port components
                if len(local_address_port) == 2:
                    port = local_address_port[1]
                    if port.isdigit() and "users:" in line:
                        users = (
                            line.split("users:")[1]
                            .strip()
                            .replace("(", "")
                            .replace("))", "")
                        )
                        process_name = users.split(",")[0].split('"')[
                            1
                        ]  # Extract process name

                        # Find the executable path using 'which' command
                        path_result = subprocess.run(
                            ["which", process_name],
                            stdout=subprocess.PIPE,
                            universal_newlines=True,
                        )
                        path = path_result.stdout.strip()
                        if path:
                            if path in unique_entries:
                                unique_entries[path] = "{},{}:{}".format(
                                    unique_entries[path], port, protocol
                                )
                            else:
                                unique_entries[path] = "{}:{}".format(port, protocol)
            except IndexError as e:
                print(f"Error processing line: '{line}' - {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return unique_entries


def running_process_list():
    process = subprocess.Popen(
        ["ps", "-eo", "pid,args"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, notused = process.communicate()
    ret = {}
    for line in stdout.splitlines():
        m = re.match(r"^\s*([0-9]+)\s+(\S+).*", line.decode())
        if m is None:
            continue
        pid = int(m.group(1))
        cmdline = m.group(2)
        ret[cmdline] = pid
    return ret


def add_component_metadata(bom):
    for p in filter(lambda x: x["type"] == "application", bom["components"]):
        fullname = "/" + p["name"]
        print("found", fullname)
        if fullname in proclist:
            print("running")
            if "properties" not in p:
                p["properties"] = []

            p["properties"].append(
                {"name": "Codenotary:Trustcenter:Running", "value": str(proclist[fullname])}
            )
        if fullname in listenproc:
            print("listening on", listenproc[fullname])
            p["properties"].append(
                {"name": "Codenotary:Trustcenter:Ports", "value": listenproc[fullname]}
            )


def get_lsb_distro(distro):
    result = subprocess.run(["lsb_release", "-a"], stdout=subprocess.PIPE)
    lsb_map = { "Distributor ID": "Name", "Release": "Release", "Codename": "Codename"}
    for line in result.stdout.decode().split("\n"):
        if ":" not in line:
            continue
        prompt, value = (x.strip() for x in line.split(":"))
        if prompt in lsb_map:
            distro[lsb_map[prompt]] = value
    return distro


def get_os_release(filename, distro):
    lsb_map = { "ID": "Name", "DISTRIB_ID": "Name", "VERSION_ID": "Release", "BUILD_ID": "Release", "DISTRIB_RELEASE": "Release", "VERSION_CODENAME": "Codename"}
    with open(filename, "rt") as f:
        for line in f:
            m = re.match(r'^(\w+)="?(.*?)"?(?=\s|$)', line)
            if m is None:
                continue
            prompt, value = m.groups()
            if prompt in lsb_map:
                distro[lsb_map[prompt]] = value
    return distro


def get_os_distro():
    distro={"Name": "unknown", "Release": "unknown", "Codename": "unknown"}
    # fine if lsb_release is installed
    result = subprocess.run(["which", "lsb_release"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return get_lsb_distro(distro)
    if os.path.exists("/etc/os-release"):
        return get_os_release("/etc/os-release", distro)
    release_file = glob.glob("/etc/*-release")
    if len(release_file) > 0:
        print(release_file[0])
        get_os_release(release_file[0], distro)
    return distro


def get_ip_address():
    try:
        result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], stdout=subprocess.PIPE)
        match = re.search(r'src (\S+)', result.stdout.decode())
        if match:
            return match.group(1)
    except subprocess.CalledProcessError as e:
        return None

def get_system_uptime():
    with open('/proc/uptime', 'rt') as f:
        uptime_seconds = float(f.readline().split()[0])
    return uptime_seconds


def get_last_update_time():
    def get_last_update_time_arch():
        if not os.path.exists('/var/log/pacman.log'):
            return
        log_files=glob.glob("/var/log/pacman.log*")
        log_files.sort()
        for filename in log_files:
            if filename.endswith('.gz'):
                zopen = gzip.open
            else:
                zopen = open
            with zopen(filename, 'rt') as log_file:
                for line in reversed(list(log_file)):
                    if 'starting full system upgrade' in line:
                        timestamp_str = re.search(r'^\[(.*?)\]', line).group(1)
                        last_update_time = datetime.datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S%z')
                        return last_update_time
        return None


    def get_last_update_time_apt():
        if not os.path.exists("/var/log/apt/history.log"):
            return None
        log_files=glob.glob("/var/log/apt/history.log.*.gz")
        log_files.sort(key=lambda x: int(x.split(".")[2])) # sort using the numeric value of /var/log/apt/history.log.NNN.gz
        log_files.insert(0, "/var/log/apt/history.log")
        for filename in log_files:
            if filename.endswith('.gz'):
                zopen = gzip.open
            else:
                zopen = open
            with zopen(filename, 'rt') as log_file:
                for line in reversed(list(log_file)):
                    if 'Start-Date' in line:
                        timestamp_str = re.search(r'Start-Date: (.*)', line).group(1).strip()
                        last_update_time = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        return last_update_time
        return None


    def get_last_update_time_dnf():
        if not os.path.exists("/var/log/dnf.log"):
            return None
        log_paths = glob.glob("/var/log/dnf.log*")
        log_paths.sort()
        for log_path in log_paths:
            if log_path.endswith('.gz'):
                zopen = gzip.open
            else:
                zopen = open
            with zopen(log_path, 'rt') as log_file:
                print(f"processing {log_path}")
                # Search for lines that indicate an update was performed
                for line in reversed(list(log_file)):
                    if 'Updated:' in line or 'Upgrade:' in line or 'Upgraded:' in line:
                        timestamp_str = line.split()[0]
                        return datetime.datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S%z')
        return None


    def get_last_update_time_yum():
        if not os.path.exists("/var/log/yum.log"):
            return None
        log_paths = glob.glob("/var/log/yum.log*")
        log_paths.sort()
        for log_path in log_paths:
            if log_path.endswith('.gz'):
                zopen = gzip.open
            else:
                zopen = open
            with zopen(log_path, 'rt') as log_file:
                print(f"processing {log_path}")
                # Search for lines that indicate an update was performed
                for line in reversed(list(log_file)):
                    if 'Updated:' in line or 'Upgrade:' in line or 'Upgraded:' in line:
                        timestamp_str = re.match("(... .. ..:..:..)", line).group(1)
                        return datetime.datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        return None
    for getter in [get_last_update_time_apt, get_last_update_time_dnf, get_last_update_time_yum, get_last_update_time_arch]:
        last_update = getter()
        if last_update is not None:
            return last_update
    return None


def add_system_metadata(bom):
    uid = "unknown"
    if os.path.exists("/sys/class/dmi/id/product_uuid"):
        with open("/sys/class/dmi/id/product_uuid", "rt") as f:
            uid = f.read().strip()
    print("uid", uid)
    if "properties" not in bom:
        bom["properties"] = []
    bom["properties"].append({"name": "Codenotary:Trustcenter:MachineID", "value": uid})
    bom["properties"].append({"name": "Codenotary:Trustcenter:Hostname", "value": socket.getfqdn()})
    bom["properties"].append({"name": "Codenotary:Trustcenter:Uptime", "value": str(get_system_uptime())})
    result = subprocess.run(
        ["uname", "-r"],
        stdout=subprocess.PIPE,
        universal_newlines=True,
        stderr=subprocess.PIPE,
    )
    bom["properties"].append({"name": "Codenotary:Trustcenter:KernelVersion", "value": result.stdout.strip()})
    distro = get_os_distro()
    for key in distro:
        bom["properties"].append({"name": f"Codenotary:Trustcenter:Distro:{key}", "value": distro[key]})
    ip_address = get_ip_address()
    if ip_address != None:
        bom["properties"].append({"name": f"Codenotary:Trustcenter:PrimaryIP", "value": ip_address})
    last_update = get_last_update_time()
    if ip_address != None:
        bom["properties"].append({"name": f"Codenotary:Trustcenter:LastSystemUpdate", "value": last_update.isoformat()})
    if os.path.exists("/etc/system_function"):
        with open("/etc/system_function", "rt") as f:
            bom["properties"].append({"name": f"Codenotary:Trustcenter:SystemFunction", "value": f.read().strip()})

def get_docker_containers():
    result = subprocess.run(["which", "docker"], stdout=subprocess.PIPE)
    if result.returncode != 0:
        return
    result = subprocess.run(
        ["docker", "container", "ls", "--format", "{{json .}}"],
        stdout=subprocess.PIPE,
        universal_newlines=True,
        stderr=subprocess.PIPE,
    )
    for instance in result.stdout.split("\n"):
        instance = instance.strip()
        if instance == "":
            continue
        yield json.loads(instance)


def get_docker_sha(container_id):
    result = subprocess.run(
        ["docker", "container", "inspect", container_id],
        stdout=subprocess.PIPE,
        universal_newlines=True,
        stderr=subprocess.PIPE,
    )
    info = json.loads(result.stdout)
    return info[0]["Image"]


def same_attr(a, b, attr):
    if attr not in a or attr not in b:
        return False
    return a[attr] == b[attr]


def component_present(bom, new_component):
    for c in bom["components"]:
        if same_attr(c, new_component, "bom-ref"):
            return True
        if same_attr(c, new_component, "purl"):
            return True
        if same_attr(c, new_component, "name") and same_attr(
            c, new_component, "version"
        ):
            return True
    return False


def add_docker(bom, image, sha_id):
    if ":" in image:
        imageName, imageVersion = image.split(":", 1)
    else:
        imageName = image
        imageVersion = "latest"
    uid = str(uuid.uuid4())
    dok = {
        "bom-ref": uid,
        "type": "container",
        "name": imageName,
        "version": imageVersion,
        "purl": "pkg:docker/{}@{}".format(imageName, sha_id),
        "properties": [],
    }
    m = re.match("sha256:([a-fA-F0-9]+)$", sha_id)
    if m is not None:
        dok["hashes"] = [ {"alg": "SHA-256", "content": m.group(1)}]
    if component_present(bom, dok):
        return None
    bom["components"].append(dok)
    depref = {"ref": uid, "dependsOn": []}
    bom["dependencies"].append(depref)
    return uid


def add_dependencies(bom, parent_id, component_id):
    for dep in bom["dependencies"]:
        if dep["ref"] == parent_id:
            dep["dependsOn"].append(component_id)
            return


def scan_docker_containers(bom):
    print("Scanning containers")
    docks = get_docker_containers()
    for d in docks:
        print("Found image", d["Image"])
        sha_id = get_docker_sha(d["ID"])
        dok_id = add_docker(bom, d["Image"], sha_id)
        if dok_id is None:
            print("Already there")
            continue
        container_sbom = trivy_scan_container(d["Image"])
        for c in container_sbom["components"]:
            if component_present(bom, c):
                print("skipping already present", c["name"])
                continue
            bom["components"].append(c)
            add_dependencies(bom, dok_id, c["bom-ref"])
            print("appending", c["name"])


def cleanup_sbom(sbom):
    # remove component which name is empty
    for c in sbom["components"]:
        if c["name"] == "" and ("purl" not in c or c["purl"] == ""):
            print("deleting", c)
            sbom["components"].remove(c)
            for dep in sbom["dependencies"]:
                if dep["ref"] == c["bom-ref"]:
                    sbom["dependencies"].remove(dep)
                    continue
                for d in dep["dependsOn"]:
                    if d == c["bom-ref"]:
                        dep["dependsOn"].remove(d)

def check_trivy():
    result = subprocess.run(["which", "trivy"], stdout=subprocess.PIPE)
    if result.returncode != 0:
        print("Trivy not installed")
        sys.exit(1)


def upload_sbom(url, sbom):
    print("uploading sbom")
    result = requests.post(url, json=sbom)
    print(result.json())


check_trivy()
proclist = running_process_list()
listenproc = list_tcp_udp_listening_processes()
bom = trivy_scan_base()
add_component_metadata(bom)
add_system_metadata(bom)
scan_docker_containers(bom)
cleanup_sbom(bom)
# upload_sbom("https://guardian.codenotary.com/api/v1/codenotary/sbom", bom)

with open("output.json", "wt") as f:
    json.dump(bom, f)
