import json
import subprocess
import re
import os
import socket
import sys
import requests
import uuid


def trivy_scan_base():
    result = subprocess.run(
        'trivy rootfs / --scanners="" --format cyclonedx'.split(" "),
        stdout=subprocess.PIPE,
        universal_newlines=True,
        stderr=subprocess.PIPE,
    )
    return json.loads(result.stdout)


def trivy_scan_container(image):
    result = subprocess.run(
        ["trivy", "image", image, '--scanners=""', "--format=cyclonedx"],
        stdout=subprocess.PIPE,
        universal_newlines=True,
        stderr=subprocess.PIPE,
    )
    return json.loads(result.stdout)


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
        m = re.match("^\s*([0-9]+)\s+(\S+).*", line.decode())
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


def get_docker_containers():
    result = subprocess.run(["which", "docker"], stdout=subprocess.PIPE)
    if result.returncode != 0:
        return
    result = subprocess.run(
        "docker container ls --format json".split(" "),
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
