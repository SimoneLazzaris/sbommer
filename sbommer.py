import json
import subprocess
import re
import socket
import sys

def trivy_scan_base():
    result = subprocess.run(
        "trivy rootfs / --scanners="" --format cyclonedx".split(" "),
        stdout=subprocess.PIPE,
        universal_newlines=True,
        stderr=subprocess.PIPE
    )
    return json.loads(result.stdout)


def trivy_scan_container(image):
    result = subprocess.run(
        ["trivy", "image", image, '--scanners=""', "--format=cyclonedx"],
        stdout=subprocess.PIPE,
        universal_newlines=True,
        stderr=subprocess.PIPE
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
            stderr=subprocess.PIPE
        )

        if result.stderr:
            print("Error:", result.stderr.strip())
            return

        # Parse the output, skipping the header line
        for line in result.stdout.strip().split('\n')[1:]:
            try:
                parts = line.split()

                protocol = parts[0].lower()  # Extract protocol type
                local_address_port = parts[4].split(':')  # Split into address and port components
                if len(local_address_port) == 2:
                    port = local_address_port[1]
                    if port.isdigit():
                        users = line.split("users:")[1].strip().replace('(', '').replace('))', '')
                        process_name = users.split(',')[0].split('"')[1]  # Extract process name

                        # Find the executable path using 'which' command
                        path_result = subprocess.run(
                            ['which', process_name],
                            stdout=subprocess.PIPE,
                            universal_newlines=True
                        )
                        path = path_result.stdout.strip()
                        if path:
                            if path in unique_entries:
                                unique_entries[path] = "{},{}:{}".format(unique_entries[path], port, protocol)
                            else:
                                unique_entries[path] = "{}:{}".format(port,protocol)
            except IndexError as e:
                print(f"Error processing line: '{line}' - {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return unique_entries


def running_process_list():
    process = subprocess.Popen(['ps', '-eo' ,'pid,args'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
    for p in filter(lambda x: x["type"]=="application",bom["components"]):
        fullname = "/" + p["name"]
        print("found",fullname)
        if fullname in proclist:
            print("running")
            if "properties" not in p:
                p["properties"]=[]

            p["properties"].append({"name": "trustcenter#running", "value": str(proclist[fullname])})
        if fullname in listenproc:
            print("listening on", listenproc[fullname])
            p["properties"].append({"name": "trustcenter#ports", "value": listenproc[fullname]})


def add_system_metadata(bom):
    with open("/sys/class/dmi/id/product_uuid", "rt") as f:
        uid = f.read().strip()
    print("uid", uid)
    if "properties" not in bom:
        bom["properties"] = []
    bom["properties"].append( {"name": "trustcenter#systemid", "value": uid } )
    bom["properties"].append( {"name": "trustcenter#hostname", "value": socket.getfqdn() } )


def get_docker_containers():
    result = subprocess.run(["which", "docker"])
    if result.returncode != 0:
        return
    result = subprocess.run(
        "docker container ls --format json".split(" "),
        stdout=subprocess.PIPE,
        universal_newlines=True,
        stderr=subprocess.PIPE
    )
    for instance in result.stdout.strip().split("\n"):
        yield json.loads(instance)

def scan_docker_containers(bom):
        print("Scanning containers")
        docks = get_docker_containers()
        for d in docks:
            print("Found image", d["Image"])
            container_sbom = trivy_scan_container(d["Image"])
            for c in container_sbom["components"]:
                bom["components"].append(c)
                print("appending", c["name"])

def check_trivy():
    result = subprocess.run(["which", "trivy"])
    if result.returncode != 0:
        print("Trivy not installed")
        sys.exit(1)


check_trivy()
proclist = running_process_list()
listenproc = list_tcp_udp_listening_processes()
bom = trivy_scan_base()
add_component_metadata(bom)
add_system_metadata(bom)
scan_docker_containers(bom)

with open("scan3.json", "wt") as f:
    json.dump(bom,f)
