#! /usr/bin/python
import sys, getopt
import platform
import logging
# import rpm
# import psutil
import socket
# import docker
import json
import time
import ConfigParser, os
import ast
import shlex, subprocess
import datetime

now = datetime.datetime.now()
inputfile = ''


config = ConfigParser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "config.cfg"))

logger = logging.getLogger('monit')
hdlr = logging.FileHandler(ast.literal_eval(config.get('logging', 'path')))
formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s %(message)s',datefmt='%Y-%m-%dT%H:%M:%S')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
level = config.get('logging', 'level')
if level == "DEBUG":
    logger.setLevel(logging.DEBUG)
elif level == "ERROR":
    logger.setLevel(logging.ERROR)
else:
    logger.setLevel(logging.INFO)
get_versions_for = ast.literal_eval(config.get('versions', 'versions_for'))
output_dict = {}
cert_entry = list()
dict_added_items = {}
host = platform.node()
mounts = ast.literal_eval(config.get('system', 'mounts'))
timeout = ast.literal_eval(config.get('health', 'timeout'))
counter = ast.literal_eval(config.get('health', 'counter'))
ports = ast.literal_eval(config.get('health', 'ports'))
app_name = ast.literal_eval(config.get('health', 'application'))
app_log_files = ast.literal_eval(config.get('health', 'logfile'))
app_health_string = ast.literal_eval(config.get('health', 'search_string'))
docker_socket_uri = ast.literal_eval(config.get('docker', 'docker_socket_uri'))
whitelist_containers = ast.literal_eval(config.get('docker', 'whitelist_containers'))
cert_path = ast.literal_eval(config.get('cert', 'cert_path'))
threshold_days = 30

def __init__(self):
    pass
def linux(self):
    os = platform.linux_distribution()[0]
    os_version = platform.linux_distribution()[1]
    kernel = platform.release()
    if (os or os_version or kernel):
        return False
    else:
        return True

def app_versions(self):
    try:
        ts = rpm.TransactionSet()
        for ver in get_versions_for:
            print ver
        mi = ts.dbMatch()
        mi.pattern('name', rpm.RPMMIRE_GLOB, ver)
        print mi.pattern
        for i in mi:
            dict_added_items[ver] = i['version']
            print dict_added_items
            added_items = ' '.join('{}="{}"'.format(key, val) for key, val in dict_added_items.items())
        return True

    except Exception, e:
        return False

def system(self):
    # CPU and memory Usage
    cpu_percent = psutil.cpu_percent(interval=1)
    mem =  psutil.virtual_memory()

    return True

    # Disk Usage
    for index,i in enumerate(mounts):
        disk = psutil.disk_usage(i)
        return True

def Application(self):
    # App Port check
    for i in ports.items():
        for j in i[1]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((socket.gethostname(), j))
            if result == 0:
                return True
            else:
                return False
            s.close()
    # App Health Check
    if len(app_name) == len(app_log_files) and len(app_health_string) == len(app_log_files):
        for index,app in enumerate(app_log_files):
            global counter
            for i in range(counter):
                bufsize = 30000
                lines = 1
                fname = app
                health_str = app_health_string[index]
                fsize = os.stat(fname).st_size
                iter = 0
                with open(fname) as f:
                    if bufsize < fsize:
                        bufsize = bufsize
                    else:
                        bufsize = bufsize-fsize
                        if bufsize > fsize:
                            bufsize = 0
                    data = []
                    while True:
                        iter +=1
                        f.seek(bufsize*iter)
                        data.extend(f.readlines())
                        if len(data) >= lines or f.tell() == 0:
                            search_str = str(''.join(data[-lines:]))
                            if health_str in search_str:
                                return 0
                                counter = 0
                                break
                            else:
                                counter -=1
                                time.sleep(1)
                                if counter == 0:
                                    return 1
                                break
                    if counter == 0:
                        break
    else:
        return 2

def docker(self):
    self.conn = docker.Client(base_url=docker_socket_uri, timeout=20)
    try:
        self.containers = self.conn.containers(all=True)
    except Exception, e:
        return 2
        sys.exit(-1)
    self.total_running_containers = len(self.containers)
    for item in self.containers:
        container_id = str(item["Id"])
        container_img = str(item["Image"])
        container_name = item["Names"][0].split('/')[1]
        container_status = str(item["Status"])
        container_component = str(item["Image"]).split(':')[0]
        container_version = str(item["Image"]).split(':')[1]
        if 'Up'in container_status:
            #docker_stats = self.conn.stats(container_id)
            docker_stats = self.conn.stats(container_id, decode=False, stream=True)
            current_stats = docker_stats.next()
            stats_deserialize = json.loads(current_stats)
            mem_usage_raw = json.dumps(stats_deserialize["memory_stats"]["usage"])
            mem_limit_raw = json.dumps(stats_deserialize["memory_stats"]["limit"])
            cpu_usage_raw = json.dumps(stats_deserialize["cpu_stats"]["cpu_usage"]["total_usage"])
            cpu_total_system_raw = json.dumps(stats_deserialize["cpu_stats"]["system_cpu_usage"])
            combined_mem_usage = (float(mem_usage_raw) / float(mem_limit_raw)) * 100
            combined_cpu_usage = (float(cpu_usage_raw) / float(cpu_total_system_raw)) * 100
            self.construct_stats = dict(
                name=str(container_name),
                image=str(container_img),
                id=container_id,
                mem_usage=str(combined_mem_usage * 100),
                cpu_usage=str(combined_cpu_usage * 100),
                status=str(container_status),
                component=str(container_component),
                version=str(container_version)
            )
            added_items = ' '.join('{}="{}"'.format(key, val) for key, val in self.construct_stats.items())
            if container_name not in whitelist_containers:
                return 0
        else:
            if container_name not in whitelist_containers:
                return 1


def cert(self):
    command = "sh "+cert_path
    args = shlex.split(command)
    output,error = subprocess.Popen(args,stdout = subprocess.PIPE, stderr = subprocess.PIPE).communicate()
    output = output.splitlines()
    if "OK: All Certificates are good" in output[0]:
        logger.debug('marker=Certificate_check\t cert_check="0"')
    elif "CRITICAL: Certificates Expired. Please Check" in output[0]:
        for item in output[1:-1]:
            logger.info('marker=Certificate_check\t cert_check="1" %s',item)
    else:
        logger.info('marker=Certificate_check\t cert_check="1" check_stats="%s"',output)


