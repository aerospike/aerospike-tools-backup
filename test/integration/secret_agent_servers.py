import docker
import lib
import time
import subprocess
import os

WORK_DIRECTORY = lib.absolute_path(lib.SECRET_AGENT_DIRECTORY)
SA_REPO_PATH = os.path.join(WORK_DIRECTORY, "aerospike-secret-agent/")
SA_BIN_PATH = os.path.join(SA_REPO_PATH, "target/aerospike-secret-agent")

SA_PORT = "3005"

CONTAINER_VAL = "/opt/aerospike/work"

SERVER_IMAGE = "aerospike/aerospike-secret-agent"
TAG = "1.1.0"

USE_DOCKER_SERVERS = True
if USE_DOCKER_SERVERS:
	DOCKER_CLIENT = docker.from_env()

class SecretAgent():
    running: bool = False
    
    def start(self):
        raise NotImplemented
    
    def stop(self):
        raise NotImplemented
    
    def output(self) -> str:
        raise NotImplemented

class SADocker(SecretAgent):
    def __init__(self, config:str, port:str) -> None:
        self.config = config
        self.container = None
        self.port = port
        self.client = docker.from_env()
    
    def start(self):
        if SecretAgent.running:
            print("secret agent is already running")
            return
        
        print("starting secret agent")

        mount_dir = WORK_DIRECTORY
        conf_path = os.path.relpath(self.config, WORK_DIRECTORY)
        cmd = "--config-file %s" % os.path.join(CONTAINER_VAL, conf_path)

        self.container = DOCKER_CLIENT.containers.run(SERVER_IMAGE + ":" + TAG,
                command=cmd,
                ports={
                    self.port + '/tcp': self.port,
                },
                volumes={ mount_dir: { 'bind': '/opt/aerospike/work', 'mode': 'rw' } },
                tty=True, detach=True, name='aerospike-secret-agent')

        SecretAgent.running = True
        time.sleep(0.5)
    
    def stop(self):
        if not SecretAgent.running:
            print("secret agent is not running")
            return

        self.container.stop()
        SecretAgent.running = False
        print("stopped secret agent")
    
    def output(self) -> str:
        if not self.container:
            return "container is None"

        return self.container.logs(stdout=True, stderr=True)

class SAProcess(SecretAgent):
    def __init__(self, config:str) -> None:
        self.path = SA_BIN_PATH
        self.config = config
        self.process = None
        self.run_cmd = f""
    
    def start(self):
        if SecretAgent.running:
            print("secret agent is already running")
            return
        
        print("starting secret agent")

        args = [self.path, "--config-file", self.config]
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        SecretAgent.running = True
        time.sleep(0.5)
    
    def stop(self):
        if not SecretAgent.running:
            print("secret agent is not running")
            return

        self.process.kill()
        SecretAgent.running = False
        print("stopped secret agent")
    
    def output(self) -> str:
        if not self.process:
            return "secret agent process is None"

        return str(self.process.stdout.read().decode("utf-8"))

def init_work_dir():
    if os.path.exists(WORK_DIRECTORY):
        lib.remove_dir(WORK_DIRECTORY)

    cmd = "mkdir -p %s" % WORK_DIRECTORY
    os.system(cmd)

def setup_secret_agent_server_docker():
    """
    Downloads the docker image for the secret agent and sets up the agent working directory 
    """

    if SecretAgent.running:
        return

    print("setting up secret agent")
    init_work_dir()
    DOCKER_CLIENT.images.pull(SERVER_IMAGE, tag=TAG)

def setup_secret_agent_server_process():

    """
    Downloads the source for the secret agent and sets up the agent working directory 
    """

    if SecretAgent.running:
        return

    init_work_dir()

    secret_agent_url = "https://github.com/aerospike/aerospike-secret-agent.git"
    cmd = "git clone %s %s" % (secret_agent_url, SA_REPO_PATH)
    os.system(cmd)

    cmd = "make -C %s" % SA_REPO_PATH
    os.system(cmd)

    cmd = "chmod +x %s" % SA_BIN_PATH

def teardown_secret_agent():
    cmd = "rm -rf %s" % WORK_DIRECTORY
    os.system(cmd)

    if USE_DOCKER_SERVERS:
        DOCKER_CLIENT.containers.get("/aerospike-secret-agent").remove()

def setup_secret_agent():
    if USE_DOCKER_SERVERS:
        setup_secret_agent_server_docker()
    else:
        setup_secret_agent_server_process()

def get_secret_agent(config:str, port:str=SA_PORT) -> SecretAgent:
    if USE_DOCKER_SERVERS:
        return SADocker(config, port)
    
    return SAProcess(config)