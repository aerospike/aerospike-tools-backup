import base64
import datetime
import lib
import time
import subprocess
import os

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

import docker

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
    instance = None
    
    def start(self):
        raise NotImplemented
    
    def stop(self):
        raise NotImplemented
    
    def output(self) -> str:
        raise NotImplemented
    
    def cleanup(self):
        raise NotImplemented

class SADocker(SecretAgent):
    cleaned_up = False

    def __init__(self, config:str, port:str) -> None:
        self.config = config
        self.container = None
        self.port = port
        self.client = docker.from_env()
        self.cleaned_up = False
    
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
        SecretAgent.instance = self
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
    
    def cleanup(self):
        self.stop()
        DOCKER_CLIENT.containers.get("/aerospike-secret-agent").remove()
        SecretAgent.instance = None
        print("docker based secret agent cleaned up")

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
        SecretAgent.instance = self
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

        return (self.process.stdout.read()).decode("utf-8")

    def cleanup(self):
        self.stop()
        SecretAgent.instance = None
        print("process based secret agent cleaned up")

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

    if SecretAgent.instance:
        SecretAgent.instance.cleanup()

def setup_secret_agent():
    if USE_DOCKER_SERVERS:
        setup_secret_agent_server_docker()
    else:
        setup_secret_agent_server_process()

def get_secret_agent(config:str, port:str=SA_PORT) -> SecretAgent:
    if USE_DOCKER_SERVERS:
        return SADocker(config, port)
    
    return SAProcess(config)

# util functions

SA_ADDR = "0.0.0.0"

class tls_cfg():
    def __init__(self, cert_file:str, key_file:str) -> None:
        self.cert_file = cert_file
        self.key_file = key_file
        self.key = None
        self.cert = None

    def get_cfg(self) -> str:

        self._write_crypto()

        def adjust_path_for_docker_volume(path:str):
            if USE_DOCKER_SERVERS:
                path = os.path.relpath(path, WORK_DIRECTORY)
                path = os.path.join(CONTAINER_VAL, path)

            return path

        cert_path = adjust_path_for_docker_volume(self.cert_file)
        key_path = adjust_path_for_docker_volume(self.key_file)

        template = """
    tls:
        "cert-file": %s
        "key-file": %s
""" % (cert_path, key_path)

        return template
    
    def _write_crypto(self):

        self._gen_private_key()
        with open(self.key_file, "wb+") as f:
            f.write(self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        self._gen_cert()
        with open(self.cert_file, "wb+") as f:
            f.write(self.cert.public_bytes(
                encoding=serialization.Encoding.PEM,
            ))

    def _gen_private_key(self):
        """
        generate private key self.key
        """
        self.key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    
    def _gen_cert(self):
        """
        Generate self.cert, a self signed cert using self.key
        """
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
        ])

        self.cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(self.key, hashes.SHA256())


        

def gen_secret_agent_conf(resources:{str:str}, tls_cfg:str) -> str:
    sa_addr = SA_ADDR
    sa_port = SA_PORT

    def make_resources(resources:{str:str}={}) -> str:
        res = ""
        for k, v in resources.items():

            if USE_DOCKER_SERVERS:
                v = os.path.relpath(v, WORK_DIRECTORY)
                v = os.path.join(CONTAINER_VAL, v)

            nl = '\n'
            res += f'       "{k}": "{v}"{nl}'
        return res

    resource_str = make_resources(resources=resources)

    secret_agent_conf_template = """
service:
  tcp:
    endpoint: %s:%s
%s

secret-manager:
  file:
    resources:
%s

log:
  level: debug
""" % (sa_addr, sa_port, tls_cfg, resource_str)
    return secret_agent_conf_template

def gen_secret_agent_secrets(secrets:{str:any}={}) -> str:
    
    def make_secrets(secrets:{str:any}={}) -> str:
        res = ""
        for k, v in secrets.items():
            if v is None or v == "":
                continue

            nl = '\n'
            name = k
            value = base64.b64encode(str(v).encode("utf-8")).decode("utf-8")
            template = f'   "{name}": "{value}",{nl}'

            res += template
        # remove the last "",\n"
        return res[:-2]
			
    secret_str = make_secrets(secrets=secrets)

    secrets_template = """
{
%s
}
""" % secret_str
    return secrets_template

def gen_secret_args(args:{str:any}, resource:str) -> [str]:
    res = []
    for k, v in args.items():
        arg = f"--{k}"
        res.append(arg)

        val = f"secrets:{resource}:{k}"
        res.append(val)

    return res