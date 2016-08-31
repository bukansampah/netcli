#!/usr/bin/env python

import sys
import traceback
import logging
import logging.config
import paramiko
import atexit
import time
import select
import telnetlib
import re
import argparse
import string
import os
import json
from ftplib import FTP


isDebug = False

class my_ftp():
    def __init__(self,host="", user="", password=""):
        self.host = host
        self.user = user
        self.password = password
        self.ftp = FTP(self.host, self.user, self.password)

    def set_debuglevel(self, level):
        self.ftp.set_debuglevel(level)

    def upload(self,full_filename, mode):
        folder = ""
        current_dir = ""
        if "/" in full_filename:
            parse = full_filename.split("/")
            n = len(parse)
            i = 0
            folder = ""
            while i < (n-1):
                if not full_filename.startswith("/") and i == 0:
                    folder = parse[i]
                else:
                    folder = folder+"/"+parse[i]
                i += 1
            filename = parse[-1]
            current_dir = os.getcwd()
            os.chdir(folder)
        else:
            filename = full_filename
            current_dir = "./"

        if mode == "binary":
            fi = open(filename, 'rb')
        else:
            fi = open(filename, 'r')
        self.ftp.storbinary("STOR "+filename, fi)
        fi.close()
        os.chdir(current_dir)
        return

    def download(self, full_filename, mode):
        folder = ""
        if "/" in full_filename:
            parse = full_filename.split("/")
            n = len(parse)
            i = 0
            folder = ""
            while i < (n-1):
                if not full_filename.startswith("/") and i == 0:
                    folder = parse[i]
                else:
                    folder = folder+"/"+parse[i]
                i += 1
            filename = parse[-1]
            self.ftp.cwd(folder)
        else:
            filename = full_filename

        if mode == "binary":
            fo = open(filename, 'wb')
        else:
            fo = open(filename, 'w')
        self.ftp.retrbinary("RETR "+filename, fo.write)
        fo.close()
        return

    def close(self):
        self.ftp.close()
        return

    def logout(self):
        self.ftp.close()
        return



class my_ssh:
    def __init__(self, host, username, password, port=22):
        self.logger = logging.getLogger()
        self.host = host
        self.user = username
        self.password = password
        self.port = port
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logger.info("ssh - connecting to: "+host)
        client.connect(self.host, port=self.port, username=self.user, password=self.password, allow_agent=True, look_for_keys=True, gss_auth=False, timeout=10)
        shell = client.invoke_shell()
        atexit.register(client.close)
        self.client = client

    def __call__(self, command):
        result = {}
        ssh_stdin, ssh_stdout, ssh_stderr = self.client.exec_command(command)
        ssh_stdin.close()
        rc = str(ssh_stdout.channel.recv_exit_status())
        output = ""
        for line in ssh_stdout.readlines(): 
            output += line

        result["command"] = command
        result["output"] = output
        result["error"] = ssh_stderr.readlines()
        return result


class my_sftp(object):
    """"""
    def __init__(self, host, username, password, port=22):
        self.logger = logging.getLogger()
        self.sftp = None
        self.sftp_open = False

        # open SSH Transport stream
        logger.info("sftp - connecting to: "+host)
        self.transport = paramiko.Transport((host, port))
        self.transport.connect(username=username, password=password)

    def _openSFTPConnection(self):
        """
        Opens an SFTP connection if not already open
        """
        if not self.sftp_open:
            self.sftp = paramiko.SFTPClient.from_transport(self.transport)
            self.sftp_open = True

    def get(self, remote_path, local_path=None):
        """
        Copies a file from the remote host to the local host.
        """
        if local_path is None:
            if "/" in remote_path:
                parse = remote_path.split("/")
                local_path = parse[-1]
            else:
                local_path = remote_path

        self._openSFTPConnection()
        logger.info("File Get - remote:"+remote_path+" local:"+local_path)
        self.sftp.get(remote_path, local_path)

    def put(self, local_path, remote_path=None):
        """
        Copies a file from the local host to the remote host
        """
        if remote_path is None:
            if "/" in local_path:
                parse = local_path.split("/")
                remote_path = parse[-1]
            else:
                remote_path = local_path

        self._openSFTPConnection()
        logger.info("File Put - remote:"+remote_path+" local:"+local_path)
        self.sftp.put(local_path, remote_path)

    def close(self):
        """
        Close SFTP connection and ssh connection
        """
        if self.sftp_open:
            self.sftp.close()
            self.sftp_open = False
        self.transport.close()


class my_telnet():
    def __init__(self,host="",port=""):
        self.logFile = None
        self.session = None
        self.useLogin = True
        self.usePassword = True
        self.timeout = 60
        self.login_timeout = 10
        self.osType = "generic"
        self.host = host
        self.username = ""
        self.password = ""
        self.port = port
        self.rootuser = ""
        self.rootpassword = ""
        self.isDebug = isDebug
        #generic
        self.regex = {}
        self.regex["generic"] = {}
        self.regex["generic"]["any"] = []
        self.regex["generic"]["any"].append("[A-Za-z0-9_\-\.]+\@[A-Za-z0-9_\-\.]*[#%>]$")
        self.regex["generic"]["any"].append("[A-Za-z0-9_\-\.]+[#%>]$")
        self.regex["generic"]["any"].append("[%]$")
        self.regex["generic"]["any"].append(".*RP.*#$")
        self.regex["generic"]["end"] = []
        self.regex["generic"]["end"].append("]#")
        self.regex["generic"]["continue"] = []
        self.regex["generic"]["continue"].append(")---")
        self.regex["generic"]["continue"].append("--More--")
        self.regex["generic"]["continue"].append(" --More--")
        self.regex["generic"]["login"] = []
        self.regex["generic"]["login"].append("ogin:")
        self.regex["generic"]["login"].append("sername:")
        self.regex["generic"]["password"] = []
        self.regex["generic"]["password"].append("assword:")


    def write_raw_sequence(self, tn, seq):
        sock = tn.get_socket()
        if sock is not None:
            sock.send(seq)

    def readOutputGeneric(self, timeout):
        regex=self.regex["generic"]
        starttime=int(time.time())
        response = ""
        while True:
            if response is "":
                response = self.session.read_very_eager()
            else:
                response = response + self.session.read_very_eager()
            if self.osType == "generic":
                logger.debug("[raw]"+response)
                for item in regex["any"]:
                    if re.search(item, response.rstrip()):
                        return response
                        break
            for item in regex["end"]:
                if response.rstrip().endswith(item):
                    return response
            for item in regex["continue"]:
                if response.rstrip().endswith(item):
                    logging.debug(response)
                    time.sleep(1)
                    self.session.write(" ")
            curtime = int(time.time())
            if curtime - starttime > timeout:
                logging.error("<err:Output Timeout>")
                return response
                break


    def login(self):
        time.sleep(1)
        starttime=int(time.time())
        response = ""
        count = 0
        while count < 3:
            if self.useLogin:
                logger.debug("waiting for login prompt")
                isFound = False
                while not isFound:
                    if response is "":
                        response = self.session.read_very_eager()
                    else:
                        response = response + self.session.read_very_eager()
                    for item in self.regex["generic"]["login"]:
                        logger.debug("[<-raw recv] "+response)
                        logger.debug("check item = "+item)
                        if response.rstrip().endswith(item):
                            isFound = True
                            count = 10
                            logger.debug("login prompt found")
                            break
                    curtime = int(time.time())
                    if curtime - starttime > self.login_timeout:
                        count += 1
                        logging.error("<err:Timeout>")
                        self.session.write("\n")
                        time.sleep(2)
                        #return response
                        break
            logger.debug("[<-recv] "+response)
            logger.debug("[send user]"+self.username)
            if not isFound:
                continue
            self.session.write(self.username + "\n")

            time.sleep(3)
            if self.usePassword:
                logger.debug("waiting for password prompt")
                isFound = False
                while not isFound:
                    if response is "":
                        response = self.session.read_very_eager()
                    else:
                        response = response + self.session.read_very_eager()
                    for item in self.regex["generic"]["password"]:
                        logger.debug("[<-raw recv] "+response)
                        logger.debug("check item = "+item)
                        if response.rstrip().endswith(item):
                            isFound = True
                            break    
                    curtime = int(time.time())
                    if curtime - starttime > self.login_timeout:
                        #self.session.write(" ")
                        logging.error("<err:Timeout>")
                        #return response
                        break
            logger.debug("[<-recv] "+response)
            logger.debug("[send user]"+self.password)
            self.session.write(self.password + "\n")
    
            response = self.readOutputGeneric(self.timeout)
            logger.debug("[<-response] "+response)
            if "ncorrect" in response or "ailed" in response:
                logger.error("invalid credential")
                return 401
            else:
                logger.debug("telnet: login success")
                return 0


    def readLastLine(self, prompt):
        while True:
            line = self.session.read_very_eager()
            lines = re.split('\n|\r', line)
            if len(lines) > 0:
                line = lines[len(lines)-1]
            response = line.rstrip()
            if response.endswith(prompt):
                logger.debug("[<-recv] "+response)
                return response
                break

    def connect(self):
        self.session = telnetlib.Telnet(self.host, self.port)
        if self.isDebug:
            self.session.set_debuglevel(100)

    def login_old(self):
        time.sleep(1)
        response = ""
        count = 0
        while count < 3:
            if self.useLogin:
                response = self.session.read_until("ogin:", timeout=self.login_timeout)
                logger.debug("user response: "+response)
                if "ogin:" in response:
                    break
                self.session.write("\n")
                count += 1
        logger.debug("[send user]"+self.username)
        self.session.write(self.username + "\n")

        time.sleep(1)
        if self.usePassword:
            response = self.session.read_until("assword:", timeout=10)
            logger.debug("[<-recv] "+response)
            logger.debug("[send user]"+self.password)
            self.session.write(self.password + "\n")

        response = self.readOutputGeneric(self.timeout)
        logger.debug("[<-response] "+response)
        if "ncorrect" in response or "ailed" in response:
            logger.error("invalid credential")
            return 401
        else:
            logger.debug("login success")



    def logout(self):
            self.session.write("exit\n")
            self.session.close()

    def sendCmd(self, cmd):
        logger.debug("[send->]"+cmd)
        self.session.write((cmd).encode('ascii'))
        response = self.readOutputGeneric(self.timeout)
        logger.debug("[<-recv] "+response)
        return response



def jsonpretty(text):
    return json.dumps(text, indent=4)


def run_ssh_command(node, cmds):
    logger.debug("ssh connect: host="+node["ipv4"]+" port:"+node["port"])
    remote = my_ssh(host=node["ipv4"], username=node["username"], password=node["password"], port=int(node["port"]))
    lines = []
    lines.append(cmds)
    ret = []
    for line in lines:
        '''somehow if it is too early, cmd will fail'''
        logger.info("[send->]"+line)
        time.sleep(1)
        response = remote(line)
        logger.debug("[<-recv]"+response["output"])
        ret.append(response)
    return ret


def run_telnet_command(node, cmds, timeout=10, login_timeout=10, is_blind=False):
    tn = my_telnet(node["ipv4"], int(node["port"]))
    tn.username = node["username"]
    tn.password = node["password"]
    tn.timeout = timeout
    tn.login_timeout = login_timeout
    status = tn.connect()
    if status > 0:
        logger.error("can not connect to telnet port")
        return status, ""
    if not is_blind:
        status = tn.login()
        if status > 0:
            logger.error("telnet login failed")
            return status, ""

    lines = cmds.split(';')
    ret = []
    for line in lines:
        logger.info("[send->] "+line)
        response = {}
        response["command"] = line
        response["output"] = tn.sendCmd(line+"\n")
        logger.debug("[<-recv] "+line)
        ret.append(response)
    tn.timeout = 1
    if not is_blind:
        tn.logout()
    return 0, ret


def sftp_file(node, filename, action):
    sftp = my_sftp(host=node["ipv4"], username=node["username"], password=node["password"], port=int(node["port"]))
    if action == "upload":
        logger.info("upload file: "+filename)
        sftp.put(filename)
    else:
        logger.info("download file: "+filename)
        sftp.get(filename)
    sftp.close()
    return


def ftp_file(node, filename, action, mode="binary"):
    ftp = my_ftp(node["ipv4"], node["username"], node["password"])
    if isDebug:
        ftp.set_debuglevel(5)

    if action == "upload":
        ftp.upload(filename, mode)
    else:
        ftp.download(filename, mode)
    ftp.close()
    return


def read_command_file(configFile):
    cmds = ""
    logger.info("Reading config file: "+configFile)
    if configFile is not '':
        finput = open(configFile)
        lines = [x.replace('\n', '') for x in finput]
        finput.close()
        for line in lines:
            if cmds == "":
                cmds = line
            else:
                cmds = cmds+";"+line
    return cmds



'''main'''
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="netcli.py parameters")
    parser.add_argument('--ipv4', help='IPv4 of the target host' )
    parser.add_argument('--protocol', help='telnet,ssh,sftp,or ftp', nargs='?', const=1, default="ssh" )
    parser.add_argument('--username', help='username', nargs='?', const=1, default="admin" )
    parser.add_argument('--password', help='password', nargs='?', const=1, default="admin" )
    parser.add_argument('--port', help='TCP port' )
    parser.add_argument('--action', help='sftp action: upload or download', nargs='?', const=1, default="download" )
    parser.add_argument('--cmd', help='command')
    parser.add_argument('--cmdfile', help='command file')
    parser.add_argument('--filename', help='filename to be uploaded/downloaded')
    parser.add_argument('--telnet-blind', action='store_true', help='run telnet in blind/raw mode')
    parser.add_argument('--no-console-log', action='store_true', help='do not log anything to console')
    parser.add_argument('--debug', action='store_true', help='debug mode')
    args = parser.parse_args()

    logger = logging.getLogger(__name__)
    LOG_FORMAT = "%(levelname) -10s %(asctime)s %(name) -15s %(funcName) -20s %(lineno) -5d: %(message)s"
    LOG_FORMAT_CONSOLE = "%(message)s"
    
    hdlr = logging.handlers.RotatingFileHandler(filename="connect.log", mode='a', maxBytes=100000000, backupCount=20, encoding="utf8")
    hdlr.setFormatter(logging.Formatter(LOG_FORMAT))
    hdlr.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(hdlr)
    logging.getLogger().setLevel(logging.DEBUG)
    
    if not args.no_console_log: 
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter(LOG_FORMAT_CONSOLE))
        logging.getLogger().addHandler(ch)
        ch.setLevel(logging.INFO)
    
    cmd = ""
    cmdfile = ""
    node = {}
    
    try:
        if args.debug:
            isDebug = True
            
        if args.ipv4:
            node["ipv4"] = args.ipv4
        else:
            logging.error("Error: Please provide target host IP\n")
            sys.exit(1)
            
        node["username"] = args.username
        node["password"] = args.password
        node["protocol"] = args.protocol

        if args.port:
            node["port"] = args.port
        else:
            if args.protocol == "ssh" or args.protocol == "sftp":
                node["port"] = "22"
            else:
                node["port"] = "23"


        if args.protocol == "telnet" or args.protocol == "ssh":
            if args.cmd:
                cmd = args.cmd
            elif args.cmdfile:
                cmdfile = args.cmdfile
                cmd = read_command_file(args.cmdfile)
            else:
                logging.error("Error: Please provide command or command file\n")
                sys.exit(2)
   

        if node["protocol"] == "ssh":
            res = run_ssh_command(node, cmd)
            for item in res:
                logging.info(item["output"])

        if node["protocol"] == "ftp":
            if not args.filename:
                logging.error("Error: Please provide filename")
                sys.exit(1)
            ftp_file(node, args.filename, args.action)

        if node["protocol"] == "sftp":
            if not args.filename:
                looging.error("Error: Please provide filename")
                sys.exit(1)
            sftp_file(node, args.filename, args.action)
        
        if node["protocol"] == "telnet":
            if args.telnet_blind:
                status, res = run_telnet_command(node, cmd, timeout=30, is_blind=True)
            else:
                status, res = run_telnet_command(node, cmd, timeout=30, is_blind=False)
            for item in res:
                logging.info(item["output"])
    
    except Exception:
        logger.error(traceback.format_exc())
        sys.exit(1)
    sys.exit(0)



