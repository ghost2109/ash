#!/usr/bin/env python3
# Script: Amazon web services Super Helper (ash)
# Author: James Phillips
# Copyright (C) 2016-2017 ash

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from subprocess import Popen, PIPE, call, check_output
from os.path import expanduser
from functools import wraps
from cmd import Cmd
import threading
import datetime
import readline
import socket
import json
import time
import sys
import os
try:
    import boto3.session
    import boto3
except Exception as e:
    sys.exit("Please install boto3 with pip3 or pip( pip install boto3 )")

if 'libedit' in readline.__doc__:
    readline.parse_and_bind("bind ^I rl_complete")
else:
    readline.parse_and_bind("tab: complete")

if '--debug' in sys.argv:
    with open('./ash.error.log', 'w') as f:
        f.write('')

def log(msg):
    date = [datetime.datetime.now()]
    with open('./ash.error.log', 'a') as file:
        file.write(date[0].__str__().split('.')[0]+ ' | ' + msg + '\n')

def tbl(function):
  """try block log(tbl) try's the function you decorate, if an error happens then it's logged and display if --debug switch is used."""
  @wraps(function)
  def wrapper(*args, **kwargs):
      try:
          return function(*args, **kwargs)
      except Exception as error:
          if '--debug' in sys.argv:
              print("Function " + function.__name__ + " returned an error: " + error.args[0] + str(error))
              print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(error).__name__, error)
              log('Python ERROR ' "Function " + function.__name__ + " returned an error: " + error.args[0])
  return wrapper


class AwsConsole(Cmd):
    @tbl
    def __init__(self):

        # ASH version number
        self.version = '1.1.3'

        if '--upgrade' in sys.argv:
            v = check_output(['git', 'ls-remote', '--tags', 'https://github.com/ghost2109/ash'])
            latest = v.decode('utf-8').split('/')[2]
            file   = os.path.realpath(__file__)
            if latest != self.version:
                print('Current Version ', self.version)
                print('Latest Version', latest)
                print("file to update ", file)
                upgrade = input("Do you want to upgrade (y/n)? ")
                if upgrade == 'y':
                  new = check_output(['curl', 'https://raw.githubusercontent.com/ghost2109/ash/master/ash.py']).decode('utf-8')
                  with open(os.path.realpath(__file__), 'w') as f:
                    f.write(new)
                  print("ash has been upgraded run ash to start using it now!")

            exit()

        # Ash config directory
        self.configLocation = expanduser("~") + '/.ash/'

        # history file location
        self.histfile = self.configLocation + 'ash.history'

        # history file size
        self.histfile_size = 1000

        # configure config file and directory
        self._start_up()

        # List for instance data arrays
        self.config['instances'] = []

        # list for name to tab complete
        self.config['names'] = []

        # list for names to tab complete db access
        self.config['db'] = []

        # File names to load on start and to save on exit
        self.config['files'] = ['instances', 'names', 'db']

        # Auto complete list for config command
        self.config['configOpts'] = ['pem', 'sshUser', 'sshSwitches', 'logs', 'dbSecurityGpLabel', 'dbuser', 's3Bucket', 'bucketRegion']

        # Hidden methods (don't display in help or auto complete)
        self.__hiden_methods = ('do_EOF', '_load')

        # Misc header not used
        self.misc_header = ''

        # if no Doc string don't display in help menu
        self.undoc_header = None

        # Standard prompt for ash
        self.prompt = "(ASH " + os.getcwd() + ") \n::) "

        # Help header
        self.doc_header = 'type ? <command> for usage:\nNB: you can use <tab> to auto complete'

        # Header displayed at start up only
        self.intro  = """
    ___        ______    ____  _   _ ____  _____ ____    _   _ _____ _     ____  _____ ____  
   / \ \      / / ___|  / ___|| | | |  _ \| ____|  _ \  | | | | ____| |   |  _ \| ____|  _ \ 
  / _ \ \ /\ / /\___ \  \___ \| | | | |_) |  _| | |_) | | |_| |  _| | |   | |_) |  _| | |_) |
 / ___ \ V  V /  ___) |  ___) | |_| |  __/| |___|  _ <  |  _  | |___| |___|  __/| |___|  _ < 
/_/   \_\_/\_/  |____/  |____/ \___/|_|   |_____|_| \_\ |_| |_|_____|_____|_|   |_____|_| \_\
"""   

        super(AwsConsole, self).__init__()
        # Load instances from config files prompts for update if empty
        self._load_instances()                           
        
    @tbl
    def print_topics(self, header, cmds, cmdlen, maxcol):
        """Hide functions by putting them in self.__hiden_methods"""
        if header is not None:
          Cmd.print_topics(self, header, cmds, cmdlen, maxcol)

    @tbl
    def get_names(self):
        """overides get_names from cmd.Cmd module"""
        return [n for n in dir(self.__class__) if n not in self.__hiden_methods]

    @tbl    
    def do_version(self, line):
      print(self.version)

    @tbl
    def _start_up(self):
        if '--config' in sys.argv:
            data = {
                    "pem" : "~/pem/",
                    "s3Bucket" : "your-bucket-name-here!",
                    "bucketRegion" : "your-bucket-region-here!",
                    "dbSecurityGpLabel" : "-ec2-",
                    "sshUser" : "ec2-user",
                    "sshSwitches" : "",
                    "dbuser"  : "readonly",
                    "logs" : [
                              "/var/log/messages", 
                              "/var/log/dmesg"
                              ],
                    "regions": [
                              "eu-west-1",
                              "eu-west-2",
                              "eu-central-1",
                              "us-east-1",
                              "us-east-2",
                              "us-west-1",
                              "us-west-2",
                              "ca-central-1",
                              "ap-south-1",
                              "ap-northeast-2",
                              "ap-southeast-1",
                              "ap-southeast-2",
                              "ap-northeast-1",
                              "sa-east-1"
                              ]
                    }

            with open(self.configLocation+'ash.json', 'w') as file:
                json.dump(data, file)

        else:
            if not os.path.isfile(self.configLocation+'ash.json'):
                exit("run ash with --config option")

        # load config file into memory from the .ash directory
        with open(self.configLocation + 'ash.json') as data_file:    
          self.config = json.load(data_file)

    @tbl
    def preloop(self):
        if readline and os.path.exists(self.histfile):
            readline.read_history_file(self.histfile)
        else:
          f = open(self.histfile, 'w')
          f.close()

    @tbl
    def postloop(self):
        if readline:
            readline.set_history_length(self.histfile_size)
            readline.write_history_file(self.histfile)

    @tbl
    def _get_port(self, portRange):
        """Returns a port thats not in use for the db function"""
        ports = range(portRange[0], portRange[1])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for port in ports:
          if sock.connect_ex(('127.0.0.1', port)) != 0:
                return str(port)

        exit("No free network port")

    @tbl
    def _getConfigFile(self, file):
        """ Get config file from s3bucket """
        s3 = boto3.client('s3', region_name=self.config['bucketRegion'])
        return s3.get_object(Bucket=self.config['s3Bucket'] ,Key=file)['Body'].read().decode('utf-8')

    @tbl
    def _get_inst(self, line, split=False):
        """helper function returns instance from dict that matches name from line"""
        if split:
          s = line.split(':')
          name, ip = s[0], s[1].split(' ')[0]
        else:
          name = line.split(' ')[0]
          ip = ''

        if ip != '':
          inst = next( i for i in self.config['instances'] if i['name'] == name and i['ip'] == ip )
        else:
          inst = next( i for i in self.config['instances'] if i['name'] == name )
        return inst

    @tbl
    def _get_param(self, param, line, default=''):
        """helper function to get and set command line parameters"""
        params = line.split(' ')[1:]
        if param in params:
          if len(params) == 1:
            return 1
          else:
            return params[params.index(param)+1]
        else:
          return default

    @tbl
    def _complete(self, text, line, begidx, endidx, completelist):
        """helper function for tab auto complete"""
        if not text:
          completions = completelist[:]
        else:
          readline.set_completer_delims(" ")
          completions = [ name for name in completelist if name.startswith(text) ]
          completions = completions.sort()
        return completions

    @tbl
    def _load_instances(self):
        """Loads instance information from aws"""

        for file in self.config['files']:
          target = self.configLocation + file + '.json'
          if os.path.isfile(target):
                with open(target) as f:
                  self.config[file] = json.load(f)
          else:
                self.prompt = "(ASH " + os.getcwd() +") \n:: please run update) "

    @tbl
    def _load(self, region):
        """get all AWS instances in the specified region(s)"""
        #for region in regions:
        print(region)
        boto_session3 = boto3.session.Session()
        ec2    = boto_session3.resource('ec2', region_name=region)
        client = boto_session3.client(  'ec2', region_name=region)
        rds    = boto_session3.client(  'rds', region_name=region).describe_db_instances()['DBInstances'] 
        all_instances = ec2.instances.all()
        tmp        = {}
        for j in all_instances.page_size(5):
          if j.state['Name'] == "running":

            tmp['key_name']   = j.key_name
            tmp['id']         = j.instance_id
            tmp['sg']         = j.security_groups
            tmp['region']     = region
            tmp['dbEndpoint'] = []
            tmp['launchTime'] = str(j.launch_time)
            

            if len(j.network_interfaces_attribute) > 1:
              if j.network_interfaces_attribute[0]['PrivateIpAddress'] == j.private_ip_address:
                iface = 1
              else:
                iface = 0
              tmp['pip'] = j.network_interfaces_attribute[iface]['PrivateIpAddress']

              if j.public_ip_address != None:
                try:
                  if 'Association' in j.network_interfaces_attribute[iface].keys():
                    if 'PublicIp' in j.network_interfaces_attribute[iface]['Association'].keys():
                      tmp['ip']       = j.network_interfaces_attribute[iface]['Association']['PublicIp']
                    else:
                      tmp['ip'] = j.network_interfaces_attribute[iface]['PrivateIpAddress']
                except Exception as Error:
                  tmp['ip'] = j.network_interfaces_attribute[iface]['PrivateIpAddress']
              
              else:
                 tmp['ip'] = j.network_interfaces_attribute[iface]['PrivateIpAddress']
            else:
                tmp['ip']       = j.public_ip_address if j.public_ip_address != None else j.private_ip_address       
                tmp['pip']      = j.private_ip_address  

            for sg in j.security_groups:
              if self.config['dbSecurityGpLabel'] in sg['GroupName']:
                sgid = client.describe_security_groups(
                          Filters=[{'Name': 'ip-permission.group-id',
                          'Values': [sg['GroupId']]}])['SecurityGroups']
                if len(sgid) > 0:
                  for grp in sgid:
                    if '-rds-' in grp['GroupName']:
                      check = grp['GroupId']
                      for db in rds:
                        if len(db['VpcSecurityGroups']) > 0:
                          for id, item in enumerate(db['VpcSecurityGroups']):
                            if db['VpcSecurityGroups'][id]['VpcSecurityGroupId'] == check:
                              tmp['dbEndpoint'].append(db['Endpoint']['Address'])
                    else:
                      continue
                    
            for tag in j.tags:            
              if tag['Key'] == 'Name': 
                tmp['name'] = tag['Value']
            #print(tmp['name'], tmp['ip'])
            if 'name' not in tmp: tmp['name'] = ''    
            if 'dbEndpoint' not in tmp: tmp['dbEndpoint'] = []   
            if tmp['dbEndpoint'] != []: self.config['db'].append(tmp['name'])

            self.config['names'].append(tmp['name']+':'+tmp['ip'])
            self.config['instances'].append(tmp.copy())
            tmp['name']       = ''
            tmp['key_name']   = ''
            tmp['id']         = ''
            tmp['sg']         = ''
            tmp['region']     = ''
            tmp['dbEndpoint'] = []
            tmp['launchTime'] = ''
            tmp['ip']         = ''
            tmp['pip']        = ''

        return 0
   
    @tbl
    def _update(self, regions):
      print("Fetching instance data for:")
      for idx, region in enumerate(regions):
        t = threading.Thread(target=self._load, args=(region,))
        t.start()
      print("\n")
      time.sleep(0.1)
      l=['-', '/', '|', '\\']
      i=3
      while threading.activeCount() > 1:
        print('\rLoading', l[i], end='\r')
        i -=1
        if i < 0:
            i=3
        time.sleep(0.1)

    def do_update(self, line):
        """
Update ec2 instance cache
Usage:
update                   -- updates all instances
update <region>          -- updates the specified region
        """
        for item in ['db','instances','names']:
          del self.config[item][:]
        if line == '':
          self._update(self.config['regions'])
        else:
          self._update([line])
        self.prompt = "(ASH " + os.getcwd() +") \n::) "
        self.save_maybe_exit()
        #call(['clear'])
        print("Updated instance list")

    @tbl
    def complete_update(self, text, line, begidx, endidx):
        """Auto complete for update function"""
        return self._complete(text, line, begidx, endidx, self.config['regions'])

    @tbl
    def do_ls(self, line):
        """Simple ls"""
        print(line)
        args = line.split(' ')
        cmd = ['ls', '--color']
        if len(args) > 0 and args[0] != '':
          cmd.extend(args)
        call(cmd)

    @tbl
    def do_cd(self, line):
        """Simple cd"""
        if line == '':
          os.chdir(expanduser("~"))
        else:
          os.chdir(line)
        self.prompt = "(ASH " + os.getcwd() +") \n::) "

    @tbl
    def do_list(self, line):
        """
List instances with ip and db endpoint.
Usage: 
list                     -- lists all instances
list <search>            -- lists all instances that contain the search term
        """
        if self.config['instances'] == []:
          print("you need to run update") 
        if line == '':  
          for i in self.config['instances']:        
                print('{:<30} {:<20} {:<20}{}'.format(i['name'], i['ip'], i['pip'], i['dbEndpoint']))
        else:
          for i in self.config['instances']:
                if line.split(':')[0] in i['name']:
                  print('{:<30} {:<20} {:<20}{}'.format(i['name'], i['ip'], i['pip'], i['dbEndpoint']))

    @tbl
    def complete_list(self, text, line, begidx, endidx):
        """Auto complete for ssh function"""
        return self._complete(text, line, begidx, endidx, self.config['names'])

    def do_launched(self, line):
        """
List instances with ip and db endpoint.
Usage: 
launch                     -- lists all instances
launch <search>            -- lists all instances that contain the search term
        """
        if self.config['instances'] == []:
            print("you need to run update") 
        if line == '':  
          for i in self.config['instances']:        
              print(i['launchTime'], i['name'], i['ip'])
        else:
          for i in self.config['instances']:
                if line.split(':')[0] in i['name']:
                    print(i['launchTime'], i['name'], i['ip'], i['launchTime'])

    @tbl
    def complete_launched(self, text, line, begidx, endidx):
        """Auto complete for ssh function"""
        return self._complete(text, line, begidx, endidx, self.config['names']).sort()


    @tbl
    def do_ssh(self, line):
        """
change ash config
usage:
ssh <name>               -- creates an ssh connection to the specified instance
ssh <name> -i            -- ssh to the instance on the internal ip
ssh <name> -u <username> -- same as above with the specified username
        """
        user = self._get_param('-u', line, default=self.config['sshUser'])
        inst = self._get_inst(line, split=True)
        pip  = self._get_param('-i', line)

        ip = inst['pip'] if pip else inst['ip']
        print("\n###########################")
        print(" Connecting with...")
        print(" USER "+ user)
        print(" KEY: " + inst['key_name']+".pem")
        print(" IP : " + ip)
        print("###########################\n")
        sshcall = ['ssh', '-i', self.config['pem'] + inst['key_name'] + '.pem', user+'@'+ip, self.config['sshSwitches']]
        if '' in sshcall:
          sshcall.remove('')
        error = call(sshcall)
        call(['clear'])

    @tbl
    def complete_ssh(self, text, line, begidx, endidx):
        """Auto complete for ssh function"""
        return self._complete(text, line, begidx, endidx, self.config['names'])

    @tbl
    def do_config(self, line):
        """
ssh to an aws instance
usage:
config <name> <setting>  -- name is the config option you wish to configure
        """
        config = line.split(' ')[0]
        opt = ', '.join(self.config[config]) if config == 'logs' else self.config[config]
          
        print('\nConfig option is currently set to', opt)
        if input('Do you want to change it? ') == 'y':
          if config == 'logs':
            newOpt = []
            item = input('Please enter a new log location: ')
            newOpt.append(item)
            while item != '':
              item = input('Please enter a new log location(just hit enter to finish): ')
              newOpt.append(item)
          else:
            newOpt = input('Please enter the new config value: ')
          self.config[config] = newOpt
          file = self.config.copy()
          for item in ['db','instances','names', 'files', 'configOpts']:
            del file[item]
          with open(self.configLocation + 'ash.json', 'w') as f:
                  json.dump(file, f)
        else:
          pass
    
    @tbl
    def complete_config(self, text, line, begidx, endidx):
        """Auto complete for ssh function"""
        return self._complete(text, line, begidx, endidx, self.config['configOpts'])

    @tbl
    def do_logs(self, line):
        """
Displays aws instance log of your choice
usage:
logs <name>              -- <name> aws instance Name tag
logs <name> -u <username>-- change default ssh username 
        """
        for idx, log in enumerate(self.config['logs']):
          print("[",idx,"]", log)
        
        num = int(input("Select logs to display [ 0 - "+str(len(self.config['logs'])-1)+" ]: "))
        
        command = 'sudo cat ' + self.config['logs'][num]
        print(command)
        user = self._get_param('-u', line, default=self.config['sshUser'])
        inst = self._get_inst(line, split=True)
        
        sshcall = ['ssh', self.config['sshSwitches'], '-i', self.config['pem'] + inst['key_name'] + '.pem', user+'@'+inst['ip'], command]
        if '' in sshcall:
          sshcall.remove('')

        p = Popen(sshcall, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        rc = p.returncode
        
        print(output.decode('utf-8'))

    @tbl
    def complete_logs(self, text, line, begidx, endidx):
        """Auto complete for logs function"""
        return self._complete(text, line, begidx, endidx, self.config['names'])

    @tbl
    def do_docker(self, line):
        """
Displays the docker containers running on the aws instance, select one and it runs docker logs on that container
usage:
dockerlogs <name>               -- <name> aws instance Name tag
dockerlogs <name> -u <username> -- change default ssh username 
        """
        user = self._get_param('-u', line, default=self.config['sshUser'])
        inst = self._get_inst(line, split=True)

        sshcall = ['ssh', self.config['sshSwitches'], '-i', self.config['pem'] + inst['key_name'] + '.pem', user+'@'+inst['ip'], 'docker ps && exit']
        if '' in sshcall:
          sshcall.remove('')

        p = Popen(sshcall, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        rc = p.returncode
        dockerps = output.decode('utf-8').split('\n')[1:-1]
        for idx, item in enumerate(dockerps):
          print("[",idx,"]\n", item)
        numof = len(dockerps)
        num = int(input("Please select a docker container [ 0 - "+str(numof -1)+" ]"))
        print(dockerps[num].split(' ')[0])
        dockerCommandList = ['logs', 'inspect', 'stop']
        for idx, command in enumerate(dockerCommandList):
          print("[", idx, "]", command)
        dockerCmd = int(input("Please select a docker command [ 0 - "+str(len(dockerCommandList) -1)+" ]"))
        command = "docker " + dockerCommandList[dockerCmd] + ' ' + dockerps[num].split(' ')[0] + " && exit"
        print(command)
        a = ['ssh', self.config['sshSwitches'],'-t', '-i', self.config['pem'] + inst['key_name'] + '.pem', user+'@'+inst['ip']]
        if '' in a:
          a.remove('')
        a.extend(command.split(' '))
        p = Popen(a, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        rc = p.returncode
        print(output.decode('utf-8'))

    @tbl
    def complete_docker(self, text, line, begidx, endidx):
        """Auto complete for dockerlogs function"""
        return self._complete(text, line, begidx, endidx, self.config['names'])

    @tbl
    def do_sendfile(self, line):
        """
send file to an aws instance
usage:
sendfile <name>           -- aws ec2 tag name
                -u <username>     -- change default ssh username
                -f <path to file> -- location including file name
                -d <ServerDir>    -- upload directory        (Default: ~/)
        """
        user  = self._get_param('-u', line, default=self.config['sshUser'])
        file  = self._get_param('-f', line, default='')
        todir = self._get_param('-d', line, default='~/')
        inst  = self._get_inst(line, split=True)

        sshcall = ['scp', self.config['sshSwitches'], '-i', self.config['pem'] + inst['key_name'] + '.pem', file, user+'@'+inst['ip']+':'+todir]
        if '' in sshcall:
          sshcall.remove('')

        error = call(sshcall)
        call(['clear'])
        if error == 0: print("Sent file ", file, 'to location: ', todir )

    @tbl
    def complete_sendfile(self, text, line, begidx, endidx):
        """Auto complete for sendfile function"""
        return self._complete(text, line, begidx, endidx, self.config['names'])

    @tbl
    def do_getfile(self, line):
        """
get file from an aws instance
usage:
getfile <name>            -- aws ec2 tag name
                -u <username>     -- change default ssh username 
                -f <path to file> -- location including file name
                -d <localDir>   -- download directory      (Default: ./)
        """
        user  = self._get_param('-u', line, default='ec2-user')
        file  = self._get_param('-f', line, default='')
        todir = self._get_param('-d', line, default='./')
        inst  = self._get_inst(line, split=True)

        sshcall = ['scp', self.config['sshSwitches'], '-i', self.config['pem'] + inst['key_name'] + '.pem', user+'@'+inst['ip']+':'+file, todir]
        if '' in sshcall:
          sshcall.remove('')

        error = call(sshcall)
        call(['clear'])
        if error == 0:
          print("Received file ", file, 'location: ', todir )
          self.do_ls()

    @tbl     
    def complete_getfile(self, text, line, begidx, endidx):
        """Auto complete for getfile function"""
        return self._complete(text, line, begidx, endidx, self.config['names'])

    @tbl
    def do_console(self, line):
        """
get file from an aws instance
usage:
console <name>            -- Get EC2 instance console output
        """
        inst  = self._get_inst(line, split=True)

        boto_session3 = boto3.session.Session()
        ec2    = boto_session3.client('ec2', region_name=inst['region'])

        stdOut = ec2.get_console_output(InstanceId=inst['id'])
        print(stdOut['Output'])
    
    @tbl               
    def complete_console(self, text, line, begidx, endidx):
        """Auto complete for getfile function"""
        return self._complete(text, line, begidx, endidx, self.config['names'])

    @tbl
    def do_db(self, line):
        """
Tunnel to Database
Usage:
db <name>                -- creates ssh tunnel to specified instance then starts mysql client
db <name> -u <username>  -- change default ssh username 
db <name> -c             -- creates ssh tunnel and runs mysql client
db <name> -p <port>      -- creates ssh tunnel with the specified port
db <name> -rp <port>     -- creates ssh tunnel with the specified remote port
        """
        localport   = self._get_param('-p', line) if self._get_param('-p', line) else self._get_port((10000, 11000))
        remoteport  = self._get_param('-rp', line) if self._get_param('-rp', line) else 3306
        inst        = self._get_inst(line)
        user        = self._get_param('-u', line, default=self.config['sshUser'])
        cmd         = self._get_param('-c', line)

        if len(inst['dbEndpoint']) > 1:
          for idx, i in enumerate(inst['dbEndpoint']):
            print(idx, i)

          endpoint = inst['dbEndpoint'][int(input("Please select a db [ 0 - "+ str(len(inst['dbEndpoint'])-1)+" ] : "  ))]
        else:
          endpoint = inst['dbEndpoint'][0]

        self.config['tunnel'] = json.loads(self._getConfigFile('locker/readonly2.json'))

        dbLt = endpoint.split('.')[0].split('-')
        if len(dbLt) >= 3:
          if 'ea' in dbLt[2]:
            env = 'ea'
          elif 'qa' in dbLt[2]:
            env = 'qa'
          else:
            env = 'prod'

          passwd = self.config['tunnel'][dbLt[0]][dbLt[1]][env]
        
        else:
          passwd = self.config['tunnel'][dbLt[0]]

        sshcall = ['ssh', self.config['sshSwitches'], '-i', self.config['pem'] + inst['key_name'] + '.pem', user+'@'+inst['ip'], '-L', localport+':'+endpoint+':'+str(remoteport), '-N']
        if '' in sshcall:
          sshcall.remove('')      
        tunnel = Popen(sshcall)

        if isinstance(tunnel.pid, int):
          call(['clear'])
          print("database tunnel to ", endpoint, 'on port ', localport, '\n', 'user is '+self.config['dbuser']+' and the password is',passwd+"\nRemote port: "+ str(remoteport))
          time.sleep(1)
          if cmd:
            sshcall = ['mysql', '-h', '127.0.0.1', '--port='+localport, '-u',self.config['dbuser'], '-p'+passwd ]
            if '' in sshcall:
              sshcall.remove('')
            mysql = Popen(sshcall)
            mysql.wait()
            tunnel.kill()
          else:
            input("Press Enter to close the tunnel")
            tunnel.kill()
    
    @tbl
    def complete_db(self, text, line, begidx, endidx):
        """Auto complete for db function"""
        return self._complete(text, line, begidx, endidx, self.config['db'])

    @tbl
    def do_glowroot(self, line):
        """
Tunnel to Database
Usage:
db <name>                -- creates ssh tunnel to specified instance to map glowroot to localhost
db <name> -u <username>  -- change default ssh tunnel username 
db <name> -p <port>      -- creates ssh tunnel with the specified port
        """
        localport   = self._get_param('-p', line) if self._get_param('-p', line) else self._get_port((39000, 39999))
        inst        = self._get_inst(line, split=True)
        user        = self._get_param('-u', line, default=self.config['sshUser'])
        
        sshcall = ['ssh', self.config['sshSwitches'], '-i', self.config['pem'] + inst['key_name'] + '.pem', user+'@'+inst['ip'], '-L', localport+':localhost:4000', '-N']
        if '' in sshcall:
          sshcall.remove('')      
        tunnel = Popen(sshcall)
        call(['clear'])
        print("glowroot tunnel to ", inst['name'], 'on port ', str(localport))
        print("http://localhost:" + str(localport))
        input("Press Enter to close the tunnel")
        tunnel.kill()
  
    @tbl
    def complete_glowroot(self, text, line, begidx, endidx):
        """Auto complete for db function"""
        return self._complete(text, line, begidx, endidx, self.config['names'])

    @tbl
    def do_flush(self, line):
        """
Remove json config files
Usage:
flush                    -- removes instance config files from filesystem
        """
        for item in ['db','instances','names']:
          del self.config[item][:]

        for file in self.config['files']:
          target = self.configLocation + file + '.json'
          if os.path.isfile(target):
                call(['rm', target])
                print('Removed', target)
          else:
                print(target, "Doesn't exist or can't be deleted")
   
    @tbl
    def save_maybe_exit(self, exit=0):
        """helper function to dump data to disk and maybe exit"""
        for file in self.config['files']:
          target = self.configLocation + file + '.json'
          if self.config[file] != []:
                with open(target, 'w') as f:
                  json.dump(self.config[file], f)
        self.postloop()
        if exit:
          sys.exit()
    
    @tbl
    def do_EOF(self, line):
        """Catches <CTL>+d and executes save_maybe_exit"""
        call(['clear'])
        self.save_maybe_exit(exit=1)

    @tbl
    def do_exit(self, line):
        """
Exit command to quit ash, please not you can also use <CTL>+d
Usage:
exit
        """
        self.save_maybe_exit(exit=1)

    @tbl
    def cmdloop(self):
        call(['clear'])
        print(self.intro)
        while True: 
            self.preloop()
            self.intro = ''
            try:
                super(AwsConsole, self).cmdloop()
                self.postloop()
                break
            except KeyboardInterrupt:
                ans = input('Do you wish to exit ash y/n ? ')
                if ans == 'y': 
                  call(['clear'])
                  self.save_maybe_exit(exit=1)

if __name__ == '__main__':
    console = AwsConsole()
    if any( x for x in ['v', '-v', 'version', '--version'] if x in sys.argv):
      print(console.version)
      exit()
    call(['clear'])
    console.cmdloop()
