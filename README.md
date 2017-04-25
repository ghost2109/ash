# ASH
AWS (Amazon Web Services) Super Helper

Ash is a console application which helps you connect to your amazon instances and databases.

### Available commands  
<pre>
ssh         -- ssh to an ec2 instance.  
sendfile    -- scp a file to an ec2 instance.  
getfile     -- scp a file from an ec2 instance.  
list        -- lists all instances or the can specify a name to search for.  
db          -- creates an ssh tunnel to your ec2 instance then to your database.  
logs        -- dumps logs to the console from the ec2 instance  
docker      -- lets you run some docker commands on running containers 
</pre>
### Setup
Download ash.py
```
curl https://raw.githubusercontent.com/ghost2109/ash/master/ash.py > ash.py && chmod +x ./ash.py
```
### Command line options  
<pre>
--config   | creates ~/.ash/ash.json  
--debug    | turns on error reporting and creates and error log file in the current directory  
--upgrade  | checks for the latest version and gives you the option to upgrade to a new version  
</pre>
### First time running ash you will need to configure it
run ash
```
./ash.py
```
Type in config at the ash prompt press then space and hit tab twice to see the config options
```
(ASH /home/user/) 
::) config <tab><tab>
bucketRegion
dbSecurityGpLabel
dbuser
logs
pem
s3Bucket
sshSwitches
sshUser    
```
To configure an option type in 
```
config<space><config option>
```
### Config options
<pre>
dbSecurityGpLabel | db | AWS security group name  
bucketRegion      | db | AWS region for the DB connection ARN's and passwords file  
sshSwitches       | o  | Customs ssh switches to add example -oStrictHostKeyChecking=no  
s3Bucket          | db | AWS bucketname for the DB connection ARN's and passwords file  
sshUser           | r  | Default ssh username default is ec2-user  
dbuser            | db | Read only database user  
logs              | o  | Log file locations to you with the logs command  
pem               | r  | Location of the directory containing the aws instance pem files  
</pre>
r  -- required  
o  -- optional
db -- only need for db tunneling  

After you have configured ash run update to get the instances to connect with.
```
(ASH /home/user/) 
::) update
```
