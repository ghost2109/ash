# ASH
AWS (Amazon Web Services) Super Helper

Ash is a console application which helps you connect to your amazon instances and databases.

### Available commands 
ssh         -- ssh to an ec2 instance.  
sendfile    -- scp a file to an ec2 instance.  
getfile     -- scp a file from an ec2 instance.  
list        -- lists all instances or the can specify a name to search for.  
db          -- creates an ssh tunnel to your ec2 instance and maps to a local port in the 10000 - 20000 then open mysql cli.  
logs        -- dumps logs to the console from the ec2 instance  
dockerlogs  -- lists running containers on an instance for you to select and run docker logs <instanceId>  
