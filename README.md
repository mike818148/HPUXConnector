# HPUXConnector

This connector is a custom connector for SailPoint IdentityIQ to support HP-UX application type. It uses Jsch to implement SSH shell command 
to execute command on target system. 

## Getting Started

These instructions will guide you to install and deploy HPUXConnector on your local SailPoint IdentityIQ application for development and testing purposes. 
You are welcome to trace the source or customized on your own requirements.

### Prerequisites

1. SSH should be installed on HP-UX target server.
2. Download Jsch library to implement SSH shell commands on target system. For example of Jsch [Link](http://www.jcraft.com/jsch/examples/) 
3. Rights or privilege required.

Following Rights are needed with root privilege:

```
/bin/chmod, /usr/sbin/useradd, /usr/sbin/usermod, /usr/sbin/userdel, /usr/sbin/groupadd, /usr/sbin/groupmod,
/usr/sbin/groupdel, /usr/bin/passwd, /usr/bin/last, /usr/bin/groups, /bin/rm, /bin/echo, 
/usr/bin/find, /bin/cat /etc/shadow, /bin/cat /etc/passwd, /bin/cat /etc/group, /usr/bin/etc/pwget, /usr/lbin/getprpw
/bin/grep, /usr/bin/awk, /user/bin/id, /usr/sbin/userdbset, /usr/lbin/modprpw, /usr/sbin/userstat
```

If you want to use sudo user to perform operations, sudo user must be configured with the following rights and permissions,
An entry in /etc/sudoers file should look similar to the following:

```
username ALL = (root) PASSWD:/bin/chmod, /usr/sbin/useradd, /usr/sbin/usermod, /usr/sbin/userdel, /usr/sbin/groupadd,
/usr/sbin/groupmod, /usr/sbin/groupdel, /usr/bin/passwd, /usr/bin/last, /usr/bin/groups, /bin/rm, /bin/echo, 
/usr/bin/find, /bin/cat /etc/shadow, /bin/cat /etc/passwd, /bin/cat /etc/group, /usr/bin/etc/pwget, /usr/lbin/getprpw 
/bin/grep, /usr/bin/awk, /user/bin/id, /usr/sbin/userdbset, /usr/lbin/modprpw, /usr/sbin/userstat
```
### Installing

### Support Features
AUTHENTICATE: NO
CREATE: SUPPORT (TESTED)
DELETE: SUPPORT (TESTED)
DISCOVER_SCHEMA: NO
DISABLE: SUPPORT (Disable with clear password)
ENABLE: SUPPORT (Enable with reset default password workaround)
READ: SUPPORT (Manage Account Refresh with issue)
GET: SUPPORT
ITERATE: SUPPORT
PERMISSIONS: NO
SET_PASSWORD: SUPPORT
UNLOCK: SUPPORT
UPDATE: SUPPORT

### Shadow Utility
Unlike Linux system, by default, HP-UX Basic mode doesn't contain shadow utility, this usually cause error while we try to use Linux - Direct connector to do provisioning on HP-UX systems. The /etc/passwd file format is basic the same as other unix/linux systems: 
login name: \
encrypted password: \
numerical user ID: \
numerical group ID: \
reserved gecos ID: \
initial working directory: \
program to use as shell: \
The major difference is the encrypted password field, normally for Linux system such as CentOS and Red Hat, to disable an account, a character can be user, normally ' ! ', to prevent user login. However, for HP-UX the character usually is ' * ', this will lead to an unexpected behavior if we are using Linux - Direct connector to integrate HP-UX systems, which makes IIQ always display Active for all aggregated accounts even if account has been disabled on target system.  
 
Another difference is that the password aging for basic mode is implemented by appending comma with a non-null string at the end of the encrypted password field. The first character of age, M, indicates the maximum number of weeks of valid password. User attempt to login with an expired password will be forced to submit a new password. The next character, m, indicates the minimum period in weeks that must expire before the password can be changed. The remaining two characters define the week when the password was last changed (a null string is equivalent to zero).
 
In order to enhance security, we can use pwconv command to convert the /etc/passwd encrypted password field to /etc/shadow format. If /etc/shadow not exists it will generate a new one. If the password aging information exists it will also be moved to shadow file. The /etc/passwd encrypted password field will be replaces with 'x' in each /etc/passwd entries.

### Password Aging Information
With no shadow file and untrusted mode, instead, HP-UX stored password-related information in the /etc/passwd password aging information in the password field.

Inside password field, aging information comes with a comma and followed up with a non-null string. Normally there are 4 digits followed by the comma, the characters for each digit represent a different value. '.' stands of 0,'/' for 1, '0-9' represent 2-11, 'A-Z' represent 12-37, 'a-z' represent 38-63. There are total 64-character set for each digit.

The first digit M in the aging information is the maximum number of weeks which password is valid; the second digit m is the minimum period of weeks before the password can be changed. The last two digits represent the week when password last changed. Note: password warning time is not available with untrusted system, unless change to trusted system or equipped with shadow utility.
E.g.
test:QivQg0wjFWQf6,7.3b:109:20::/home/test:/sbin/sh
In above entry, we find "7.3b" after the comma inside the password field.
7 represents M (pwdmax) in 64-character set map to value 9, means 9 maximum weeks which password is valid.
'.' represents m (pwdmin) in 64-character set map to value 0.
3b represents the last password change time.

#### Compile

Ant build script is configured under /HPUXConnector/build.xml could manage that compilation and deployment. 
(Replace directory names and project name with names appropriate to the specific installation.)
Make sure that the build.xml is a part of your java project, and does not reside at a location that is external to the project.

To enable Ant view in Eclipse do following:

```
Windows > Show View > Other > Ant > Ant
```
Your Ant View should like this, Click Complie button, will export jar file under /HPUXConnector/build/jar folder:

![alt text](https://github.com/mike818148/HPUXConnector/blob/master/HPUXConnectorAnt.PNG "Logo Title Text 1")

#### Configure

* Move /HPUXConnector/build/jar/HPUXConnector.jar and /HPUXConnector/lib/jsch-0.1.54.jar under ~/identityiq/WEB-INF/lib

* Move /HPUXConnector/HPUXAttributesForm.xhtml under ~/identityiq/define/applications

* Start IIQ and import /HPUXConnector/HP-UX-Direct.xml

## Deployment

Add additional notes about how to deploy this on a live system

## Built With

* SailPoint OpenConnector
* [Jsch Library](http://www.jcraft.com/jsch/)

## Contributing

Please reference document [Compass - Custom Connector](https://community.sailpoint.com/docs/DOC-4793) for more about architecture of IIQ Custom Connector for details and other examples.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/mike818148/HPUXConnector/tree/master/HPUXConnector). 

## Authors

Origin author: Mikg Chung, Gamatech Ltd.

## License

This project is licensed under the Gamatech Ltd. Hong Kong - using MIT License see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* [Compass] Custom Connectors, authored by Michael Hovis, Jennifer Mitchell and Thomas Crumley
