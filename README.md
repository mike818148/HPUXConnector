# HPUXConnector

This connector is a custom connector for SailPoint IdentityIQ to support HP-UX application type. It uses Jsch to implement SSH shell command 
to execute command on target system. 

## Getting Started

These instructions will guide you to install and deploy HPUXConnector on your local SailPoint IdentityIQ application for development and testing purposes. 
You are welcome to trace the source or customized on your own requirements.

### Prerequisites

1. SSH should be installed on HP-UX target server.
2. Rights or privilege required.

Following Rights are needed with root privilege:

```
/bin/chmod, /usr/sbin/useradd, /usr/sbin/usermod, /usr/sbin/userdel, /usr/sbin/groupadd, /usr/sbin/groupmod,
/usr/sbin/groupdel, /usr/bin/passwd, /usr/bin/last, /usr/bin/groups, /bin/rm, /bin/echo, /usr/bin/chage,
/usr/bin/find, /bin/cat /etc/shadow, /bin/cat /etc/passwd, /bin/cat /etc/group, /usr/bin/etc/pwget, /usr/bin/grget, 
/bin/grep, /usr/bin/awk, /user/bin/id, /usr/sbin/userdbset, /usr/lbin/modprpw, /usr/sbin/userstat
```

If you want to use sudo user to perform operations, sudo user must be configured with the following rights and permissions,
An entry in /etc/sudoers file should look similar to the following:

```
username ALL = (root) PASSWD:/bin/chmod, /usr/sbin/useradd, /usr/sbin/usermod, /usr/sbin/userdel, /usr/sbin/groupadd,
/usr/sbin/groupmod, /usr/sbin/groupdel, /usr/bin/passwd, /usr/bin/last, /usr/bin/groups, /bin/rm, /bin/echo, /usr/bin/chage,
/usr/bin/find, /bin/cat /etc/shadow, /bin/cat /etc/passwd, /bin/cat /etc/group, /usr/bin/etc/pwget, /usr/bin/grget, 
/bin/grep, /usr/bin/awk, /user/bin/id, /usr/sbin/userdbset, /usr/lbin/modprpw, /usr/sbin/userstat
```
### Installing

#### Compile and Deploy


Ant build script is configured under /HPUXConnector/build.xml could manage that compilation and deployment. 
(Replace directory names and project name with names appropriate to the specific installation.)
Make sure that the build.xml is a part of your java project, and does not reside at a location that is external to the project.

To enable Ant view by following:

```
Windows > Show View > Other > Ant > Ant
```
Your Ant View should like this:

![alt text](https://github.com/mike818148/HPUXConnector/blob/master/HPUXConnectorAnt.PNG "Logo Title Text 1")

Click Complie button, will export jar file under /HPUXConnector/build/jar folder

Move /HPUXConnector/build/jar/HPUXConnector.jar and /HPUXConnector/lib/jsch-0.1.54.jar under ~/identityiq/WEB-INF/lib

And repeat

```
until finished
```

End with an example of getting some data out of the system or using it for a little demo

## Running the tests

Explain how to run the automated tests for this system

### Break down into end to end tests

Explain what these tests test and why

```
Give an example
```

### And coding style tests

Explain what these tests test and why

```
Give an example
```

## Deployment

Add additional notes about how to deploy this on a live system

## Built With

* [Dropwizard](http://www.dropwizard.io/1.0.2/docs/) - The web framework used
* [Maven](https://maven.apache.org/) - Dependency Management
* [ROME](https://rometools.github.io/rome/) - Used to generate RSS Feeds

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **Billie Thompson** - *Initial work* - [PurpleBooth](https://github.com/PurpleBooth)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to anyone who's code was used
* Inspiration
* etc
