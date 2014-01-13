CRET
====
This is a simple tool to execute commands on a remote
computer running a Windows OS. It is able to use both
remote services or WMI.

Using remote services, an executable will be copied and
started as a service on the remote host to receive and
execute commands.

Using WMI, commands are passed through WMI, and a service
will be copied only for interactivity (otherwise it won't
be copied).

How to use it
=============
Just launch the executable :]

Authors
=======
Adrien Chevalier

Improvements
============
- fix the repeating input problem
- change the error code to non printable chars
