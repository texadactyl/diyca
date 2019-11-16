Overview
--------

*** Python 3 only ***

(Python 2 is deprecated in 2020)

*** It is very important to follow docs/preparation_notes.txt precisely. ***

This git project constitutes a Do-It-Yourself Certificate Authority (diyca), suitable for unit testing (developer testing) just prior to entering integration system testing with a wider audience: more developers, end-users, and/or auditors.  A web server approach is used in obtaining an X.509 certificate signed by this unit testing CA, based on a Certificate Signing Request (CSR) provided by the user, employing a web browser (Firefox, Safari, etc.).

The inspiration of this project is the myriad of Internet of Things (IoT) projects that might be falling into one of the following categories of undesirable patterns:

* No data security at all: (1) no authentication of the endpoints, (2) no message integrity checking, and (3) data is transmitted over the network in cleartext.
* Partners are using weak cryptography (E.g. RC4 or Single-DES) and there is no secure methodology of installing or managing the secret keys.  E.g. coding the secret keys as program constants.
* Partners are using strong secret key cryptography but there is no secure methodology of installing or managing the secret keys.  E.g. The secret keys are never changed.

Even when developers agree to securely use public key infrastructure and strong cryptography, I have seen cases where they stub this aspect out of their project during unit testing.  This just puts off the inevitable and may cause project delays when the stubs are later replaced with operational code.  Better to design and develop a project from the very beginning as it is intended to be in production.

Therefore, the primary goal of this project is to allow developers to unit test programs which make use of X.509 certificate based authentication and cryptography.  Thus, when it is time to migrate to more stringent testing environments (E.g. integrated system testing and user acceptance testing), the only thing new will be the target environment details since the developers will have gained experience with a Certificate Authority operations, X.509 certificates, and managing the user's private key.

This project is already proven running the web server on an Intel/AMD environment (Biostar Celeron board) and a Raspberry Pi 2 & 3 (ARM 32-bit processor with 1GB RAM).

Licensing
---------

This is *NOT* commercial software; instead, usage is covered by the GNU General Public License version 3 (2007).  In a nutshell, please feel free to use the project and share it as you will but please don't sell it.  Thanks!

See the LICENSE file for the GNU licensing information.

Getting Started
---------------

Subfolders:

* app_web - Python 3 source code for the web server running in a Flask infrastructure
            (see docs/preparation_notes.txt for references to all of the supporting software
            as well as how to install, test, etc.)
* bin - Bash scripts for setting up diyca and other tools
* calvin - Self-signed Certificate Authority
* certs - Calvin's certificate and the web server's certificate
* docs - project documentation (admittedly, skimpy at the moment)
* example.users - example SSL programs that use certificates signed by Calvin, "alice" and "bob"
* log - Holds all of the log files which cutoff at midnight; aged to keep a maximum of 10 files
* signer - uploaded CSRs (temporarily) and downloaded CRTs (accumulating, for the moment)

The starting point with this project is the docs/preparation_notes.txt file.  Follow the instructions therein precisely with possible exceptions related to Raspbian set up changes or bugs that you found (please open an issue).

External Package Dependencies
-----------------------------
```
dnspython
flask
pyopenssl
sqlite3
werkzeug
```

Feel free to contact richard.elkins@gmail.com for inquiries and issues, especially if you find any bugs.  I'll respond as soon as I can.

Richard Elkins

Dallas, Texas, USA, 3rd Rock, Sol, ...
