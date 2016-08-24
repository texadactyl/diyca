# diyca
D.I.Y. Certificate Authority

The contents of this git project constitutes a Do-It-Yourself Certificate Authority.

The inspiration of this project is the myriad of Internet of Things (IoT) projects that are often falling into one of the following categories of undesirable patterns:

* No data security at all: (1) no authentication of the endpoints, (2) no message integrity checking, and (3) data is transmitted over the network in cleartext.
* Partners are using weak cryptography (E.g. RC4 or Single-DES) and there is no secure methodology of installing or managing the secret keys.  E.g. coding the secret keys as program constants.
* Partners are using strong secret key cryptography but there is no secure methodology of installing or managing the secret keys.  E.g. The secret keys are never changed.

Even when developers agree to securely use public key infrastructure and strong cryptography, I have seen cases where they stub this aspect out of their project during unit testing.  This can result in umpleasant surprises during integrated system testing and lead to project delays.  Better to design and develop a project from the beginning as it is intended to be in production.

The primary goal of this project is to allow developers to unit test programs which make use of X509 certificate based authentication and cryptography.  Thus, when it is time to migrate to more stringent testing environments (E.g. integrated system testing and user acceptance testing), the only thing new will be the environment details since the developers will have experience with a Certificate Authority, certificates, and the user's private key.

The project is already proven on an Intel/AMD environment.  A secondary purpose of this project is to support the installation on ARM 32-bit or 64-bit devices such as the Raspberry Pi 2/3 or the Pine A64(+).

This is *NOT* commercial software; instead, usage is covered by the GNU General Public License version 3 (2007).  In a nutshell, please feel free to use the project and share it as you will but please don't sell it.  Thanks!

See the license.txt and gplv3.txt files for the GNU licensing information.

Feel free to contact richard.elkins@gmail.com for inquiries and issues, especially if you find any bugs.  I'll respond as soon as I can.

Documentation is in the docs subfolder.

Richard Elkins

Dallas, Texas, USA, 3rd Rock, Sol
