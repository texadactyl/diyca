# diyca
D.I.Y. Certificate Authority

The contents of this git project constitutes "D.I.Y. Certificate Authority".

The inspiration of this project is the myriad of Internet of Things (IoT) projects that are often falling into one of the following categories of undesirable habits:
* No data security at all: (1) no authentication of the endpoints, (2) no message integrity checking, and (3) data is transmitted over the network in cleartext.
* Partners are using weak cryptography (E.g. RC4 or Single-DES) and there is no secure methodology of managing the secret keys.
* Partners are using strong secret key cryptography but there is no secure methodology of managing the secret keys.

The purpose of this project is to allow developers to unit test programs which make use of X509 certificate based authentication and cryptography.  Thus, when it is time to migrate to more stringent testing environments (E.g. integrated system testing and user acceptance testing), the only thing new will be the environment since the developers will have already dealt with a Certificate Authority (CA), the user certificate signed by the CA, and the user's private key.

This is *NOT* commercial software; instead, usage is covered by the GNU General Public License version 3 (2007).

See the license.txt and gplv3.txt files for licensing information.

Feel free to contact richard.elkins@gmail.com for inquiries and issues, especially if you find any bugs.  I'll respond as soon as I can.

Documentation is in the docs subfolder.

Richard Elkins

Dallas, Texas, USA, 3rd Rock, Sol
