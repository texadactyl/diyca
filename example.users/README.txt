The "example.users" directory tree under "diyca" hold 2 sample SSL applications:

	alice =======(SSL)=========> bob
    [client]                     [server]

In the "alice" subdirectory, a datagen.py application was added to generate
some data for alice to transmit to bob.

bob simply echos anything sent to him back to the client.

================================================================

Before you can run alice and bob, you need to do the following:
	Install the Python OpenSSL module (`sudo pip install pyopenssl`).
	Generate a private key and a Certificate Signing Requests (CSR) for both.
	Get Calvin (your CA) to sign the CSRs and return certificates for both.
	Make sure that you have a copy of Calvin's trusted certificate.

Positioned in example.users, using a terminal window, execute:
	bin/1.gen_keys_csrs.sh
	bin/2.run_datagen.sh

The private keys and Certificate Signing Requests (CSR) for alice and bob are complete.
Next, pay close attention to bin/3.README.txt !!

Once you have completed the first 3 steps, you are ready to run alice and bob.

In one terminal window, start bob (the SSL server):
	bin/4.run_bob.sh

In a 2nd terminal window, start alice (the SSL client):
	bin/5.run_alice.sh
