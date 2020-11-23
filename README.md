# Java---BeastAttack

This replicates the “BEAST” attack on SSL and TLS version 1.0 from 2011. 
There is a plaintext which is encrypted by the executable "encrypt". We are able to add a prefix of length at most 8 before the plaintext and we know that "encrypt" uses CBC block encryption. 

It can be observed that the initialisation vector for each encryption is linearly dependent on time. Therefore we can predict this and repeatedly try different prefixes to recover the plaintext.
