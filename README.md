# DFA on AES--Python Implementation
This is a python implementation of the DFA attack on AES. The faults are injected at the beginning of the 8th round. 
In this particular code, we target the 0th byte of the 8th round input for fault injection. Also, we need two correct-faulty ciphertext pairs, in this case, to recover 4 key bytes of the last round key. It is two be noted that the attack can be performed only with a 
single correct-faulty ciphertext pair (in fact, the entire 16-byte key can be recovered). However, in order to make the code faster, and easy
to follow, we simplify the attack a bit.
