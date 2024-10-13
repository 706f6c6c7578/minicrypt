# minicrypt
Encryption / decryption made easy, with Ed25519 and XChaCha20+poly1305.

This little tool is intended for Alice and Bob, exchanging small messages  
while handling one recipient only and producing no metadata!

It has only two commands -d for decryption and -g for key pair generation.  

For deterministic Ed25519 keys I recommend my [red](https://github.com/706f6c6c7578/red) program. 

That messages always have the same size, I recommend my [pad](https://github.com/706f6c6c7578/pad) program.
