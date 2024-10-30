# kinetra.de/net

A library to handle secure TCP connections over a custom protocol.  
**Warning:** This library is not complete and contains unfinished code.

## Security

**kinetra.de/net** uses AES-256 for data encryption, ECDH P521 for key exchange, and ECDSA P521 for signing.

## Data Encoding

To efficiently encode data, **kinetra.de/net** utilizes [benc](https://github.com/deneonet/benc) as its serializer.

## Key Rotations

If the private key of the server's certificate is compromised or just expired, simply generate a new one and update the client's root key as well. **cosair.gg** encodes a version field into the certificate and root key to verify that the client is always in sync with the server. If the versions do not match, a clear error will be returned.

## Generating Certificates

As simple as `go run kinetra.de/net/gen -v {VERSION_NUMBER}`, everything is done locally on your machine. To ensure that the root key is in sync with the certificate, it will be generated as well.

## The Handshake Process

1. **[Client]**: I want your certificate to prove your identity as **[Server]**.  
2. **[Server]**: Sure, here’s my certificate.  
3. **[Client]**: I'll check the signature using my root key, verifying that the public key was not compromised, is not expired, and matches the expected version.  
4. **[Client]**: I verified it; it's valid. Here’s my public key. I'll create a shared secret using your public key.  
5. **[Server]**: I have the shared secret now too. Let me verify that we have the same and that your public key was not compromised as well. I’ll send you an encrypted message using the shared secret.  
6. **[Client]**: I successfully decrypted the message. Our connection is now secure!

## Examples

Find examples [here](https://github.com/deneonet/cosair.gg-net-examples).
