bencgen --in client_root_key.benc --out ../cert --file rootkey --lang go
bencgen --in handshake_packet.benc --out ../handshake --file packet --lang go
bencgen --in server_certificate.benc --out ../cert --file servercert --lang go