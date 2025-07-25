# TomTP

A UDP-based transport protocol that takes an "opinionated" approach, similar to QUIC but with a focus 
on providing reasonable defaults rather than many options. The goal is to have lower complexity, 
simplicity, and security, while still being reasonably performant.

TomTP is peer-to-peer (P2P) friendly, meaning a P2P-friendly protocol often includes easy integration
for NAT traversal, such as UDP hole punching, multi-homing, where data packets can come from different 
source addresses, or out of band public key exchange. It does not have a TIME_WAIT state that could exhaust 
ports and it does not open a socket for each connection, thus allowing many short-lived connections.

In TomTP, there is 1 supported crypto algorithm (curve25519/chacha20-poly1305) as in contrast to TLS with
many options. It is mentioned [here](https://www.cs.auckland.ac.nz/~pgut001/pubs/bollocks.pdf) that there 
are 60 RFCs for TLS. However, the [Wikipedia](https://en.wikipedia.org/wiki/Transport_Layer_Security) site 
only mentions 9 primary RFCs and 48 extensions and informational RFCs, totalling 57 RFC.

## Similar Projects

* https://github.com/Tribler/utp4j
* https://github.com/quic-go/quic-go
* https://github.com/skywind3000/kcp (no encryption)
* https://github.com/johnsonjh/gfcp (golang version)
* https://eprints.ost.ch/id/eprint/846/
* https://eprints.ost.ch/id/eprint/879/
* https://eprints.ost.ch/id/eprint/979/

## Features / Limitations

* Public key of the recipient transfer is out of band (e.g., TXT field of DNS), or in band.
* Always encrypted (curve25519/chacha20-poly1305) - renegotiate of shared key on crypto sequence number overflow
* Support for streams, but flow and congestion control is done at the connection level
* 0-RTT (first request always needs to be equal or larger than its reply -> fill up to MTU and no 
  perfect forward secrecy)
* User decides on perfect forward secrecy. 2 options: a) no perfect forward secrecy for 1st message 
  if payload is sent in first message (request and reply). b) perfect forward secrecy with empty first message  
* FIN/ACK teardown with timeout (no 3-way teardown as in TCP)
* Goal: less than 3k LoC

## Assumptions

* Every node on the world is reachable via network in 1s. Max RTT is 2sec
* Packets are identified with sequence offset + length (similar to QUIC). Length is 16bit, as an IP packet has a 
  maximum length of 64KB.
* Initial paket size is 1400 (QUIC has 1200).
* Receiver window max size is 64bit
* Sequence offset is 64bit similar to QUIC with 62bit. Also, since packets are identified with
  offset/length and length is 16bit. Current buffer sizes for 100 Gb/s cards are 
  [2GB](https://fasterdata.es.net/host-tuning/linux/100g-tuning/), which is already the 
  maximum ([max allowed in Linux is 2GB-1](https://fasterdata.es.net/host-tuning/linux/)). So 32bit with 4GB is being 
  already the limit, and a new protocol needs to support more. What about 48bit? A worst case reorder with packets in 
  flight for 1sec is when the first packet arrives last and with a buffer of 2^48 bytes (256TB). Thus, what is the 
  in-flight bandwidth that can handle worst case for 1 second: 48bit is 2^48 * 8 -> 2.3 Pb/s
    * Current fastest speed: 22.9 Pb/s - multimode (https://newatlas.com/telecommunications/datat-transmission-record-20x-global-internet-traffic/)
    * Commercial: 402 Tb/s - singlemode (https://www.techspot.com/news/103584-blistering-402-tbs-fiber-optic-speeds-achieved-unlocking.html)
  So, 64bit should be enough for the foreseeable future.

## Messages Format (encryption layer)

The current version is 0. The available types are:

* 000b: INIT_HANDSHAKE_S0
* 001b: INIT_HANDSHAKE_R0
* 010b: INIT_WITH_CRYPTO_S0
* 011b: INIT_WITH_CRYPTO_R0
* 100b: DATA_0 for rollover at crypto sequence number 0
* 101b: DATA (everything else)
* 110b: not used
* 111b: not used

The available types are not encrypted as packets may arrive twice, and we need to know
how to decode them.

### Type INIT_HANDSHAKE_S0, min: 1400 bytes (due to filler, no data, since no encryption)

Minimum is 1400 bytes to prevent amplification attacks. Since it's not encrypted, no payload can be sent. 
S0 means, it's only sent by the sender at sequence number 0. Connection Id is set randomly, and the corresponding
R0 needs to reply with the same random connection Id. 

```mermaid
---
title: "INIT_HANDSHAKE_S0 Packet"
---
packet-beta
  0-4: "Version"
  5-7: "Type"
  8-71: "Connection Id (64bit), based on pub_key_ep_snd"
  72-327: "Public Key Sender Id (X25519)"
  328-583: "Public Key Sender Ephemeral (X25519)"
  584-839: "Public Key Sender Ephemeral Rollover (X25519)"
  840-841: "Fill up to 1400 bytes (example 1 byte)"
```

### Type INIT_HANDSHAKE_R0, min: 136 bytes (112 bytes until payload + min payload 8 bytes + 16 bytes MAC)

The reply can contain data as it can be encrypted with perfect forward secrecy. In order to get data, INIT_HANDSHAKE_S0
needs to fill up so that we can get data here. R0 means, it's only sent by the receiver at sequence number 0. The
random connection Id after this message will be deleted, and the proper pubIdRcv Xor pubIdSnd is used. 

```mermaid
---
title: "INIT_HANDSHAKE_R0 Packet"
---
packet-beta
  0-4: "Version"
  5-7: "Type"
  8-71: "Connection Id (64bit), same as in INIT_HANDSHAKE_S0"
  72-327: "Public Key Receiver Id (X25519)"
  328-583: "Public Key Receiver Ephemeral (X25519)"
  584-839: "Public Key Receiver Ephemeral Rollover (X25519)"
  840-887: "Double Encrypted Crypto Sequence Number (48bit)"
  888-951: "Data (variable, but min 8 bytes)"
  952-1079: "MAC (HMAC-SHA256) (128bit)"
```

### Type INIT_WITH_CRYPTO_S0, min: 138 bytes (114 bytes until payload + min payload 8 bytes + 16 bytes MAC)

If we have a crpyto key, we can already encrypet with the first message, but it will no non-perfect forward secrecy. The
user can decide if he wants to send data. S0 means, it's only sent by the sender at sequence number 0.

```mermaid
---
title: "INIT_WITH_CRYPTO_S0 Packet"
---
packet-beta
  0-4: "Version"
  5-7: "Type"
  8-71: "Connection Id (64bit), based on pub_key_ep_snd"
  72-327: "Public Key Sender Id (X25519)"
  328-583: "Public Key Sender Ephemeral (X25519)"
  584-839: "Public Key Sender Ephemeral Rollover (X25519)"
  840-887: "Double Encrypted Crypto Sequence Number (48bit)"
  888-903: "Filler length (16bit), example 1 byte"
  904-911: "Fill, example 1 byte"
  912-975: "Data (variable, but min 8 bytes)"
  976-1103: "MAC (HMAC-SHA256)"
```

### Type INIT_WITH_CRYPTO_R0, min: 104 bytes (80 bytes until payload + min payload 8 bytes + 16 bytes MAC)

R0 means, it's only sent by the receiver at sequence number 0.

```mermaid
---
title: "INIT_WITH_CRYPTO_R0 Packet"
---
packet-beta
  0-4: "Version"
  5-7: "Type"
  8-71: "Connection Id (64bit), same as in INIT_WITH_CRYPTO_S0"
  72-327: "Public Key Receiver Ephemeral (X25519)"
  328-583: "Public Key Receiver Ephemeral Rollover (X25519)"
  584-631: "Double Encrypted Crypto Sequence Number (48bit)"
  632-695: "Data (variable, but min 8 bytes)"
  696-823: "MAC (HMAC-SHA256) (128bit)"
```

### Type DATA_0, min: 71 bytes (47 bytes until payload + min payload 8 bytes + 16 bytes MAC)

0 means, it's only sent at sequence number 0.

```mermaid
---
title: "DATA_0 Packet"
---
packet-beta
  0-4: "Version"
  5-7: "Type"
  8-71: "Connection Id (64bit), old connection id, before rollover"
  72-327: "Public Key Sender/Receiver Ephemeral Rollover (X25519)"
  328-375: "Double Encrypted Crypto Sequence Number (48bit)"
  376-439: "Data (variable, but min 8 bytes)"
  440-567: "MAC (HMAC-SHA256) (128bit)"
```

### Type DATA, min: 40 bytes (16 bytes until payload + min payload 8 bytes + 16 bytes MAC)
```mermaid
---
title: "DATA Packet"
---
packet-beta
  0-4: "Version"
  5-7: "Type"
  8-71: "Connection Id (64bit)"
  72-119: "Double Encrypted Crypto Sequence Number (48bit)"
  120-183: "Data (variable, min. 8 bytes)"
  184-311: "MAC (HMAC-SHA256) (128bit)"
```

The length of the complete INIT_R0 needs to be same or smaller INIT_S0, thus we need to fill up the INIT message. 
The pubKeyIdShortRcv (first 64bit) XOR pukKeyIdShortSnd (first 64bit) identifies the connection Id (connId) for multi-homing.

The connection establishmet works as follows. The notation:

Id public key of Alice id: pub_id_alice
Id private key of Alice id: prv_id_alice
Ephemeral public key of Alice id: pub_ep_alice
Ephemeral private key of Alice id: prv_ep_alice

```mermaid
sequenceDiagram
  Note left of Sender: Alice gets the pub_id_receiver out of band
  Sender->>Receiver: INIT_S0: send pub_id_sender, pub_ep_sender, encrypt with: prv_ep_sender, pub_id_receiver
  Note right of Receiver: Bob creates a new prv_ep_receiver/pub_ep_receiver
  Note right of Receiver: From here on we have perfect forward secrecy
  Receiver->>Sender: INIT_R0, send pub_ep_receiver, encrypt with: pub_ep_sender, prv_ep_receiver
  Note left of Sender: Sender creates a new prv_ep_receiver_rollover/pub_ep_receiver_rollover
  Sender->>Receiver: INIT_S1: send pub_ep_sender_rollover, encrypt with: prv_ep_sender, pub_ep_receiver
  Note right of Receiver: Receiver creates a new prv_ep_receiver_rollover/pub_ep_receiver_rollover
  Receiver->>Sender: INIT_R1, send pub_ep_receiver_rollover, encrypt with: pub_ep_sender, prv_ep_receiver
  Sender->>Receiver: DATA: send data, encrypt with: prv_ep_sender, pub_ep_receiver
  Receiver->>Sender: DATA: send data, encrypt with: pub_ep_sender, prv_ep_receiver
```

We need to store 3 shared keys at most. During rollover, if we received rollover packets and waiting for non-rollover packets,
we need to have both keys, and on rollover with the crypto sequence number 1, there will be new keys for the next rollover.
Thus, we need to store at most 3. 

### Double Encryption with Encoded Sequence Number

Similar to QUIC, TomTP uses a deterministic way to encrypt the sequence number and payload. However, TomTP uses twice
chacha20poly1305. The `chainedEncrypt` function handles the double encryption process for messages,
particularly focusing on encoding and encrypting the sequence number. Here's a detailed breakdown of how it works:

First Layer Encryption:

1. Create a deterministic nonce with the sequence number. TomTP uses 6 bytes for sequence numbers and ChaCha20-Poly1305
   uses a 12 bytes nonce. Thus, a sender puts its sequence number in the first 0-6 bytes, the receiver puts its 
   sequence number in the last 6-12 bytes to avoid collision. 
1. Use standard ChaCha20-Poly1305 to encrypt the payload data with this nonce
1. Include any header/crypto data as additional authenticated data (AAD) 
1. The resulting ciphertext must be at least 24 bytes to allow for nonce extraction

Second Layer Encryption:

1. Take the first 24 bytes (16bytes MAC + 8 bytes payload, hence we need a min. of 8 bytes payload) of the first 
encryption result as a random nonce
1. Use XChaCha20-Poly1305 to encrypt just the sequence number
1. Take only the first 6 bytes (48 bits) of this encrypted sequence number (we drop the MAC)

The final message structure is:

* Header/crypto data (unencrypted, but signed)
* Second layer ciphertext sequence number (6 bytes)
* First layer ciphertext (including authentication tag)

Decryption reverses this process using the same shared secret:

First Layer Sequence Number Decryption:

1. Extract the first 24 bytes from the first layer ciphertext as random nonce.
1. Use XChaCha20-Poly1305 with the shared secret to decrypt the 6-byte encrypted sequence number.
1. No authentication is needed since a wrong sequence number will cause the second layer to fail.

Second Layer Payload Decryption:

1. Generate the same deterministic nonce with the sequence number. (sender - 0-6 bytes, recipient 6-12 bytes)
1. Use standard ChaCha20-Poly1305 with this nonce and shared secret
1. Include the header/crypto data as additional authenticated data (AAD)
1. Decrypt and authenticate the first layer ciphertext
1. If authentication succeeds, return the decrypted sequence number and payload

The scheme ensures that tampering with either the sequence number or payload will cause authentication to fail during 
the second layer decryption. The deterministic nonce binds the sequence number to the payload, while the random nonce 
from the first encryption adds unpredictability to the sequence number encryption.

## Encrypted Payload Format (Transport Layer) - min. 8 Bytes (without data)

To simplify the implementation, there is only one payload header.

```mermaid
---
title: "TomTP Payload Packet"
---
packet-beta
  0: "S/R"
  1-2: "ACK/PAK"
  3-7: "RCV_WND_SIZE" 
  8-39: "Opt. ACKs: Example ACK: StreamId 32bit"
  40-63: "Opt. ACKs: Example ACK: StreamOffset 24/48bit"
  64-79: "Opt. ACKs: Example ACK: Len 16bit"
  80-111: "StreamId 32bit"
  112-135: "StreamOffset 24/48bit"
  136-143: "Data..."
```
The TomTP payload packet begins with a header byte containing several control bits:

* Bit 0 is the "S/R" flag which distinguishes between sender and receiver roles.
* Bits 1-2: 
  * 0: No ACK/Data with 24bit,
  * 1: No ACK/Data with 48bit,
  * 2: ACK with 24bit/Data with 24bit, 
  * 3: ACK with 48bit/Data with 48bit,
* Bits 3-7: Receiver window size: 1024 << (bits - 1), 31 is not used for rcv, but means CLOSE. Max receiver size is 512GB

If ACK bit is present then:

* Bytes 8-39 contain the StreamId (32 bits)
* Bytes 40-63 hold the StreamOffset (24 or 48 bits)
* Bytes 64-79 contain the Len field (16 bits)

The Data section:

* Bytes 80-111 contain the StreamId (32 bits)
* Bytes 112-135 hold the StreamOffset (24 or 48 bits)

Only if data length is greater than zero:

* Bytes 136-... and beyond contain the actual data payload

### Overhead
- **Total Overhead for Data Packets:**  
  47 bytes (crypto header 39 bytes + payload header 8 bytes) with 0 data (for a 1400-byte packet, this results in an overhead of ~3.3%).

### Communication States and Corner Cases

This is a list of things that could go wrong and will go wrong and how they are handled

## Handshake: packet loss 1
```mermaid
sequenceDiagram
    participant Alice
    participant Network
    participant Bob
    
    Note over Alice, Bob: Test - Testing 1 retransmission with success
    
    Alice->>Network: Send Packet 1 (data="hallo1")
    Note over Network: Packet 1 gets lost
    
    Note over Alice: Wait for RTO timer (250ms + 1μs)
    
    Alice->>Network: Retransmit Packet 1
    Network->>Bob: Packet arrives successfully
    
    Note over Bob: First time receiving (isNew=true)
```

## Handshake: packet loss 2
```mermaid
sequenceDiagram
participant Alice
participant Network
participant Bob

    Note over Alice, Bob: TestRTOTimes4Success - Testing multiple retransmissions with success
    
    Alice->>Network: Send Packet 1 (data="hallo1") at t=0
    Note over Network: Packet 1 gets lost
    
    Note over Alice: Wait for RTO timer (250ms + 1μs)
    Alice->>Network: Retransmit Packet at t=250ms+1μs
    Note over Network: Retransmission 1 gets lost
    
    Note over Alice: Wait for RTO timer (687ms + 2μs)
    Alice->>Network: Retransmit Packet at t=687ms+2μs
    Note over Network: Retransmission 2 gets lost
    
    Note over Alice: Wait for RTO timer (1452ms + 3μs)
    Alice->>Network: Retransmit Packet at t=1452ms+3μs
    Note over Network: Retransmission 3 gets lost
    
    Note over Alice: Wait for RTO timer (2791ms + 4μs)
    Alice->>Network: Retransmit Packet at t=2791ms+4μs
    Network->>Bob: Packet arrives successfully
    
    Note over Bob: First time receiving (isNew=true)
```

## Handshake: Timeout
```mermaid
sequenceDiagram
participant Alice
participant Network
participant Bob

    Note over Alice, Bob: TestRTOTimes4Fail - Testing multiple retransmissions with failure
    
    Alice->>Network: Send Packet 1 (data="hallo1") at t=0
    Note over Network: Packet 1 gets lost
    
    Note over Alice: Wait for RTO timer (250ms + 1μs)
    Alice->>Network: Retransmit Packet at t=250ms+1μs
    Note over Network: Retransmission 1 gets lost
    
    Note over Alice: Wait for RTO timer (687ms + 2μs)
    Alice->>Network: Retransmit Packet at t=687ms+2μs
    Note over Network: Retransmission 2 gets lost
    
    Note over Alice: Wait for RTO timer (1452ms + 3μs)
    Alice->>Network: Retransmit Packet at t=1452ms+3μs
    Note over Network: Retransmission 3 gets lost
    
    Note over Alice: Wait for RTO timer (2791ms + 4μs)
    Alice->>Network: Retransmit Packet at t=2791ms+4μs
    Note over Network: Retransmission 4 gets lost
    
    Note over Alice: Wait for RTO timer (5134ms + 5μs)
    Note over Alice: Error occurs - Maximum retransmissions exceeded
```

## Handshake Garbage 1
```mermaid
sequenceDiagram
    participant Alice
    participant Network
    participant Bob
    Note over Alice, Bob: TestGarbage1 - Return garbage
    Alice->>Network: Garbage
    Network->>Bob: Garbage
    Note over Bob: Print error
```


## Handshake Garbage 2
```mermaid
sequenceDiagram
    participant Alice
    participant Network
    participant Bob
    
    Note over Alice, Bob: TestGarbage1 - Return garbage
    
    Alice->>Network: Send Packet 1 (data="hallo1")
    Network->>Bob: Packet arrives successfully
    
    Note over Bob: Bob is in a weird state

    Bob->>Network: Garbage
    Network->>Alice: Garbage
    
    Note over Alice: Print error
```

### LoC

```
echo "Source Code LoC"; ls -I "*_test.go" | xargs tokei; echo "Test Code LoC"; ls *_test.go | xargs tokei

Source Code LoC
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 Go                     16         3532         2668          300          564
 Markdown                1          457            0          362           95
===============================================================================
 Total                  17         3989         2668          662          659
===============================================================================
Test Code LoC
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 Go                     14         3812         2831          386          595
===============================================================================
 Total                  14         3812         2831          386          595
===============================================================================


```