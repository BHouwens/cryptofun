# Key Exchange

Key exchange protocols make up a vital part of many crucial security protocols, such as TLS for securing communications on the Web and the Signal protocol for securing messages exchanged in applications such as WhatsApp. Typically, establishment of secret, symmetric keys is achieved via key agreement or key transport. 

*Key agreement* refers to the process by which communicating entities agree on key material in such a way that both entities contribute information to the key material, and that neither entity can pre-determine the value of the key. 

*Key transport* describes the process by which a symmetric key is securely transferred from one entity to another.

..

## Xenotta KE Protocols

The key exchange (KE) protocols available for use in Xenotta's cryptographic library are the following:

- *Diffie-Hellman*: Key agreement protocol between two parties
- *XMerkle Puzzle Board*: A modified and strengthened version of Merkle puzzle board key generation
