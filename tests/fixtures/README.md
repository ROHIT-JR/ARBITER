# Composite certificate fixture

`lamps_composite_mldsa65_rsa3072_pss_draft07.pem` is the `x5c` certificate
for `id-MLDSA65-RSA3072-PSS-SHA512` from the IETF LAMPS working group's
[`draft-ietf-lamps-pq-composite-sigs-07` test vectors](https://github.com/lamps-wg/draft-composite-sigs/blob/draft-ietf-lamps-pq-composite-sigs-07/src/testvectors.json).
The JSON's base64 DER certificate was converted to PEM without altering its
contents. Its signature and public-key algorithm OID is
`2.16.840.1.114027.80.9.1.4` (the draft 07 prototype assignment).
