# The batch keyset

## Values

```
ENC (CDKenc) 90379A3E7116D455E55F9398736A01CA
MAC (CDKmac) 473F36161A7F7F60CC3A766EA4BE5247
DEK (CDKdek) D3749ED4FF42FD58B39EEB562B017CD9
```

## Where they came from

1. Our card (serial I500738213, batch PI260905-2133) rejected the factory developer keyset 404142434445464748494A4B4C4D4E4F with "Card cryptogram invalid".
2. GlobalPlatformPro discussion #382 (Feb 2025) documents the same card model from a marketplace, with three seller-supplied key values under the label "J3R150 TK". They failed for that buyer in every mode he tried.
3. An Ozon review of the same card stream (Jul 2026) quotes the same three values and reports a successful key reset with them.

## How they were verified

The host checks the card cryptogram from INITIALIZE UPDATE before sending
EXTERNAL AUTHENTICATE. A mismatch rejects the candidate keyset locally.
The full channel-opening command still authenticates after a match; it is
not an offline-only key checker. We did not measure this card's retry limit.

## Scope

Marketplace batches move together. Both cards of our order carry this keyset. If your card is from a different batch, verify the same way before attempting anything: the check is free, the write operations are not.
