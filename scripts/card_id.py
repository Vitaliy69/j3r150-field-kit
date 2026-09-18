#!/usr/bin/env python3
"""Read-only SELECT/ATR check; does not authenticate or list the registry."""
import sys
from pcsc_mac import CardConnection


def main():
    with CardConnection() as card:
        print("ATR:", card.atr().hex().upper())
        isd = bytes.fromhex("A000000151000000")
        sw, data = card.transmit([0, 0xA4, 4, 0, len(isd)] + list(isd) + [0],
                                 "SELECT ISD", has_le=True)
        if sw != "9000":
            sys.exit(f"ISD SELECT failed: {sw}")
        print(f"ISD FCI ({len(data)} bytes): {data.hex().upper()}")
        print("VERDICT: card answered SELECT; ISD keys were not tested or changed.")


if __name__ == "__main__":
    main()
