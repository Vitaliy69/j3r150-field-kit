#!/usr/bin/env python3
"""Historical dummy-cryptogram probe; its results are retained in transcripts.

The original used the defective PC/SC binding and compared multiple commands
inside a failed session. It cannot provide a controlled case-3/case-4 result.
"""
import sys

if __name__ == "__main__":
    sys.exit("Historical probe archived. See transcript 42 for the independent GPPro run; "
             "use open_channel.py with documented keys for a normal handshake.")
