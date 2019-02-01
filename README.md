hccapx-helpers
==============

Small scripts made to ease some manipulations with .hccapx files. Intended to work with Python 3.

* `hccapx_print.py` - print .hccapx contents
* `hccapx_uniq.py` - filter out duplicate handshakes in order to reduce bruteforce time. Handshakes considered duplicate if <MAC_STA; ESSID> pair matches.
