# packet_analyzer_tshark

Packet analyzer CLI program written in Python with PyShark.

Run this command to run this program and tshark without root on Linux
```
sudo usermod -a -G wireshark $USER
```

Apply the new group membership without logging out and back in
```
newgrp wireshark
```