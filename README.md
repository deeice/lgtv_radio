# lgtv_radio ![lgtuner](zipit/lgtuner.png)

Tiny command line tool to push internet radio URLs from a computer to an LG webOS TV and have it play them.

-------------------

The lgtv_radio tool tells the TV to launch the browser app and play the requested URL. 

With this tool I can now use the [ziptuner](https://github.com/deeice/ziptuner) 
on my PC (or on a Zipit Z2) to browse for interesting internet radio stations 
and command the LG TV over wifi to play them through the connected eARC soundbar.

The lgtv_radio tool can also tell the TV to play a single file from a local web server,
or dig into a .pls or .m3u file and tell the TV to play the first URL.  (The TV browser app doesn't do playlists on it's own)

The tool has a SCAN mode to find the TV IP address and a keygen mode to pair up to the TV and enable the control commands.  

It also has a STOP command, and VOLUME controls, so I don't need the TV remote.

```
Usage: 
 IP Scan Mode:  lgtv_radio SCAN
 Pairing Mode:  lgtv_radio <TV_IP>
 Control Mode:  lgtv_radio <TV_IP> <PAIRING_KEY> <COMMAND>
 <COMMAND> = <STREAM_URL> | STOP | VOL+ | VOL-
```
