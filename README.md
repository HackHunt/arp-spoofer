## ARP Spoofer

- Sends an ARP ***is-at*** request to the router and the target to spoof.
- Easy to be MitM with this.

### Why ARP Spoofing is possible?
- Clients accept reponses even if they do not send a request.
- Clients trust reponse without any form of verification.

### Supports Platform: Linux, Debain

### How to use:
- Convert the setup.sh into executable
	> **chmod 755 setup.sh**
- Run setup.sh
	> **./setup.sh**
- Run the Python Script with root privileges.
    > **sudo python3 arp_spoofer.py** 

### Available Arguments:
- **-h or --help:** *Displays all the available options.*
- **-i or --interface**: *Required. Define interface you want to start spoofing.*
- **-r or --router:** *Required. Define the router’s IP address.*
- **-t or --target:** *Required. Define the target’s IP address.*

- **Note:** You need to be connected to the same network as this program is based on ARP Request Protocol.

### Color:
- **Green:** Successful.
- **Yellow:** In process.
- **System Color:** Result.
- **Red:** Unsuccessful or Errors. 

### Programming Language: Python 3.8

### Libraries Used:
- **subprocess:** The *subprocess* module allows you to spawn new processes, connect to their
input/output/error pipes, and obtain their return codes. Used to interact with command line
arguments.
- **argparse:** The *argparse* module makes it easy to write user-friendly command-line interfaces. The
program defines what arguments it requires, and argparse will figure out how to parse those out of
sys.argv.
- **re:** The *re (Regular Expression or regex)* module is used to search within a string using a sequence
of characters that define a search pattern. It is use to check the IP address enter by the user.
- **sys:** The *sys* module provides access to some variables used or maintained by the interpreter and
to functions that interact strongly with the interpreter.
- **scapy:** The *scapy* module enables the user to send, sniff and dissect and forge network packets.
This capability allows construction of tools that can probe, scan or attack networks.
- **time:** The *time* (Time access and conversions) module provides various time-related functions. It is used
to send packets every certain seconds not continously.
- **termcolor:** The *termcolor* module is used for ANSII color formatting for
output in terminal.

### Licensed: GNU General Public License, version 3

### Developer Information:
- **Website:** [Hack Hunt](https://hack-hunt.blogspot.com/)
- **Contact:** hh.hackunt@gmail.com
- **Youtube:** [Hack Hunt](https://youtube.com/hackhunt) 
- **Instagram:** [hh.hackhunt](https://www.instagram.com/hh.hackhunt/)
- **Facebook:** [hh.hackhunt](https://www.facebook.com/hh.hackhunt/)
- **Twitter:** [hh_hackhunt](https://twitter.com/hh_hackhunt/)
