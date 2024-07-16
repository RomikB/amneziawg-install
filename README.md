# AmneziaWG installer

**This project is a bash script that aims to setup a [AmneziaWG](https://docs.amnezia.org/ru/documentation/amnezia-wg/) VPN on a Linux server, as easily as possible!**

## Requirements

Supported distributions:

- AlmaLinux >= 9
- Debian >= 11
- Rocky Linux >= 9
- Ubuntu >= 20.04

others can work but not tested

## Usage

Before installation it is strictly recommended to upgrade your system to the latest available version and perform the reboot afterwards.

Download and execute the script. Answer the questions asked by the script and it will take care of the rest.

```bash
wget https://raw.githubusercontent.com/romikb/amneziawg-install/main/amneziawg-install.sh
chmod +x amneziawg-install.sh
./amneziawg-install.sh
```

It will install AmneziaWG (kernel module and tools) on the server, configure it, create a systemd service and a client configuration file.

Run the script again to add or remove clients!
