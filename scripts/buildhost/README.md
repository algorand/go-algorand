buildhost
====================

## Installing the build host ##

run the following on a fresh image:

```bash
git clone https://github.com/algorand/go-algorand
cd go-algorand/scripts/buildhost
sudo ./configure.sh
```

following that, configure the environment variables by typing
```bash
nano service_env.sh
```

and start the service
```bash
sudo systemctl start buildhost
```


## Developer notes - Creating a tap interface on an EC2 machine using netplan ##

```bash
cd /etc/netplan
sudo cp 50-cloud-init.yaml 50-cloud-init.yaml.bak
```

 Merge the following into 50-cloud-init.yaml, while retaining the original mac address:
 ```
# This file is generated from information provided by
# the datasource.  Changes to it will not persist across an instance.
# To disable cloud-init's network configuration capabilities, write a file
# /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg with the following:
# network: {config: disabled}
network:
  version: 2
  renderer: networkd
  ethernets:
    ens3:
      match:
        name: ens3
      dhcp4: true
  bridges:
    br0:
      interfaces: [ens3]
      macaddress: "02:2c:f9:9d:ec:04"
      dhcp4: true
```

run the following script:
```bash
sudo netplan generate
sudo netplan apply
sudo apt-get install bridge-utils -y
sudo brctl stp br0 on
sudo ip tuntap add mode tap tap0
sudo ip addr add 11.11.11.2/24 dev tap0
sudo ip link set dev tap0 up
sudo brctl addif br0 tap0
```

At this point, the tap0 interface should be up and ready. To test it, you could try
```bash
curl -i tap0 http://www.google.com
```


## Developer notes - Creating a tap interface on an EC2 machine using bridge utils: ##

```bash
sudo apt-get install bridge-utils uml-utilities libvirt-bin -y
sudo tunctl -t tap0
sudo ifconfig tap0 up
sudo brctl addif virbr0 tap0
brctl show
```


The following line could be added to the qemu configuration:
```
  -net nic,macaddr=00:16:3e:00:00:01 -net tap,ifname=tap0,script=no,downscript=no
```
