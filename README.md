# tools
my tools

CreateTestPort -PortLocation 101/4 -PortName port1 -PortType ETHERNET -object CHASSIS1
CreateHost -HostName myhost11 -MacAddr 00:01:00:00:00:01 -Ipv4Addr 190.168.106.57 -Ipv4Mask 24 -Ipv4sutAddr 190.168.106.1 -Arpd enable -FlagPing enable -Ipv6Addr 6000::2 -Ipv6Mask 96 -Ipv6sutAddr 6000::1 -object port1

CreateHost -HostName myhost12 -MacAddr 00:01:00:00:00:10 -Ipv4Addr 31.1.1.3 -Ipv4Mask 24 -Ipv4sutAddr 31.1.1.1 -Arpd enable -FlagPing enable -Ipv6Addr 6000::3 -Ipv6Mask 96 -Ipv6sutAddr 6000::1 -object port1


CreateSubInt -SubIntName cha1Vlan -object port1
ConfigPort -VlanTag 0x8100 -VlanId 10 -object cha1Vlan -OVlanId 100
CreateHost -HostName myhost21 -MacAddr 00:01:00:00:00:03 -Ipv4Addr 132.1.1.2 -Ipv4Mask 24 -Ipv4sutAddr 132.1.1.1 -Arpd enable -FlagPing enable -object cha1Vlan
SendArpRequest -object myhost11
SendArpRequest -object myhost12
SendArpRequest -object myhost21



udpsend.exe 10.46.244.165 9090 3 "


./udpsend.pl 192.168.199.108 9090 3 "CreateTestPort -PortLocation 101/1 -PortName port1 -PortType ETHERNET -object CHASSIS1"
./udpsend.pl 192.168.199.108 9090 3 "CreateHost -HostName myhost11 -MacAddr 00:01:00:00:00:01 -Ipv4Addr 192.168.199.200 -Ipv4Mask 24 -Ipv4sutAddr 192.168.199.1 -Arpd enable -FlagPing enable -Ipv6Addr 6000::2 -Ipv6Mask 96 -Ipv6sutAddr 6000::1 -object port1"
