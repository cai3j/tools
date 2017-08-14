package main

import (
	"bufio"
	_ "encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	_ "os/exec"
	"reflect"
	_ "strconv"
	_ "strings"
	"sync"
	_ "time"
)

const APP_VERSION = "0.1"

// The flag package provides a default help printer via -h switch
var versionFlag *bool = flag.Bool("v", false, "Print the version number.")
var intFlag *int = flag.Int("int", 0, "Get a Int")
var skipFlag *bool = flag.Bool("skip", false, "Skip something")
var strFlag *string = flag.String("str", "None", "Get a string")
var intf *string = flag.String("i", "eth0", "Get a interface")

func scan(iface *net.Interface) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		fmt.Printf("IP LIST : %+v\n", addrs)
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				fmt.Printf("ipnet (%v): %+v\n", reflect.TypeOf(ipnet), ipnet)
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	if addr != nil {
		fmt.Printf("Address : %+v(type:%v)\n", addr, reflect.TypeOf(addr))
		value1 := reflect.ValueOf(addr)
		fmt.Printf("Address : %+v(type:%v) %v\n",
			value1, reflect.TypeOf(value1), value1.Type())
	}

	return nil
}

func cliOrder(order_chan chan string) {
	running := true
	reader := bufio.NewReader(os.Stdin)
	for running {
		data, _, _ := reader.ReadLine()
		command := string(data)
		if command == "stop" {
			running = false
			continue
		}
		if len(command) > 0 {
			order_chan <- command
		}
		log.Println("command:", command)
	}
	os.Exit(0)
}

func readPacket(handle *pcap.Handle, stop chan string) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet) //读取报文
	in := src.Packets()
	for {
		var packet gopacket.Packet
		var order string
		select {
		case order = <-stop: // 如果是读到停止， 就返回
			log.Print("Read a command : ", order)
			if order == "quit" {
				return
			}
		case packet = <-in:
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if icmpLayer == nil {
				continue
			}
			log.Printf("pkt : %+v", packet)
			//icmp := icmpLayer.(*layers.ICMPv4)
			//log.Printf("%+v",icmp)
		}
	}
}

func ExePcap(args []string) {
	log.Printf("ExePcap args : %v", args)
	if len(args) > 0 {
		devs, _ := pcap.FindAllDevs()
		for i, v := range devs {
			fmt.Printf("%d : %v(%s)\n", i, v, reflect.TypeOf(v))
			fmt.Printf("%d : %v(%s)\n", i, devs[i], devs[i].Name)
		}

		return
	}

	intfs, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	//fmt.Printf("inter %+v\n", intfs)
	for _, intf := range intfs {
		fmt.Printf("inter %v : %+v\n", intf.Name, intf)
	}

	fmt.Println("Select a interface : ", *intf)

	handle, err := pcap.OpenLive(*intf, 65536, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	var wg sync.WaitGroup

	order_chan := make(chan string)
	go func() {
		cliOrder(order_chan)
	}()
	defer close(order_chan)

	wg.Add(1)
	go func() {
		defer wg.Done()
		readPacket(handle, order_chan)
		log.Print("Read packet done!")
	}()
	log.Print("Init OK!")
	wg.Wait()
}

func ExePacket(args []string) error {
	fmt.Printf("test order : %v\n", args)
	order_chan := make(chan string)
	go cliOrder(order_chan)
	defer close(order_chan)
	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(args[0], 65536, true, pcap.BlockForever) // 打开pcap的接口
	if err != nil {
		log.Printf("%v", err)
		return err
	}
	defer handle.Close()
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet) //读取报文
	in := src.Packets()
	for {
		var packet gopacket.Packet
		var orderin string
		select {
		case orderin = <-order_chan:
			fmt.Printf("order is %v", orderin)
			//return
		case packet = <-in:
			fmt.Println("------------------------------------")
			fmt.Println(packet.String())
			//fmt.Println(packet.Dump())
			fmt.Println("------------------------------------")
			for i, k := range packet.Layers() {
				fmt.Printf("%d : type %s\n", i, k.LayerType())
				if k.LayerType() == layers.LayerTypeEthernet {
					eth := k.(*layers.Ethernet)
					fmt.Printf("   this is ethernet srcMac:%s, dstMac:%s\n",
						net.HardwareAddr(eth.SrcMAC),
						net.HardwareAddr(eth.DstMAC))
				} else if k.LayerType() == layers.LayerTypeIPv4 {
					ip4 := k.(*layers.IPv4)
					fmt.Printf("   this is ipv4 src : %s, dst : %s\n",
						ip4.SrcIP, ip4.DstIP)
				}

			}
			fmt.Println("------------------------------------")
			first := packet.LinkLayer()

			fmt.Printf("first layer type : %v , %v\n",
				reflect.TypeOf(first), reflect.TypeOf(first.LayerType()))
			if first.LayerType() == layers.LayerTypeEthernet {
				eth := first.(*layers.Ethernet)
				fmt.Printf("this is ethernet srcMac:%v\n", eth.SrcMAC)
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}
				
				iplayer := packet.Layer(layers.LayerTypeIPv4)
				ip := iplayer.(*layers.IPv4)
				ip.SerializeTo(buf, opts)
				fmt.Printf("int :  %v (%d)\n", buf.Bytes(),len(buf.Bytes()))
				eth.SerializeTo(buf, opts)
				fmt.Printf("int :  %v (%d)\n", buf.Bytes(),len(buf.Bytes()))
				
			}
			fmt.Printf("Second layer type : %v\n", 1)
			//ethlayer := packet.Layer(layers.LayerTypeEthernet)
			//fmt.Printf("Eth type : %v\n",ethlayer)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				fmt.Println("This is a TCP packet!")
			}
			//log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress),
			//	net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}




func ExeTest(args []string) error {
	fmt.Printf("test order : %v\n", args)
	fmt.Println("Int :", *intFlag)
	fmt.Println("String : ", *strFlag)
	if *skipFlag {
		return nil
	}

	return nil
}

func main() {
	flag.Parse() // Scan the arguments list
	if *versionFlag {
		fmt.Println("Version:", APP_VERSION)
		return
	}
	if len(flag.Args()) <= 0 {
		flag.PrintDefaults()
		return
	}
	order := flag.Arg(0)
	args := flag.Args()[1:]
	log.Printf("Order : %v %+v", order, args)
	fmt.Println("============================")
	switch order {
	case "test":
		ExeTest(flag.Args()[1:])
	case "packet":
		ExePacket(flag.Args()[1:])
	case "pcap":
		ExePcap(args)
	default:
		flag.PrintDefaults()
	}
}
