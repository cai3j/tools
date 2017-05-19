package main

import (
	"flag"
	"fmt"
	"net"
	"reflect"
	"time"
	"regexp"
	"strings"
	"log"
	"os"
	"bufio"
    "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const APP_VERSION = "0.1"

// The flag package provides a default help printer via -h switch
var versionFlag *bool = flag.Bool("v", false, "Print the version number.")
var intFlag *int = flag.Int("int",0,"Get a Int")
var skipFlag *bool = flag.Bool("skip",false, "Skip something")
var strFlag *string = flag.String("str", "None", "Get a string")
var intf *string = flag.String("i","eth0","Get a interface")

func scan(iface *net.Interface) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		fmt.Printf("IP LIST : %+v\n",addrs)
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				fmt.Printf("ipnet (%v): %+v\n",reflect.TypeOf(ipnet),ipnet)
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
		fmt.Printf("Address : %+v(type:%v)\n",addr,reflect.TypeOf(addr))
		value1 := reflect.ValueOf(addr)
		fmt.Printf("Address : %+v(type:%v) %v\n",value1,reflect.TypeOf(value1),value1.Type())
	}
	
	return nil
}
func cliOrder(order chan string) error{
	running := true
    reader := bufio.NewReader(os.Stdin)
    for running {
        data, _, _ := reader.ReadLine()
        command := string(data)
        if command == "stop" {
            running = false
        }
        if command == "stoppacket"{
        	order <- "stoppacket"
        }
        log.Println("command", command)
    }
    return nil
}
func packetFun(args []string) error {
	fmt.Printf("test order : %v\n", args)
	order_chan := make(chan string) 
	go cliOrder(order_chan)
	defer close(order_chan)
	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(args[0], 65536, true, pcap.BlockForever) // 打开pcap的接口
	if err != nil {
		return err
	}
	defer handle.Close()
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)     //读取报文
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
			for i,k := range packet.Layers() {
				fmt.Printf("%d : type %s\n",i,k.LayerType())
				if k.LayerType() == layers.LayerTypeEthernet {
					eth := k.(*layers.Ethernet)
					fmt.Printf("   this is ethernet srcMac:%s, dstMac:%s\n",
							net.HardwareAddr(eth.SrcMAC),
							net.HardwareAddr(eth.DstMAC))
				} else if k.LayerType() == layers.LayerTypeIPv4 {
					ip4 := k.(*layers.IPv4)
					fmt.Printf("   this is ipv4 src : %s, dst : %s\n",
						    ip4.SrcIP,ip4.DstIP)
				}
				
			}
			fmt.Println("------------------------------------")
			first := packet.LinkLayer()
			
			fmt.Printf("first layer type : %v , %v\n",reflect.TypeOf(first),reflect.TypeOf(first.LayerType()))
			if first.LayerType() ==  layers.LayerTypeEthernet {
				eth := first.(*layers.Ethernet)
				fmt.Printf("this is ethernet srcMac:%v\n",eth.SrcMAC)
			}
			fmt.Printf("Second layer type : %v\n", 1)
			//ethlayer := packet.Layer(layers.LayerTypeEthernet)
			//fmt.Printf("Eth type : %v\n",ethlayer)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				fmt.Println("This is a TCP packet!")
			}
			//log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}
func testFun(args []string) error {
	fmt.Printf("test order : %v\n", args)
	fmt.Println("Int :",*intFlag)
	fmt.Println("String : ", *strFlag)
	if *skipFlag {
		return nil
	}
	fmt.Println("Hello world")
	
	var t1 = time.Now()
	var t2 = t1.Add(time.Minute)
	fmt.Printf("Time : %v , %v\n",t1.Format(time.RFC3339),t2)
	return nil
}
func intfFun(args []string) error {
	fmt.Printf("intf order : %v\n", args)
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	//fmt.Printf("Interfaces %+v\n",ifaces)
	
	for _, iface := range ifaces {
		fmt.Printf("======= \ninterface %v, %d\n", iface.Name,iface.Index)
		fmt.Printf("scan : %+v\n", iface)
		scan(&iface)
	}
	return nil
}

func regexpFun(args []string) error{
	fmt.Printf("regexpFun : %v\n", args)
	ret,_ := regexp.MatchString("a.b","acb")
	fmt.Printf("regexp : %+v\n",ret)
	reg1 := regexp.MustCompile("a(.*?)b")
	
	fmt.Printf("sub match all ok: %v\n", reg1.FindAllStringSubmatch("seafbooadb",10))
	fmt.Printf("sub match all err: %v\n", reg1.FindAllStringSubmatch("seaooa",10))
	fmt.Printf("sub match ok: %v\n", reg1.FindStringSubmatch("seafbooadb"))
	fmt.Printf("sub match err: %v\n", reg1.FindStringSubmatch("sebooa"))
	
	reg2,_ := regexp.Compile("\\d")
	reg3 := regexp.MustCompile("\\d")	
	fmt.Printf("Compile : %v\n", reg2.FindStringSubmatch("1"))
	fmt.Printf("Must Compile : %v\n", reg3.FindStringSubmatch("1"))
	fmt.Printf("Splite : %v\n", reg3.Split("1x1b2c345", 10))
	return nil
}

func strFun(args []string) error{
	log.Printf("strFun : %v\n", args)
	var str1 string = "123"
	var str2 string = "123"
	fmt.Printf("Compare %v\n",strings.Compare(str1, str2))
	fmt.Printf("A + B =  %v\n",str1+str2)
	var list1 []int = []int{2,4,5}
	fmt.Printf("list   %+v (%d)\n",list1,len(list1))
	return nil
}

func cliFun(args []string) error{
	log.Printf("cliFun : %v\n", args)
	running := true
    reader := bufio.NewReader(os.Stdin)
    for running {
        data, _, _ := reader.ReadLine()
        command := string(data)
        if command == "stop" {
            running = false
        }
        log.Println("command", command)
    }
    return nil
}

func main() {
	flag.Parse() // Scan the arguments list
	if *versionFlag {
		fmt.Println("Version:", APP_VERSION)
		return
	}
	if len(flag.Args()) <= 0{
		flag.PrintDefaults()
		return
	}
	order := flag.Arg(0)
	fmt.Printf("%+v %v\n", flag.Args(), order)
	fmt.Println("============================")
	
	switch order {
		case "test" :
			testFun(flag.Args()[1:])
		case "intf" :
			intfFun(flag.Args()[1:])
		case "regexp" :
			regexpFun(flag.Args()[1:])
		case "cli":
			cliFun(flag.Args()[1:])
		case "str" :
			strFun(flag.Args()[1:])	
		case "packet" :
			packetFun(flag.Args()[1:])		
		default :
			flag.PrintDefaults()
	}
}

