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
	"sync"
	"encoding/binary"
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
			log.Print("Read a command : ",order)
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
			//log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}

func ExePcap(args []string) {
	log.Printf("ExePcap args : %v", args)
	

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

var retmap map[string]interface{}

func test(order string, args ...string)  map[string]interface{} {
	fmt.Printf("string : %s\n", order)
	for i,v := range args {
		fmt.Printf("%d : %s\n", i,v)
	}
	if retmap == nil{
		retmap = make(map[string]interface{})
	}
	retmap["123"] = 1
	retmap["234"] = "DE"
	log.Printf(" test ret : %v", retmap)
	return retmap
}

func ExeTest(args []string) error {
	fmt.Printf("test order : %v\n", args)
	fmt.Println("Int :",*intFlag)
	fmt.Println("String : ", *strFlag)
	if *skipFlag {
		return nil
	}
	fmt.Println("Hello world")
	if ok,err := regexp.MatchString(`\d`, "a1bc"); err == nil && ok  {
		log.Printf("match \n")
	}
	ilist := []string{"order"}
	retv := test(ilist[0],ilist[1:]...)
	log.Printf(" test : %v", retv)
	a := 1
	if a > 0 {
		fmt.Println("A > 0")
	} else if a < 0 {
		fmt.Println("A < 0")
	} else {
		fmt.Println("A = 0")
	}
	var t1 = time.Now()
	var t2 = t1.Add(time.Minute)
	fmt.Printf("Time : %v , %v\n",t1.Format(time.RFC3339),t2)
	return nil
}
func ExeNet(args []string) error {
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

func ExeRegexp(args []string) error{
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

func ExeStr(args []string) error{
	log.Printf("strFun : %v\n", args)
	var str1 string = "123"
	var str2 string = "123"
	fmt.Printf("Compare %v\n",strings.Compare(str1, str2))
	fmt.Printf("A + B =  %v\n",str1+str2)
	var list1 []int = []int{2,4,5}
	fmt.Printf("list   %+v (%d)\n",list1,len(list1))
	return nil
}

func ExeCli(args []string) {
	log.Printf("ExeTest args : %v", args)
	
	running := true
	chs := make(chan int)
	reader := bufio.NewReader(os.Stdin)
	for running {
		data, _, _ := reader.ReadLine()
		command := string(data)
		if command == "stop" {
			running = false
		}
		if command == "save" {
			go func() {
				chs <- 10
				log.Println("Some one read")
			}()
		}
		if command == "read" {
			val := <-chs
			log.Println(val)
		}
		log.Println("command : ", command)
	}
	defer close(chs)
}

func ExeUdps(args []string){
	log.Printf("ExeUdps args : %v", args)
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{
        IP:   net.IPv4(0, 0, 0, 0),
        Port: 9090,
    })
    if err != nil {
        fmt.Println("监听失败!", err)
        return
    }
    defer socket.Close()

    for {
        // 读取数据
        pkt := make([]byte, 4096)
        read, remoteAddr, err := socket.ReadFromUDP(pkt)
        if err != nil {
            fmt.Println("读取数据失败!", err)
            continue
        }
        fmt.Println(read, remoteAddr)
        fmt.Printf("(%v)%s \n\n",len(pkt), pkt)
		order := binary.BigEndian.Uint16(pkt[:2])

		fmt.Printf("%v\n",order)
        // 发送数据
        senddata := []byte("hello client!")
        _, err = socket.WriteToUDP(senddata, remoteAddr)
        if err != nil {
            return
            fmt.Println("发送数据失败!", err)
        }
    }
}
func ExeUdpc(args []string){
	log.Printf("ExeUdpc args : %v", args)
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{
        IP:   net.IPv4(127, 0, 0, 1),
        Port: 9090,
    })
    if err != nil {
        fmt.Println("连接失败!", err)
        return
    }
    defer socket.Close()

    // 发送数据
    senddata := []byte("hello server!")
    _, err = socket.Write(senddata)
    if err != nil {
        fmt.Println("发送数据失败!", err)
        return
    }

    // 接收数据
    data := make([]byte, 4096)
    read, remoteAddr, err := socket.ReadFromUDP(data)
    if err != nil {
        fmt.Println("读取数据失败!", err)
        return
    }
    fmt.Println(read, remoteAddr)
    fmt.Printf("%s\n", data)
    datastring := string(data[:read])
    fmt.Printf("%s %v\n",datastring,len(datastring))
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
	args := flag.Args()[1:]
	log.Printf("Order : %v %+v", order, args)
	fmt.Println("============================")
	
	switch order {
		case "test" :
			ExeTest(flag.Args()[1:])
		case "net" :
			ExeNet(flag.Args()[1:])
		case "regexp" :
			ExeRegexp(flag.Args()[1:])
		case "str" :
			ExeStr(flag.Args()[1:])	
		case "packet" :
			ExePacket(flag.Args()[1:])	
		case "udps":
			ExeUdps(args)
		case "udpc":
			ExeUdpc(args)
		case "pcap":
			ExePcap(args)
		case "cli2":
			ExeCli(args)
		default :
			flag.PrintDefaults()
	}
}

