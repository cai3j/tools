package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
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

var retmap map[string]interface{}

func test(order string, args ...string) map[string]interface{} {
	fmt.Printf("string : %s\n", order)
	for i, v := range args {
		fmt.Printf("%d : %s\n", i, v)
	}
	if retmap == nil {
		retmap = make(map[string]interface{})
	}
	retmap["123"] = 1
	retmap["234"] = "DE"
	log.Printf(" test ret : %v", retmap)
	return retmap
}

//**************************************************
// 参数解析 order -s1 1 -s2 2 -s3
//**************************************************
func argfrase(args ...string) map[string]string {
	iswitch := make(map[string]string)
	var key string = ""
	var c bool = false
	//fmt.Printf("nill   :   %v\n", key)
	for _, v := range args {
		if ok, _ := regexp.MatchString(`^\s*$`, v); ok {
			continue
		}
		if ilist := regexp.MustCompile(`^-(.+)`).FindStringSubmatch(v); len(ilist) > 0 {
			key = ilist[1]
			iswitch[key] = ""
			c = false
		} else {
			if key != "" {
				if v2, ok := iswitch[key]; ok {
					iswitch[key] = v2 + " " + v
				} else {
					iswitch[key] = v
				}
				if ok, _ := regexp.MatchString(`^{`, v); ok {
					c = true
				} else if ok, _ := regexp.MatchString(`/}$`, v); ok {
					c = false
				}
				if c != true {
					key = ""
				}
			}
		}
	}
	return iswitch
}

type structtest struct {
	str1 string
	str2 string
}

var structmap map[string]*structtest

func testGlobal() {
	if structmap == nil {
		structmap = make(map[string]*structtest)
		structmap["s1"] = &structtest{str1: "1", str2: "2"}
		structmap["s2"] = &structtest{"2", "3"}
	}

	structmap["s1"].str2 = structmap["s1"].str2 + "dcc"
}
func ExeTest(args []string) error {
	fmt.Printf("test order : %v\n", args)
	fmt.Println("Int :", *intFlag)
	fmt.Println("String : ", *strFlag)
	if *skipFlag {
		return nil
	}
	fmt.Println("Hello world")

	fmt.Println("=================test func ==========================")
	ilist := []string{"order"}
	retv := test(ilist[0], ilist[1:]...)
	log.Printf(" test : %v", retv)

	fmt.Println("=================test else if ==========================")
	a := 1
	if a > 0 {
		fmt.Println("A > 0")
	} else if a < 0 {
		fmt.Println("A < 0")
	} else {
		fmt.Println("A = 0")
	}

	fmt.Println("=================test time==========================")
	var t1 = time.Now()
	var t2 = t1.Add(time.Minute)
	fmt.Printf("Time : %v , %v\n", t1.Format(time.RFC3339), t2)

	fmt.Println("=================test os==========================")
	fmt.Printf("os.getpid : %+v\n", os.Getpid())
	pwd, _ := os.Getwd()
	fmt.Printf("os.Getwd : %+v\n", pwd)
	hostname, _ := os.Hostname()
	fmt.Printf("os.Hostname : %+v\n", hostname)
	fmt.Printf("os.TempDir : %+v\n", os.TempDir())
	fmt.Printf("os.Getenv : %+v\n", os.Getenv("PATH"))

	fmt.Println("=================test exec==========================")
	output, err := exec.Command("ls").Output()
	fmt.Printf(" ls : %+v(%v)\n", string(output), reflect.TypeOf(output))
	output, err = exec.Command("xx").Output()
	fmt.Printf(" xx : %+v(%v)  err %+v(%v)\n", string(output), reflect.TypeOf(output), err, reflect.TypeOf(err))
	output, err = exec.Command("xx").CombinedOutput()
	fmt.Printf(" xx : %+v(%v)\n", string(output), reflect.TypeOf(output))

	fmt.Println("=================test list==========================")
	var list1 []int = []int{2, 4, 5}
	fmt.Printf("list   %+v (%d)\n", list1, len(list1))

	fmt.Println("=================test==========================")
	var v1 int
	var v2, v3 string
	v1, v2, v3 = 1, "12", "34"
	fmt.Println(v1, v2, v3)
	argmap := argfrase("k", "-i", "m")
	fmt.Printf("arg frase : %+v\n", argmap)
	fmt.Println("=================struct==========================")
	testGlobal()
	fmt.Printf("struct %v, %v\n", structmap, structmap["s1"].str2)
	testGlobal()
	fmt.Printf("struct %v, %v\n", structmap, structmap["s1"].str2)
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
		fmt.Printf("======= \ninterface %v, %d\n", iface.Name, iface.Index)
		fmt.Printf("scan : %+v\n", iface)
		scan(&iface)
	}
	return nil
}

func ExeRegexp(args []string) error {
	fmt.Printf("regexpFun : %v\n", args)

	ret, _ := regexp.MatchString("a.b", "acb")
	fmt.Printf("regexp : %+v\n", ret)

	if ok, err := regexp.MatchString(`\d`, "a1bc"); err == nil && ok {
		log.Printf("match \n")
	}

	reg1 := regexp.MustCompile("a(.*?)b")
	fmt.Printf("sub match all ok: %v\n", reg1.FindAllStringSubmatch("seafbooadb", 10))
	fmt.Printf("sub match all err: %v\n", reg1.FindAllStringSubmatch("seaooa", 10))
	fmt.Printf("sub match ok: %v\n", reg1.FindStringSubmatch("seafbooadb"))
	fmt.Printf("sub match err: %v\n", reg1.FindStringSubmatch("sebooa"))

	reg2, _ := regexp.Compile(`\d`)
	reg3 := regexp.MustCompile("\\d")
	fmt.Printf("Compile : %v\n", reg2.FindString("1"))
	fmt.Printf("Must Compile : %v\n", reg3.FindString("1"))
	fmt.Printf("Splite : %v\n", reg3.Split("1x1b2c345", 10))
	return nil
}

func ExeStr(args []string) error {
	log.Printf("strFun : %v\n", args)
	var str1 string = "123"
	var str2 string = "123"
	var int1 int = 123
	_ = int1
	fmt.Printf("Compare %v\n", strings.Compare(str1, str2))
	fmt.Printf("A + B =  %v\n", str1+str2)
	fmt.Printf("%s\n", strings.TrimLeft(":2324", ":"))
	fmt.Printf("string(1) ::: %s\n", strconv.FormatBool(true))
	int3, err := strconv.Atoi("123")
	fmt.Printf("string to int ::: %d, %v\n", int3, err)
	return nil
}

func ExeList(args []string) error {
	log.Printf("ExeList : %v\n", args)
	var ilist []int
	ilist = append(ilist, 1, 2, 3)
	fmt.Printf("%v\n", ilist)
	return nil
}

func mapret() map[string]string {
	ret := make(map[string]string)
	log.Printf("address : %p", &ret)
	ret["a"] = "a1"
	return ret
}

func ExeMap(args []string) error {
	log.Printf("ExeMap : %v\n", args)
	var map1 map[string]interface{}
	var map2 map[string]interface{}

	map1 = make(map[string]interface{})
	map2 = make(map[string]interface{})
	map1["22"] = map2
	map2["33"] = "vv"
	kk := map1["22"].(map[string]interface{})
	//Something  :  map[33:vv](map[string]interface {})
	fmt.Printf("Something  :  %v(%s)\n", map1["22"], reflect.TypeOf(map1["22"]))
	//Something  :  vv(string)
	fmt.Printf("Something  :  %v(%s)\n", kk["33"], reflect.TypeOf(kk["33"]))
	map1["4a"] = mapret()
	map4 := map1["4a"].(map[string]string)
	log.Printf("address2 : %p", &map4)
	//Something  :  a1(string)
	fmt.Printf("Something  :  %v(%s)\n", map4["a"], reflect.TypeOf(map4["a"]))

	map5 := make(map[string]map[string]string)
	map5["1"] = make(map[string]string)
	map5["1"]["2"] = "3"
	fmt.Printf("%v\n", map5) //map[1:map[2:3]]

	map6 := make(map[string]string)
	map6["22"] = "33"
	map6p := &map6
	fmt.Printf("map6p : %v\n", (*map6p)["33"])
	/*
		if ((_,ok := map6["33"];ok) && (_,ok2 := map6["32"];ok2)) {
			fmt.Printf("map6p\n")
		}
	*/
	return nil
}

func ExePoint(args []string) {
	log.Printf("ExePoint args : %v", args)
	type StructTest struct {
		a int
		b string
	}
	var struct1 *StructTest
	struct1 = new(StructTest)
	struct1 = nil
	struct1 = new(StructTest)
	struct1.a = 1
	struct1.b = "12"
	fmt.Printf("%v\n", struct1)
}

func ExeChan(args []string) {
	log.Printf("ExeChan args : %v", args)
	chs := make(chan struct {
		a int
		b string
	})
	fmt.Printf("Type : %s\n", reflect.TypeOf(chs))
	defer close(chs)
	go func() {
		time.Sleep(time.Second)
		chs <- struct {
			a int
			b string
		}{1, "2"}
	}()

	value := <-chs
	fmt.Printf("%v,%d,%s\n", value, value.a, value.b)

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

func ExeUdps(args []string) {
	log.Printf("ExeUdps args : %v", args)
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 9090,
	})
	fmt.Printf("Socket type : %s\n", reflect.TypeOf(socket))
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
		fmt.Printf("(%v)%s \n\n", len(pkt), pkt)
		order := binary.BigEndian.Uint16(pkt[:2])

		fmt.Printf("%v\n", order)
		// 发送数据
		senddata := []byte("hello client!")
		_, err = socket.WriteToUDP(senddata, remoteAddr)
		if err != nil {
			return
			fmt.Println("发送数据失败!", err)
		}
	}
}
func ExeUdpc(args []string) {
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
	fmt.Printf("%s %v\n", datastring, len(datastring))
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
	case "net":
		ExeNet(flag.Args()[1:])
	case "regexp":
		ExeRegexp(flag.Args()[1:])
	case "str":
		ExeStr(flag.Args()[1:])
	case "map":
		ExeMap(flag.Args()[1:])
	case "list":
		ExeList(flag.Args()[1:])
	case "point":
		ExePoint(flag.Args()[1:])
	case "chan":
		ExeChan(flag.Args()[1:])
	case "packet":
		ExePacket(flag.Args()[1:])
	case "udps":
		ExeUdps(args)
	case "udpc":
		ExeUdpc(args)
	case "pcap":
		ExePcap(args)
	case "cli":
		ExeCli(args)
	default:
		flag.PrintDefaults()
	}
}
