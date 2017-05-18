package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	//"time"
	"net"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const APP_VERSION = "0.1"

// The flag package provides a default help printer via -h switch
var versionFlag *bool = flag.Bool("v", false, "Print the version number.")
var intFlag *int = flag.Int("int", 0, "Get a Int")
var intfSelect *string = flag.String("i", "eth0", "Get a interface")

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

func ExeTest(args []string) {
	log.Printf("ExeTest args : %v", args)
	a := 1
	if a > 0 {
		fmt.Println("A > 0")
	} else if a < 0 {
		fmt.Println("A < 0")
	} else {
		fmt.Println("A = 0")
	}
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

	fmt.Println("Select a interface : ", *intfSelect)

	handle, err := pcap.OpenLive(*intfSelect, 65536, true, pcap.BlockForever)
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
	flag.Parse()
	if *versionFlag {
		fmt.Println("Version:", APP_VERSION)
		return
	}
	fmt.Println("Hello world")

	if len(flag.Args()) <= 0 {
		flag.PrintDefaults()
		return
	}
	order := flag.Arg(0)
	args := flag.Args()[1:]
	log.Printf("Order : %v %+v", order, args)
	switch order {
	case "pcap":
		ExePcap(args)
	case "test":
		ExeTest(args)
	case "udps":
		ExeUdps(args)
	case "udpc":
		ExeUdpc(args)	
	}

}
