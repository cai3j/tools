package main

import (
	"flag"
	"fmt"
	"net"
	_ "reflect"
	_ "time"
	"regexp"
	"strings"
	_ "log"
	"os"
	_ "os/exec"
	"bufio"
	_ "sync"
	"encoding/binary"
    _ "github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/pcap"
)

type InterfaceInfo struct{
 	intf string;
 	pid int;
 	mac string;
}
 
var intf map[string] InterfaceInfo
 
var cli *bool = flag.Bool("cli", false, "Use cli.")
var port *int = flag.Int("port", 9090, "Set server port.")


func readloop(port int) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{
        IP:   net.IPv4(0, 0, 0, 0),
        Port: port,
    })
	if err != nil {
        fmt.Println("Listen error!", err)
        return
    }
    defer socket.Close()
    sendip_init()
    fmt.Printf("Init OK (listen %d)\n",port);
    for true {
        buff := make([]byte, 8000)
        readnum, client, err := socket.ReadFromUDP(buff)
        if err != nil {
        	continue
        }
        //fmt.Println("--------------------------\n")
        //printBlock(1,0,$buff);
        //print "--------------------------\n";
        sendip(socket, client,buff,readnum);
    
	    //chop($buff); 
        //print "$buff\n";
        //send(SERVER,"$buff\n",0,$client);
    }
}

func cli_init(port int) {
    socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{
        IP:   net.IPv4(127, 0,0, 1),
        Port: port,
    })
    if err != nil {
        return
    }
    defer socket.Close()
    
    if err != nil {
        fmt.Println("发送数据失败!", err)
        return
    }
    
    reader := bufio.NewReader(os.Stdin)
    for true {
        data, _, _ := reader.ReadLine()
        getdata := string(data)
        if(len(getdata) <= 0){
            continue;
        }
		
        _, err = socket.Write([]byte(getdata))
    }
    return
}



func sendip_init() {
	intf = make(map[string] InterfaceInfo)
	sim_ntx_init()
}

func sendip(socket *net.UDPConn, client *net.UDPAddr, pktbyte []byte, length int) int {
	order := binary.BigEndian.Uint16(pktbyte[:1])
    pkt := string(pktbyte[2:length]);
    //print "ORDER : $order\n";
	fmt.Printf("ORDER : %d", order)
    if (1 == order) {
        //sim_simple(client,pkt);
    } else if (3 == order) {
        pkt = strings.TrimSpace(pkt)
        fmt.Println ("--------------------------");
        fmt.Println ( "NTX : ",pkt);
        fmt.Println ("--------------------------");
        pkt = strings.ToLower(pkt)
        spacecomp := regexp.MustCompile("\\s+")
        argslist := spacecomp.Split(pkt, 100)
        sim_ntx(socket, client, argslist[0],argslist[1:]...)
    }else if (0 == order) {    //config
        //config_exe($client,split(/\s+/,$pkt));
     }else{
        fmt.Printf("UNKNOW ORDER\n");
        return -1;
    }
    return 0;
}

var ntx_data map[string]interface{};
func sim_ntx_init() {
	if ntx_data == nil {
		ntx_data = make(map[string]interface{})
	}
}

func sim_ntx(socket *net.UDPConn, client *net.UDPAddr, order string , args ...string) int {
    data := argfrase(args...);
    fmt.Printf("%-10s : %s\n", "FRASE ORDER", order);
    if v,ok := data["object"];ok {
    	data["object"] = strings.TrimLeft(data["object"], ":")
    }
    for k,v := range data {
        fmt.Printf("\t%s = %s\n",k,v)
    }
    istring  := ""
    
    if order == "helloserver" {
        istring = "hello client"; 
        ilen,err := socket.WriteToUDP([]byte(istring),client)
        fmt.Printf("Send:%s(%d)\n",istring,ilen);
    }else if order == "createhost" || order == "createaccesshost" {
        //   port1Vlan1 CreateAccessHost -HostName Host1  -UpperLayer DualStack
        //   -Ipv6Addr 2013::1 -Ipv6Mask 64 
        //   -Ipv6LinkLocalAddr fe80::1 -Ipv4Addr 192.0.1.11
        if v,ok := data["hostname"];ok {
            port := data["object"]  //interface
            fmt.Printf("%-10s%s\n","CreateHost NAME :",data["hostname"]);
            ntx_data[data["hostname"]] = data;
            vid := "0"
            v1,ok1 := data["hostname"]
            v2,ok2 := ntx_data["port"]
            if ok1 && ok2 {
            	portv2 := v2.(map[string]string) 
                vid  = portv2["vlanid"]
                port = portv2["object"]
            }
            if v1,ok1 := data["ipv4addr"];ok1 {
                //tcpdump_arpd($port,$data{ipv4addr},$data{macaddr},$vid);
            }
            if v1,ok1 = data["ipv6addr"];ok1 {
                //tcpdump_arpd($port,$data{ipv6addr},$data{macaddr},$vid);
            }
        }

    } else {
        fmt.Printf("UNKNOW ORDER  : %s\n",order)
    }
    return 0;
}

//**************************************************
// 参数解析 order -s1 1 -s2 2 -s3
//**************************************************
func argfrase(args ...string) map[string]string{
    iswitch := make(map[string]string)
    key := "" 
    c := false
    //fmt.Printf("nill   :   %v\n", key)
    for _,v := range args {
        if ok,_ := regexp.MatchString(`^\s*$`,v);ok {
        	continue
        }         
        if ilist :=regexp.MustCompile(`^-(.+)`).FindStringSubmatch(v);len(ilist) > 0 {
            key = ilist[1]
            iswitch[key] = ""
            c = false
        } else {
            if key != "" {
                if v2,ok := iswitch[key]; ok {
                    iswitch[key] = v2 + " " + v;
                }else{
                    iswitch[key] = v;
                }
                if ok,_ := regexp.MatchString(`^{`,v);ok {
                    c = true
                }else if ok,_ := regexp.MatchString(`/}$`,v);ok{
                    c = false
                }
                if c != true {
                    key = "";
                }
            }
        }
    }
    return iswitch
}

func main() {
	fmt.Printf("Init port %d.\n", *port)
	fmt.Println("-----------------------")
	if *cli {
	    go cli_init(*port);
	}
	readloop(*port)
	os.Exit(0)
}
