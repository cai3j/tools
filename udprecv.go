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
    if _,ok := data["object"];ok {
    	data["object"] = strings.TrimLeft(data["object"], ":")
    }
    for k,v := range data {
        fmt.Printf("\t%s = %s\n",k,v)
    }
    istring  := ""
    
    if order == "helloserver" {
        istring = "hello client"; 
        ilen,err := socket.WriteToUDP([]byte(istring),client)
        if err != nil {
        	fmt.Printf("err : %s\n",err)
        } else {
        	fmt.Printf("Send:%s(%d)\n",istring,ilen);
        }
        
    }else if order == "createhost" || order == "createaccesshost" {
        //   port1Vlan1 CreateAccessHost -HostName Host1  -UpperLayer DualStack
        //   -Ipv6Addr 2013::1 -Ipv6Mask 64 
        //   -Ipv6LinkLocalAddr fe80::1 -Ipv4Addr 192.0.1.11
        if _,ok := data["hostname"];ok {
            port := data["object"]  //interface
            fmt.Printf("%-10s%s\n","CreateHost NAME :",data["hostname"]);
            ntx_data[data["hostname"]] = data;
            vid := ""
            _,ok1 := data["hostname"]
            _,ok2 := ntx_data["port"]
            if ok1 && ok2 {
            	portv2 := ntx_data["port"].(map[string]string) 
                vid  = portv2["vlanid"]
                port = portv2["object"]
            }
            if _,ok1 := data["ipv4addr"];ok1 {
                //tcpdump_arpd($port,$data{ipv4addr},$data{macaddr},$vid);
            }
            if _,ok1 = data["ipv6addr"];ok1 {
                //tcpdump_arpd($port,$data{ipv6addr},$data{macaddr},$vid);
            }
            _ = port
            _ = vid
        }
    }else if order == "sendarprequest" {
        if _,ok := data["object"];ok {
            object := data["object"]  //host
            fmt.Printf("%-10s%s\n","OBJECT     NAME :",object)
            if _,ok := ntx_data["object"];ok {
                host := ntx_gethostinfo(object)
                host_sendarp(&host);
            }
        }
    }else if order == "ping" {
        if _,ok := data["object"];ok { //host
            object := data["object"]  //host
            fmt.Printf("%-10s%s\n","OBJECT     NAME :",object)
            fmt.Printf("%-10s%s\n","Host       NAME :",data["host"])
            str := "ERROR:ARG"
            _,ok1 := data["host"]
            _,ok2 := ntx_data["object"]
            if (ok1 && ok2) {
                host := ntx_gethostinfo(object)
                if _,ok1 = data["result"];!ok1 {
                    str = host_ping(&host,&data);
                    str = "OK:" + str
                }else{
                    str = host_pingresult(&host,&data);
                    str = "OK:" + "$str";
                }
            }
            ilen,_ := socket.WriteToUDP([]byte(str),client)    
            fmt.Printf("Send:%s(%d)\n",str,ilen);
        }
    }else if order == "createsubint" { //创建子VLAN接口
        if _,ok := data["subintname"] {
            fmt.Printf("%-10s%s\n","CreateSubInt NAME :",data["subintname"])
            ntx_data[data["subintname"]] = data;
        }
    }else if order == "configport" { //VLAN信息
        if _,ok := data["object"];ok {
            object := data["object"]
            fmt.Printf("%-10s%s\n","OBJECT     NAME :",object)
            delete(data["object"])
            for k1,v1 := range(data){
            	tmpv := ntx_data["object"].(map[string]string)
            	tmpv[k1] = v1
            }
        }
   }else if order == "createstaengine" { //创建统计引擎
        if _,ok := data["staenginename"];ok {
            fmt.Printf("%-10s%s\n","OBJECT        NAME :",data["object"]) // PORT信息
            fmt.Printf("%-10s%s\n","CreateProfile NAME :",data["staenginename"])
            fmt.Printf("%-10s%s\n","StaType NAME :",data["statype"])
            ntx_data[data["staenginename"]] = data;
            if data["statype"] != "analysis" {
                tcpdump_creat(data["object"]);
            }            
        }
    }else if order == "configcapturemode" {
        fmt.Printf("%-10s%s\n","OBJECT        NAME :",data["object"]) // engen
    }else if order == "startcapture" {
        fmt.Printf("%-10s%s\n","OBJECT        NAME :",data["object"]) // engen
        eng = data["object"]
        if _,ok := ntx_data[eng];ok {
            if ntx_data[eng]["statype"] == "analysis" {
                tcpdump_start(ntx_data[eng]["object"]); //在抓包引擎的接口上抓
            }
        }
    }else if order == "stopcapture" {
        fmt.Printf("%-10s%s\n","OBJECT        NAME :",data["object"]) // engen
        eng = data["object"];
        if _,ok := ntx_data[eng];ok {
            if ntx_data[eng]["statype"] == "analysis" {
                tcpdump_stop(ntx_data[eng]["object"]) //在抓包引擎的接口上停止
            }    
        }
    }else if order == "getcapturepacket" {
        if _,ok := ntx_data["packetindex"];ok {
            fmt.Printf("%-10s%s\n","OBJECT        NAME :",data["object"]) // engen
            fmt.Printf("%-10s%s\n","PacketIndex        :",data["packetindex"])
            eng = data["object"];
            str = tcpdump_get(ntx_data[eng]["object"],data["packetindex"]);
            if nil != str {
                ilen,_ := socket.WriteToUDP([]byte(str),client)    
	            fmt.Printf("Send:OK:%s(%d)\n",str,ilen)
            } else {
	            ilen,_ := socket.WriteToUDP([]byte("ERROR"),client)    
	            fmt.Printf("Send:ERROR(%d)\n",ilen);
            }
        }
    }else if order == "createfilter" {
        if _,ok := data["filtername"];ok {
            fmt.Printf("%-10s%s\n","OBJECT        NAME :",data["object"])    // port
            fmt.Printf("%-10s%s\n","filtername NAME :",data["filtername"])
            ntx_data[data["trafficname"]] = data;
        }
    }else if order == "configfilter" {
        if _,ok := data["filtername"];ok {
            fmt.Printf("%-10s%s\n","OBJECT        NAME :",data["object"]) // port
            fmt.Printf("%-10s%s\n","filtername NAME :",data["filtername"])
            ntx_data[data["trafficname"]] = data;
        }
    }else if order == "destoryfilter" {
        if _,ok := data["filtername"];ok {
            fmt.Printf("%-10s%s\n","OBJECT        NAME :",data["object"]; // port
            fmt.Printf("%-10s%s\n","filtername NAME :",data["filtername"])
            delete(ntx_data,data["trafficname"])
        }
    }else if order == "createtraffic" {
        if _,ok := data["trafficname"];ok {
            fmt.Printf("%-10s%s\n","CreateTraffic NAME :",data["trafficname"])
            ntx_data[data["trafficname"]] = data;
        }
    }else if order == "getportstats" {
        string = undef;
        staEngine = data["object"]; //引擎名称
        port = ntx_data[staEngine]["object"];
        t,r,ts,rs := tcpdump_stat(port);
        istring := fmt.Sprintf("GetPortStats TxFrames = %d , RxFrames = %d , rxsignature = %d , txsignature = %d",t,r,rs,ts)
        ilen,_ := socket.WriteToUDP([]byte(istring),client)    
        fmt.Printf("Send:%s(%d)\n",istring,ilen);
    }else if order == "getstreamstats" {
        istring = undef;
        if _,ok := data["streamname"];ok {
            staEngine = data["object"];        //引擎名称
            streamname = data["streamname"] //流名称
            port = ntx_data[staEngine]["object"]
            fmt.Printf("%-10s%s\n","OBJECT NAME :",staEngine)
            fmt.Printf("%-10s%s\n","Stream NAME :",streamname)
            t,r := tcpdump_stat(port,streamname)
            istring = fmt.sprintf("GetStreamStats TxFrames = %d , RxFrames = %d",t,r)
        } else {
            istring = "GetStreamStats Error";
        }
        ilen,_ := socket.WriteToUDP([]byte(istring),client)    
        fmt.Printf("Send:%s(%d)\n",istring,ilen);
        
    }else if order == "createprofile" {
        //Input: 1. args:参数列表，可包含如下参数
        //  (1) -Name Name 必选参数,Profile的名字
        //  (2) -Type Type 可选参数,Constant Burst
        //  (3) -TrafficLoad StreamLoad 可选参数，数据流发送的速率，如 -StreamLoad 1000
        //  (4) -TrafficLoadUnit TrafficLoadUnit 可选参数，数据流发送的速率单位，如 -TrafficLoadUnit fps
        //  (5) -BurstSize BurstSize, 可选参数，Burst中连续发送的报文数量
        //  (6) -FrameNum FrameNum, 可选参数，一次发送报文的数量
        //  (7) -Blocking blocking, 堵塞模式，Enable/Disable
        //  (8) -DistributeMode DistributeMode
        if _,ok := data["name"];ok {
            fmt.Printf("%-10s%s\n","CreateProfile NAME :",data["name"])
            ntx_data[data["name"]] = data;
            //%{$ntx_data{$data{'name'}}{testorder}} = ();  //创建新的profile，将删除testorder信息
        }
    }else if order == "destroyprofile" {
        if _,ok := data["name"];ok {
            fmt.Printf("%-10s%s\n","CreateProfile NAME :",data["name"])
            profile := data["name"]
            if _,ok := ntx_data["profile"] {
                streamlist = ntx_findstream(profile);
                ntx_stopstream(port,streamlist);
                delete(ntx_data,profile)
            }
        }
    }else if order == "createcustompkt" {
        if _,ok := data["pduname"];ok { //HexString 是具体的报文内容
            fmt.Printf("%-10s%s\n","CreateCustomPkt NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data
            ntx_data[data["pduname"]]['typel3"] = "pkt"
        }
    }else if order == "createethheader" {
        if _,ok := data["pduname"];ok {
        	pdu := data["pduname"]
            fmt.Printf("%-10s%s\n","CreateEthHeader NAME :",data["pduname"])
            ntx_data[pdu] = data;
            ntx_data[pdu]["typel2"] = 'eth';
        }
    }else if order == "createvlanheader" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateVlanHeader NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data
            ntx_data[data["pduname"]]["typevlan"] = 'vlan'
        }
    }else if order == "createipv4header" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateIPV4Header NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data;
            ntx_data[data["pduname"]['TypeL3'] = 'ipv4';
        }
    }else if order == "createipv6header" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateIPV6Header NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data;
            ntx_data[data["pduname"]]['typel3"] = 'ipv6';
        }
    }else if order == "createudpheader" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateUDPHeader NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data;
            ntx_data[data["pduname"]]['typel4"]  = 'udp';
        }
    }else if order == "createtcpheader" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateTCPHeader NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data;
            ntx_data[data["pduname"]]['typel4'] = 'tcp';
        }
    }else if order == "createicmppkt" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateICMPPkt NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data
            ntx_data[data["pduname"]]["typel4"] = 'icmp'
            
            if _,ok = ntx_data[data["pduname"]["type"];ok {
                ntx_data[data["pduname"]]["icmptype"] = ntx_data[data["pduname"]]["type"]
            }
        }
    }else if order == "createstream" {
        //object 是port
        if (exists $data{'streamname'} && exists $data{profilename}) {
            stream = $data{'streamname'};
            fmt.Printf("%-10s%s\n","CreateStream NAME :",$stream;
            if (exists $ntx_data{$stream}){ //如果stream已经存在， 就清除计数
                tcpdump_clearstatics($stream);
            }
            
            ntx_data[stream] = data;
        }
    }else if order == "configstream" {
    	_,ok1 := data["streamname"]
    	_,ok2 := ntx_data[data["streamname"]]
        if ok1 && ok2 {
            stream = data["streamname"]
            fmt.Printf("%-10s%s\n","CreateStream NAME :",stream)
            for k,v := range(data) {
                ntx_data[stream][k = v
            }
        }
    }else if order == "destroystream" {
        if _,ok := data["streamname"];ok {
            fmt.Printf("%-10s%s\n","CreateProfile NAME :",data["name"];
            stream = data["streamname"]
           
            if _,ok = ntx_data[stream];ok {
                ntx_stopstream(port,stream);
                delete(ntx_data,stream)
            }
        }
    }else if order == "addpdu" {
        //stream name : testorder
        _,ok1 := data["pduname"]
        _,ok2 := data["object"]
        if ok1 && ok2 {
            stream  = data["object"]
            fmt.Printf("%-10s%s\n","Stream NAME  :",stream)
            fmt.Printf("%-10s%s\n","AddPdu       :",data["pduname"])
            ntx_data[stream]["addpdu"] = data["pduname"]        
        }       
    
    }else if order == "starttraffic" {
        port = data["object"];
        profile = ""
        streamlist := make([]string)
        onlyport = 0;
        
        if _,ok := data["streamnamelist"];ok { //streamnamelist = {stream11 stream12}
            info = data["streamnamelist"]
            info = strings.Trim(info, "{}")
            streamlist1 := regexp.MustCompile(`\s+`).Split(info, 100)
            for _,v := range(streamlist1) {
            	if ok,_ := regexp.MatchString(`\S`, v);ok {
		            streamlist = append(streamlist,v)
            	}
            }
            f (len(streamlist) > 0) {
                profile = ntx_findprofile(streamlist[0])
            }
        } else if _,ok := data["streamlist"];ok {
            streamlist = append(streamlist,data["streamlist"])
            profile = ntx_findprofile(data[streamlist])
        } else if _,ok := data["profilelist"];ok {
            profile = data["profilelist"]
            streamlist = ntx_findstream(profile)
        } else {
            streamlist = ntx_findstreamByPort(port)
            onlyport = 1;
        }
        
        fmt.Printf("%-10s%s\n","OBJECT NAME  :",port)
        fmt.Printf("%-10s%s\n","Profile NAME :",profile)
        fmt.Printf("%-10s%s\n","ClearStatistic :",data["clearstatistic"])
        
        _,ok1 = data["clearstatistic"]
         if !ok1 || (ok && data["clearstatistic"] == "1"){
            if onlyport {
                tcpdump_clearstatics("?ALL");
            } else {
                for _,stream = range(streamlist) { 
                    tcpdump_clearstatics(stream);
                }
            }
            sleep 1;
         }

        ntx_startstream($port,@streamlist)
    }else if order == "stoptraffic" {
        port = data["object"];
        profile = undef
        streamlist = make([]string,0)
        if _,ok := data["streamnamelist"];ok { //streamnamelist = {stream11 stream12}
            info := data["streamnamelist"]
            info = strings.Trim(info, "{}")
            streamlist1 := regexp.MustCompile(`\s+`).Split(info, 100)
            for _,v := range(streamlist1) {
            	if ok,_ := regexp.MatchString(`\S`, v);ok {
		            streamlist = append(streamlist,v)
            	}
            }
            if (len(streamlist) > 0) {
                profile = ntx_findprofile(streamlist[0])
            }
        } else if _,ok := data["streamlist"];ok {
            streamlist = append(streamlist,data["streamlist"])
            profile = ntx_findprofile(data[streamlist])
        } else if _,ok := data["profilelist"];ok {
            profile = data["profilelist"];
            streamlist = ntx_findstream(profile);
        } else {
            streamlist = ntx_findstreamByPort(port);
        }

        fmt.Printf("%-10s%s\n","OBJECT NAME  :",port)
        fmt.Printf("%-10s%s\n","Profile NAME :",profile)
        
        ntx_stopstream(port,streamlist)
    }else if order == "createtestport" {
        if_,ok := data["portname"];ok {
        	data[portname] = strings.TrimLeft(data[portname],":")
            ntx_int_init(&data);
        }
    }else if order == "cleanuptest" {
        //无法删除线程，暂不清除port
        for port,_ := eachinterface {
        	portinfo = interface[port]
        	if _,ok := portinfo["object"];ok {
	        	continue
        	}
            fmt.Printf("Delete port %s obj %s",port,portinfo["object"]);
            delete(portinfo,"object")
        }
        fmt.Printf("Clean all -- Not support\n")
    }else if order == "resetsession" {
        if _,ok := data["object"];ok {
            printf "%-10s%s\n","ResetSession  :", data["object"])
            DPrint("------ResetSession--before--")
            DPrint(&ntx_data,&interface)
            //str = `ps -ef | grep udpr`;
            //DPrint($str);
            DPrint("------ResetSession----------");
            ntx_stopstream();
            ntx_int_reset(&data);
             for k,v :=range(ntx_data) {
	             delete(ntx_data,k)
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
