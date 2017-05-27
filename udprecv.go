package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
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
 	object string;
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

func tcpdump_creat(i string) {
	_ = i
}
func tcpdump_start(i string) {
	_ = i
}
func tcpdump_stop(i string) {
	_ = i
}
func tcpdump_get(i string, num string)string {
	_ = i
	return ""
}
func tcpdump_stat(i string, stream string)(t int,r int,ts int,rs int) {
	_ = i
	_ = stream
	return 1,2,3,4
}
func tcpdump_clearstatics(stream string){
	_ = stream
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
                host_sendarp(&host,"");
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
                    result := host_ping(&host,&data)
                    str = "OK:" + strconv.FormatBool(result)
                }else{
                    str = host_pingresult(&host,&data);
                    str = "OK:" + str
                }
            }
            ilen,_ := socket.WriteToUDP([]byte(str),client)    
            fmt.Printf("Send:%s(%d)\n",str,ilen);
        }
    }else if order == "createsubint" { //创建子VLAN接口
        if _,ok := data["subintname"];ok {
            fmt.Printf("%-10s%s\n","CreateSubInt NAME :",data["subintname"])
            ntx_data[data["subintname"]] = data;
        }
    }else if order == "configport" { //VLAN信息
        if _,ok := data["object"];ok {
            object := data["object"]
            fmt.Printf("%-10s%s\n","OBJECT     NAME :",object)
            delete(data,"object")
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
        eng := data["object"]
        if _,ok := ntx_data[eng];ok {
        	engv := ntx_data[eng].(map[string]string)
            if engv["statype"] == "analysis" {
                tcpdump_start(engv["object"]); //在抓包引擎的接口上抓
            }
        }
    }else if order == "stopcapture" {
        fmt.Printf("%-10s%s\n","OBJECT        NAME :",data["object"]) // engen
        eng := data["object"];
        if _,ok := ntx_data[eng];ok {
        	engv := ntx_data[eng].(map[string]string)
            if engv["statype"] == "analysis" {
                tcpdump_stop(engv["object"]) //在抓包引擎的接口上停止
            }    
        }
    }else if order == "getcapturepacket" {
        if _,ok := ntx_data["packetindex"];ok {
            fmt.Printf("%-10s%s\n","OBJECT        NAME :",data["object"]) // engen
            fmt.Printf("%-10s%s\n","PacketIndex        :",data["packetindex"])
            eng := data["object"];
            engv := ntx_data[eng].(map[string]string)
            istring := tcpdump_get(engv["object"],data["packetindex"]);
            if "" != istring {
                ilen,_ := socket.WriteToUDP([]byte(istring),client)    
	            fmt.Printf("Send:OK:%s(%d)\n",istring,ilen)
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
            fmt.Printf("%-10s%s\n","OBJECT        NAME :",data["object"]) // port
            fmt.Printf("%-10s%s\n","filtername NAME :",data["filtername"])
            delete(ntx_data,data["trafficname"])
        }
    }else if order == "createtraffic" {
        if _,ok := data["trafficname"];ok {
            fmt.Printf("%-10s%s\n","CreateTraffic NAME :",data["trafficname"])
            ntx_data[data["trafficname"]] = data;
        }
    }else if order == "getportstats" {
        istring := "";
        staEngine := data["object"]; //引擎名称
        staEnginev := ntx_data[staEngine].(map[string]string)
        port := staEnginev["object"]
        t,r,ts,rs := tcpdump_stat(port,"");
        istring = fmt.Sprintf("GetPortStats TxFrames = %d , RxFrames = %d , rxsignature = %d , txsignature = %d",t,r,rs,ts)
        ilen,_ := socket.WriteToUDP([]byte(istring),client)    
        fmt.Printf("Send:%s(%d)\n",istring,ilen);
    }else if order == "getstreamstats" {
        istring = ""
        if _,ok := data["streamname"];ok {
            staEngine := data["object"];        //引擎名称
            streamname := data["streamname"] //流名称
            staEnginev := ntx_data[staEngine].(map[string]string)
            port := staEnginev["object"]
            fmt.Printf("%-10s%s\n","OBJECT NAME :",staEngine)
            fmt.Printf("%-10s%s\n","Stream NAME :",streamname)
            t,r,_,_ := tcpdump_stat(port,streamname)
            istring = fmt.Sprintf("GetStreamStats TxFrames = %d , RxFrames = %d",t,r)
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
            //%{$ntx_data{$data{"name"}}{testorder}} = ();  //创建新的profile，将删除testorder信息
        }
    }else if order == "destroyprofile" {
        if _,ok := data["name"];ok {
            fmt.Printf("%-10s%s\n","CreateProfile NAME :",data["name"])
            profile := data["name"]
            if _,ok := ntx_data["profile"];ok {
                streamlist := ntx_findstream(profile)
                _ = streamlist
                //ntx_stopstream(port,streamlist)
                delete(ntx_data,profile)
            }
        }
    }else if order == "createcustompkt" {
        if _,ok := data["pduname"];ok { //HexString 是具体的报文内容
            fmt.Printf("%-10s%s\n","CreateCustomPkt NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data
            pdunamev := ntx_data[data["pduname"]].(map[string]string)
            pdunamev["typel3"] = "pkt"
        }
    }else if order == "createethheader" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateEthHeader NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data;
            pdunamev := ntx_data[data["pduname"]].(map[string]string)
            pdunamev["typel2"] = "eth"
        }
    }else if order == "createvlanheader" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateVlanHeader NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data
            pdunamev := ntx_data[data["pduname"]].(map[string]string)
            pdunamev["typevlan"] = "vlan"
        }
    }else if order == "createipv4header" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateIPV4Header NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data
            pdunamev := ntx_data[data["pduname"]].(map[string]string)
            pdunamev["typel3"] = "ipv4"
        }
    }else if order == "createipv6header" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateIPV6Header NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data;
            pdunamev := ntx_data[data["pduname"]].(map[string]string)
            pdunamev["typel3"] = "ipv6"
        }
    }else if order == "createudpheader" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateUDPHeader NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data;
            pdunamev := ntx_data[data["pduname"]].(map[string]string)
            pdunamev["typel4"]  = "udp";
        }
    }else if order == "createtcpheader" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateTCPHeader NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data;
            pdunamev := ntx_data[data["pduname"]].(map[string]string)
            pdunamev["typel4"] = "tcp"
        }
    }else if order == "createicmppkt" {
        if _,ok := data["pduname"];ok {
            fmt.Printf("%-10s%s\n","CreateICMPPkt NAME :",data["pduname"])
            ntx_data[data["pduname"]] = data
            pdunamev := ntx_data[data["pduname"]].(map[string]string)
            pdunamev["typel4"] = "icmp"
            
            if _,ok = pdunamev["type"];ok {
                ntx_data[pdunamev["icmptype"]] = pdunamev["type"]
            }
        }
    }else if order == "createstream" {
        //object 是port
        _,ok1 := data["streamname"]
        _,ok2 := data["profilename"]
        if (ok1 && ok2) {
            stream := data["streamname"]
            fmt.Printf("%-10s%s\n","CreateStream NAME :",stream)
            if _,ok := ntx_data[stream];ok { //如果stream已经存在， 就清除计数
                tcpdump_clearstatics(stream)
            }
            
            ntx_data[stream] = data;
        }
    }else if order == "configstream" {
    	_,ok1 := data["streamname"]
    	_,ok2 := ntx_data[data["streamname"]]
        if ok1 && ok2 {
            stream  := data["streamname"]
            fmt.Printf("%-10s%s\n","CreateStream NAME :",stream)
            streamv :=ntx_data[stream].(map[string]string)
            for k,v := range(data) {
                streamv[k] = v
            }
        }
    }else if order == "destroystream" {
        if _,ok := data["streamname"];ok {
            fmt.Printf("%-10s%s\n","CreateProfile NAME :",data["name"])
            stream := data["streamname"]
           
            if _,ok = ntx_data[stream];ok {
                //ntx_stopstream(port,stream)
                delete(ntx_data,stream)
            }
        }
    }else if order == "addpdu" {
        //stream name : testorder
        _,ok1 := data["pduname"]
        _,ok2 := data["object"]
        if ok1 && ok2 {
            stream  := data["object"]
            fmt.Printf("%-10s%s\n","Stream NAME  :",stream)
            fmt.Printf("%-10s%s\n","AddPdu       :",data["pduname"])
            streamv :=ntx_data[stream].(map[string]string)
            streamv["addpdu"] = data["pduname"]        
        }       
    
    }else if order == "starttraffic" {
        port := data["object"];
        profile := ""
        streamlist := make([]string,0)
        onlyport := false;
        
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
            profile = ntx_findprofile(data["streamlist"])
        } else if _,ok := data["profilelist"];ok {
            profile = data["profilelist"]
            streamlist = ntx_findstream(profile)
        } else {
            streamlist = ntx_findstreamByPort(port)
            onlyport = true;
        }
        
        fmt.Printf("%-10s%s\n","OBJECT NAME  :",port)
        fmt.Printf("%-10s%s\n","Profile NAME :",profile)
        fmt.Printf("%-10s%s\n","ClearStatistic :",data["clearstatistic"])
        
        _,ok1 := data["clearstatistic"]
         if !ok1 || (ok1 && data["clearstatistic"] == "1"){
            if onlyport {
                tcpdump_clearstatics("?ALL");
            } else {
                for _,stream := range(streamlist) { 
                    tcpdump_clearstatics(stream);
                }
            }
            //sleep 1;
         }

        ntx_startstream(port,streamlist)
        
    } else if order == "stoptraffic" {
        port := data["object"];
        profile := ""
        streamlist := make([]string,0)
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
            profile = ntx_findprofile(data["streamlist"])
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
        if _,ok := data["portname"];ok {
        	data["portname"] = strings.TrimLeft(data["portname"],":")
            ntx_int_init(&data);
        }
    }else if order == "cleanuptest" {
        //无法删除线程，暂不清除port
        for port,_ := range(intf) {
        	portinfo := intf[port]
        	if portinfo.object != "" {
	        	continue
        	}
            fmt.Printf("Delete port %s obj %s",port,portinfo.object);
            portinfo.object = ""
        }
        fmt.Printf("Clean all -- Not support\n")
    }else if order == "resetsession" {
        if _,ok := data["object"];ok {
            fmt.Printf("%-10s%s\n","ResetSession  :", data["object"])
            fmt.Println("------ResetSession--before--")
            fmt.Println(&ntx_data,&intf)
            //str = `ps -ef | grep udpr`
            //DPrint($str)
            fmt.Println("------ResetSession----------");
            //ntx_stopstream("");
            ntx_int_reset(&data);
             for k,_ :=range(ntx_data) {
	             delete(ntx_data,k)
             }
        }
    } else {
        fmt.Printf("UNKNOW ORDER  : %s\n",order)
    }
    return 0;
}


//创建CHASSIS1 的接口
//#-portlocation 101/4 或 101/virbr1
//#-portname ::CHASSIS1/1/4
//#-porttype ETHERNET
//#-object CHASSIS1
func ntx_int_init (iinterface *map[string]string) {
	_ = iinterface
/*    my (%int) = @_;
    my $port = $int{portname};
    return if (not defined $port) ;
    if (exists $interface{$port}) {
        printf "Delete old port %s\n",$port;
        tcpdump_delport($port);
    }
    my $index = $int{portlocation};
    $index =~ s/^.*?\/(\S+)$/$1/;
    if (not ($index =~ /^\d+$/)) {
        #may be interface name ex:virbr0
        DPrint("Interface $index is created!");
        $interface{$port}{INT} = $index;
        $interface{$port}{porttype} = $int{porttype};
        $interface{$port}{portlocation} = $int{portlocation};
        $interface{$port}{object} = $int{object};
        return 
    }
    my (%devinfo,$err);
    my   @devs = Net::Pcap::pcap_findalldevs(\%devinfo, \$err);
    if ($index <=0 || $index > scalar @devs) {
        DPrint("interface $index is not exists!");
        return 0;
    }
    if (exists $interface{$port}) {
        DPrint("interface $port is exists!");
        DPrint($interface{$port});
        if ($devs[$index-1] ne $interface{$port}{INT} ) {
            DPrint("INTERFACE is change ：unsupport, please reboot server");
        }
    }
    DPrint("interface $index is $devs[$index-1]!");
    $interface{$port}{INT} = $devs[$index-1];
    $interface{$port}{porttype} = $int{porttype};
    $interface{$port}{portlocation} = $int{portlocation};
    $interface{$port}{object} = $int{object};
    */
}
//#重置 CHASSIS1
//#-object CHASSIS1
func ntx_int_reset(iinterface *map[string]string) {
	_ = iinterface
/*    my (%int) = @_;
    my $object = $int{object};
    foreach my $port(keys %interface) {
        DPrint("Find $object : $port");
        if (not(exists $interface{$port}{object} &&
            $object eq $interface{$port}{object})){
            next;
        }
        DPrint("reset $object : $port");
        tcpdump_release($port);
        tcpdump_delport($port);
    }*/
}
//#根据stream找profile
func ntx_findprofile (stream string) string {
	_ = stream
/*    my $stream = shift;
    our %ntx_data;
    foreach(keys %ntx_data){
        if (exists $ntx_data{$_}{profilename} &&
            exists $ntx_data{$_}{streamname}) {
            if ($ntx_data{$_}{streamname} eq $stream) {
                return $ntx_data{$_}{profilename}
            }
        }
    }
    return undef;*/
	return ""
}

//#根据profile找到所属的stream
func ntx_findstream(profile string) []string {
	_ = profile
/*    my $profile = shift;
    our %ntx_data;
    my @stream = ();
    foreach(keys %ntx_data){
        if (exists $ntx_data{$_}{profilename} &&
            exists $ntx_data{$_}{streamname}) {
            if ($ntx_data{$_}{profilename} eq $profile) {
                push @stream, $_;
            }
        }
    }
    return @stream;*/
	var stringl []string = []string{"1","2"}
	return stringl
}

// #根据port找到所属的stream
func ntx_findstreamByPort(port string) []string {
	_ = port
    /*my $port = shift;
    our %ntx_data;
    my @stream = ();
    my $traffic = undef;
    foreach(keys %ntx_data){
        if (exists $ntx_data{$_}{trafficname} &&
            ($ntx_data{$_}{object} eq $port)) {
            $traffic = $_;
            last
        }
    }
    if (not defined $traffic) {
        return @stream;
    }
    foreach(keys %ntx_data){
        if (exists $ntx_data{$_}{streamname}) {
            if ($ntx_data{$_}{object} eq $traffic) {
                push @stream, $_;
            }
        }
    }
    return @stream; */
    stream := []string{"1","2"}
    return stream
}

func ntx_startstream(port string,streamlist []string){
	_ = port
	_ = streamlist
/*    my($port,@streamlist) = @_;
    our %ntx_data;
    if (@streamlist <= 0) {
        @streamlist = ntx_findstreamByPort($port);
    }
    foreach my $stream(@streamlist){
        my $profile = $ntx_data{$stream}{profilename};
        if (not exists $ntx_data{$profile}) {
            print "[ERROR]Can not find profile of stream $stream\n";
            next;
        }
        
        my $timeout = 0;
        if(exists $ntx_data{$profile}{trafficloadunit} && 
            exists $ntx_data{$profile}{trafficload} &&
            ($ntx_data{$profile}{trafficload} >0)) {
            if("fps" eq $ntx_data{$profile}{trafficloadunit}) {
                $timeout = 1/$ntx_data{$profile}{trafficload};
            } elsif("percent" eq $ntx_data{$profile}{trafficloadunit}) {
                $timeout = 1/(100 * $ntx_data{$profile}{trafficload});
            }
        }
        printf "Find Stream %s in %s (timeout : $timeout)\n",
            $ntx_data{$stream}{streamname},$profile,$timeout;
        my %pdu = ntx_getpdu($stream);
        while( my($k, $v) = each %pdu){
            print "\t$k = $v\n";
        }
        if (not exists $pdu{framenum}) { #continue模式
            if( $ntx_data{NTX_STREAM}{$stream}{PID} <= 0) {
                my $pid = fork();
                if($pid == 0) {
                    while(1) {
                        my %info = ntx_getinfo(%pdu);
                        $info{ADDDATA} = 'START'.$stream.'END';
                        my $packet = getpacket(\%info);
                        tcpdump_send($port,$packet,1,$timeout);
                        while (getInfoNext(\%info) > 0) {
                            #Time::HiRes::sleep(0.1);
                            $packet = getpacket(\%info);
                            tcpdump_send($port,$packet,1,$timeout);
                        }
                    }
                    exit;
                }
                DPrint("Start $stream ($pid)");
                $ntx_data{NTX_STREAM}{$stream}{PID}  = $pid;
                $ntx_data{NTX_STREAM}{$stream}{PORT} = $port
            }
        } else {
            my %info = ntx_getinfo(%pdu);
            $info{ADDDATA} = 'START'.$stream.'END';
            my $packet = getpacket(\%info);
            tcpdump_send($port,$packet,1,0);
            $ntx_data{$profile}{'txframes'}++;
            my $num = 1;
            while (getInfoNext(\%info) > 0) {
                last if (++ $num > $info{FRAMENUM});
                #Time::HiRes::sleep(0.1);
                $packet = getpacket(\%info);
                tcpdump_send($port,$packet,1,0);
                $ntx_data{$profile}{'txframes'}++;
            }
        }
    }
    */
}

func ntx_stopstream(port string,streamlist []string){
	_ = port
	_ = streamlist
   /* my($port,@streamlist) = @_;
    our %ntx_data;
    if (@streamlist <= 0) {
        @streamlist = keys %{$ntx_data{NTX_STREAM}}
    }
    foreach my $stream(@streamlist){
        if(not exists $ntx_data{NTX_STREAM}{$stream}){
            printf "Stream %s not start\n",$stream;
            next;
        }
        if (defined $port && $ntx_data{NTX_STREAM}{$stream}{PORT} ne $port) {
            next;
        }
        printf "Stop Stream %s\n",$stream;
        my $pid = $ntx_data{NTX_STREAM}{$stream}{PID};
        kill 9, $pid;
        $pid = waitpid $pid,0;
        DPrint("($stream)PID $pid is over");
        delete $ntx_data{NTX_STREAM}{$stream};
    }*/
}

func ntx_gethostinfo(hostname string) map[string]string {
	_ = hostname
	host := make(map[string]string)
	
 /*   my ($hostname) = @_;
    our %ntx_data;
    my %host = %{$ntx_data{$hostname}};
    my $port = $ntx_data{$hostname}{object};
    $host{vid} = 0;
    if (#(not exists $interface{$port}) &&
        exists $ntx_data{$port}{subintname}) {
        if (exists $ntx_data{$port}{vlanid}) {
            $host{vlanid} = $ntx_data{$port}{vlanid};
        }
        $port = $ntx_data{$port}{object};  #是子接口，就换成实接口
    }
    $host{port} = $port;*/
    return host;
}


//#获取stream的pdu信息
func ntx_getpdu(stream string){
	_ = stream
  /*  my $stream = shift;
    our %ntx_data;
    my %pdudata;
    
    if (not (defined $stream && exists $ntx_data{$stream})) {
        return %pdudata;
    }
    my $profile = $ntx_data{$stream}{profilename};
    
    my $pdu = $ntx_data{$stream}{addpdu};
    
    DPrint("Creat pdu($stream): $pdu");
    $pdu =~ s/[{}]//g;
    my @pduname = split(/\s+/,$pdu);
    foreach(@pduname){
        DPrint("Find pdu : $_");
        if (exists $ntx_data{$_}) {
            DPrint("Creat pdu : $_");
            %pdudata = (%pdudata,%{$ntx_data{$_}});  
        }
    }
    %pdudata = (%pdudata,%{$ntx_data{$stream}});
    if (exists $ntx_data{$profile}) {
        %pdudata = (%pdudata,%{$ntx_data{$profile}});
    }
    return %pdudata;*/
}

//#**************************************************
//# 转换NTX指令为内部指令
//#**************************************************
func ntx_getinfo(data *map[string]string){
	_ = data 
    /*my (%data) = @_;
    my %info = ();
    our %ntx_data;
    $info{'FRAMENUM'} = $data{'framenum'} if(exists $data{'framenum'});
    $info{'FRAMELEN'} = $data{'framelen'} if(exists $data{'framelen'});
    $info{'TYPE2EXT'} = "\U$data{'l2'}" if(exists $data{'l2'});
    $info{'MACDEST'} = $data{'ethdst'} if(exists $data{'ethdst'});
    $info{'MACSRC'} = $data{'ethsrc'} if(exists $data{'ethsrc'});
    $info{'ETHTYPE'} = $data{'ethtype'} if(exists $data{'ethtype'});
    $info{'MACDEST'} = $data{'da'} if(exists $data{'da'});
    $info{'MACSRC'} = $data{'sa'} if (exists $data{'sa'}) ;
    $info{'VLANID'} = $data{'vlanid'} if (exists $data{'vlanid'}) ;
    #$info{'VLANTAG'} = $data{'vlantag'} if (exists $data{'vlantag'}) ;
    $info{'VLANIDMODE'} = $data{'vlanidmode'} if (exists $data{'vlanidmode'}) ;
    $info{'VLANIDCOUNT'} = $data{'vlanidcount'} if (exists $data{'vlanidcount'}) ;
    $info{'VLANIDSTEP'} = $data{'vlanidstep'} if (exists $data{'vlanidstep'}) ;
    $info{'MPLS.TYPE'} = $data{'mplstype'} if (exists $data{'mplstype'}) ;
    $info{'MPLS.LABEL'} = $data{'mplslabel'} if (exists $data{'mplslabel'}) ;
    $info{'MPLS.LABELCOUNT'} = $data{'mplslabelcount'} if (exists $data{'mplslabelcount'}) ;
    $info{'MPLS.LABELMODE'} = $data{'mplslabelmode'} if (exists $data{'mplslabelmode'}) ;
    $info{'MPLS.LABELSTEP'} = $data{'mplslabelstep'} if (exists $data{'mplslabelstep'}) ;
    $info{'MPLS.EXP'} = $data{'mplsexp'} if (exists $data{'mplsexp'}) ;
    $info{'MPLS.TTL'} = $data{'mplsttl'} if (exists $data{'mplsttl'}) ;
    $info{'MPLS.BOTTOMOFSTACK'} = $data{'mplsbottomofstack'} if (exists $data{'mplsbottomofstack'}) ;
    $info{'TYPE3EXT'} = "\U$data{'l3'}" if(exists $data{'l3'});
    $info{'IP.SRC'} = $data{'ipsrcaddr'} if(exists $data{'ipsrcaddr'});
    $info{'IP.DEST'} = $data{'ipdstaddr'} if(exists $data{'ipdstaddr'});
    $info{'IP.DEST'} = $data{'destipaddr'} if(exists $data{'destipaddr'});
    $info{'IP.DESTCOUNT'} = $data{'ipdstaddrcount'} if(exists $data{'ipdstaddrcount'});
    $info{'IP.DESTMODE'} = $data{'ipdstaddrmode'} if(exists $data{'ipdstaddrmode'}); #increment
    $info{'IP.DESTSTEP'} = $data{'ipdstaddrstep'} if(exists $data{'ipdstaddrstep'}); #0.0.0.1
    $info{'IP.SRC'} = $data{'sourceipaddr'} if(exists $data{'sourceipaddr'});
    $info{'IP.SRCCOUNT'} = $data{'ipsrcaddrcount'} if(exists $data{'ipsrcaddrcount'});
    $info{'IP.SRCMODE'} = $data{'ipsrcaddrmode'} if(exists $data{'ipsrcaddrmode'}); #increment
    $info{'IP.SRCSTEP'} = $data{'ipsrcaddrstep'} if(exists $data{'ipsrcaddrstep'}); #0.0.0.1
    $info{'IP.DEST'} = $data{'destipaddr'} if(exists $data{'destipaddr'});
    #$info{'IP.TYPE'}  = $data{'ipprotocoltype'}if(exists $data{'ipprotocoltype'});
    $info{'IPV6.SRC'} = $data{'ipv6srcaddress'}if(exists $data{'ipv6srcaddress'});
    $info{'IPV6.DEST'} = $data{'ipv6dstaddress'}if(exists $data{'ipv6dstaddress'});
    #$info{'IPV6.TYPE'} = $data{'ipv6protocoltype'}if(exists $data{'ipv6protocoltype'});
    $info{'IPV6.SRCCOUNT'} = $data{'ipv6srcaddresscount'}if(exists $data{'ipv6srcaddresscount'}); 
    $info{'IPV6.SRCMODE'} = $data{'ipv6srcaddressmode'}if(exists $data{'ipv6srcaddressmode'}); 
    $info{'IPV6.SRCSTEP'} = $data{'ipv6srcaddressstep'}if(exists $data{'ipv6srcaddressstep'}); 
    $info{'TYPE4EXT'} = "\U$data{'l4'}" if(exists $data{'l4'});
    $info{'UDP.SRC'} = $data{'udpsrcport'}if(exists $data{'udpsrcport'});
    $info{'UDP.DEST'} = $data{'udpdstport'}if(exists $data{'udpdstport'});
    $info{'UDP.SRCMODE'} = $data{'udpsrcportmode'}if(exists $data{'udpsrcportmode'});
    $info{'UDP.SRCSTEP'} = $data{'udpsrcportstep'}if(exists $data{'udpsrcportstep'});
    $info{'UDP.SRCSTEP'} = $data{'udpsrcstep'}if(exists $data{'udpsrcstep'});
    $info{'UDP.SRCCOUNT'} = $data{'udpsrcportcount'}if(exists $data{'udpsrcportcount'});
    #$info{"UDP.CHECKSUM"}= $data{''}if(exists $data{''});
    if(exists $data{'tcpsrcport'}){
        $info{"TCP.SRC"} = $data{'tcpsrcport'};
        #$info{"TCP.FLAG"} = 0x10;  #默认填ack
    }
    $info{"TCP.DEST"} = $data{'tcpdstport'}if(exists $data{'tcpdstport'});
    $info{"TCP.FLAG"} |= 0x02  if(exists $data{'syn'} && $data{'syn'} > 0);
    $info{"TCP.FLAG"} |= 0x02  if(exists $data{'tcpflagsyc'} && (lc $data{'tcpflagsyc'}) eq 'true');
    $info{"TCP.FLAG"} |= 0x10  if(exists $data{'tcpflagack'} && (lc $data{'tcpflagack'}) eq 'true');
    #$info{"TCP.FLAG"} &= ~0x10 if(exists $data{'tcpflagack'} && (lc $data{'tcpflagack'}) eq 'false');
    $info{'TCP.SRCMODE'} = $data{'tcpsrcportmode'}if(exists $data{'tcpsrcportmode'});
    $info{'TCP.SRCSTEP'} = $data{'tcpsrcportstep'}if(exists $data{'tcpsrcportstep'});
    $info{'TCP.SRCSTEP'} = $data{'tcpsrcstep'}if(exists $data{'tcpsrcstep'});
    $info{'TCP.SRCCOUNT'} = $data{'tcpsrcportcount'}if(exists $data{'tcpsrcportcount'});
    $info{"CHECKSUM"} =$data{'enablechecksum'}if(exists $data{'enablechecksum'});
    if(exists $data{'icmptype'}){
        if ($data{'icmptype'} eq 'echo_request') {
            $info{'ICMP.TYPE'} = 8;
        }elsif($data{'icmptype'} eq 'echo_reply'){
            $info{'ICMP.TYPE'} = 0;
        }
    }
    $info{'ICMP.ID'} = $data{'icmpid'} if(exists $data{'icmpid'});
    $info{'ICMP.ID'} = $data{'id'} if(exists $data{'id'});
    $info{'DATA'} = $data{'hexstring'} if(exists $data{'hexstring'});
    $info{'DATA'} = $data{'customheader'} if(exists $data{'customheader'}); 
    $info{'TYPE3EXT'} = 'IPV4' if (exists $info{'IP.SRC'});
    $info{'TYPE3EXT'} = 'IPV6' if (exists $info{'IPV6.SRC'});
    $info{'TYPE4EXT'} = 'UDP' if (exists $info{'UDP.DEST'});
    $info{'TYPE4EXT'} = 'TCP' if (exists $info{'TCP.DEST'});
    $info{'TYPE4EXT'} = 'ICMP' if (exists $info{'ICMP.TYPE'});
    $info{'TYPE3EXT'} = 'IPV6IPV4' if (exists $info{'IP.SRC'} && exists $info{'IPV6.SRC'});
    
    return %info; */
}
//#学习ARP
func host_sendarp(host *map[string]string,destip string){
	_ = host
	_ = destip
/*    my ($host,$destip) = @_;
    my $port = $$host{port};
    my $arp;
    $arp->{ip}  = $$host{ipv4addr};
    $arp->{dest} = $$host{macaddr};
    $arp->{vid} = $$host{vlanid} if(exists $$host{vlanid});
    $arp->{dstip} = $$host{ipv4sutaddr} if(not defined $destip);
    $arp->{srcip} = $arp->{ip};
    print "SendArpRequest :$arp->{srcip}, $arp->{dstip}, $arp->{dest}, $arp->{vid}\n";
    tcpdump_send($port,pktArpRequest($arp));
    return 1;
    */
}

//#获取mac， 无目的ip，取网关mac
func host_getmac(arplist []string,host string, destip string){
	_ = arplist
	_ = host
	_ = destip
   /* my ($arplist,$host,$destip) = @_;
    my $port = $$host{port};
    my $vid = 0;
    $vid = $$host{vlanid} if(exists $$host{vlanid});
    if (not defined $destip) {
        $destip = $$host{ipv4sutaddr};
    }
    
    if(not exists ${$arplist}{$destip.':'.$vid}) {
        host_sendarp($host,$destip);
        sleep 1; #等待应答
    }
    if(not exists ${$arplist}{$destip.':'.$vid}) {
        DPrint("NO MAC ($destip)");
        return undef;
    }
    return ${$arplist}{$destip.':'.$vid}; */
}

//#ping 一个主机
//#暂不支持一个host多个ping实例
func host_ping(host *map[string]string,ping *map[string]string) bool {
	_ = host
	_ = ping
 /*   my ($pinglist,$arplist,$host,$ping) = @_;
    my $port = $$host{port};
    my $vid = 0;
    $vid = $$host{vlanid} if(exists $$host{vlanid});
    if (not exists $ping->{host}) { #host必需指定
        return 0;
    }
    
    #没有判断ping的hostip是否子网IP , 直接取网关MAC ??????????
    my $destmac = host_getmac($arplist,$host);
    if(not defined $destmac) {
        DPrint("NO MAC");
        return 0;
    }
    
    #删除老的ping记录, 一个host仅产生一个ping ??????
    if(defined $pinglist){
        lock($pinglist);
        foreach(keys %{$pinglist}){
            if (/:$vid/){
                DPrint("Delete : $_");
                delete ${$pinglist}{$_} ;
            }
        }
    }
    
    #组包
    my $pingid = ($ping->{host}).':'.$vid.":";
    my ($eth,$ip,$icmp);
    $eth->{src} = $$host{macaddr};
    $eth->{dest} = $destmac;
    $eth->{vid} = $vid if($vid > 0);
    $eth->{type} = 0x0800; # 0x86dd;

    $ip->{ttl} = 128;
    $ip->{hlen} = 5;
    $ip->{ver} = 4;            
    $ip->{dest_ip} =$ping->{host};
    $ip->{src_ip} = $$host{ipv4addr};
    $ip->{ttl} = $ping->{ttl} if(exists $ping->{ttl});
    $ip->{proto} = 1;
    $ip->{id} = 31418;

    $icmp->{type} = 8;     
    $icmp->{code} = 0;
    $icmp->{id}   = 1;     #id

    my $seq = 9; #初始序号
    my ($count,$interval,$timeout) = (4,0.03,3);
    $count = $ping->{count} if(exists $ping->{count});
    $interval = $ping->{interval}/1000 if(exists $ping->{interval});
    $timeout = $ping->{timeout}/1000 if(exists $ping->{timeout});
    {
        lock($pinglist);
        ${$pinglist}{$pingid."timeout"} = $timeout;
        ${$pinglist}{$pingid."count"}   = $count;
    }
    while ($count-- > 0) {
        {
            lock($pinglist);
            ${$pinglist}{$pingid.$seq} = Time::HiRes::time;
        }
        #长度暂不处理
        $icmp->{data} = pack('nna*a*',$icmp->{id},$seq,
                             'abcdefghijklmin');
        $ip->{data}   = pktIcmpencode($icmp,$ip);
        $eth->{data}  = pktIpencode($ip);
        tcpdump_send($port,pktEthencode($eth));
        $seq ++;
        Time::HiRes::sleep($interval);
    }
    Time::HiRes::sleep($timeout - $interval) if($timeout > $interval);
    
    */
	 return true
}

//#获取ping的结果
//#暂不支持一个host多个ping实例
func host_pingresult(host *map[string]string, ping *map[string]string) string {
	_ = host
	_ = ping
 /*   my ($host,$ping) = @_;
    my $port = $$host{port};
    my $vid = 0;
    $vid = $$host{vlanid} if(exists $$host{vlanid});
    my $ret = "-rx 0 -tx 0";
    if (not exists $ping->{host}) {
        return $ret;
    }
    
    my $pingid = ($ping->{host}).':'.$vid.":";
    my %ping;
    {
        lock($interface{$port}{ping});
        if(not exists ${$interface{$port}{ping}}{$pingid."timeout"}){
            return $ret;
        }
        while(my ($k,$v) = each %{$interface{$port}{ping}}){
            $ping{$k} = $v;
        }
    }
    my ($rx,$tx,$max,$min,$avg) = (0,0,0,0,0);
    my $timeout = $ping{$pingid."timeout"};
    foreach my $key (keys %ping) {
        next if(index($key,$pingid) != 0);
        next if($key !~ /:(\d+)$/);
        $tx++;
        if(exists $ping{$pingid.$1.'R'}) {
            next if($ping{$pingid.$1.'R'} > ($ping{$key} + $timeout));
            $rx++;
            my $tmp = $ping{$pingid.$1.'R'} - $ping{$key};
            $max = $tmp if ($tmp > $max);
            $min = $tmp if($tmp < $min || !$min);
            $avg += $max;
            DPrint("$key : $tmp");
        } else {
            DPrint("$key : NO REPLY");
        }
    }
    $avg = $avg/$rx if($rx);
    $ret = sprintf("-rx %d -tx %d -max %.3f -min %.3f -avg %.3f",
                    $rx,$tx,$max,$min,$avg);
    return $ret;
    */
    return ""
}

//#**************************************************
//# 大数的递增处理 11 22 33 44 + 00 01 00 20
//#**************************************************
func increment(data string, num int){
	_ = data
	_ = num
   /* my ($data,$num) = @_;
    my $len = length $data;
    my $tmp = 0;
    while($len-- > 0) {
        $tmp = vec($data,$len,8)+vec($num,$len,8)+$tmp;
        if($tmp <= 255){
            vec($data,$len,8) = $tmp;
            $tmp = 0;
        } else {
            vec($data,$len,8) = $tmp & 0xFF;
            $tmp = $tmp >> 8;
        }
    }
    return $data;*/
}

//#**************************************************
//# 获取下一个包的信息
//#**************************************************
func getInfoNext(info *map[string]string) int{
	_ = info
	/*
    my $info = shift;
    foreach my $k ('VLANID','IP.SRC','IPV6.SRC','UDP.SRC','TCP.SRC','IP.DEST','UDP.DEST','TCP.DEST') {
        next if (not exists $info->{$k}) ;
        next if (not exists $info->{$k.'COUNT'});
        if (not exists $info->{$k.'COUNT.TMP'}) {
            $info->{$k.'.TMP'}      = $info->{$k};
            $info->{$k.'COUNT.TMP'} = $info->{$k.'COUNT'};
        }
        --($info->{$k.'COUNT'});
        if ($info->{$k.'COUNT'} <= 0){
            $info->{$k}      = $info->{$k.'.TMP'};
            $info->{$k.'COUNT'} = $info->{$k.'COUNT.TMP'}
        }else{
            if (exists $info->{$k.'MODE'} && exists $info->{$k.'STEP'}) {
                if ($info->{$k.'MODE'} eq 'increment') {
                    if ($k =~ /IP/) {
                        my $step = formatIptoByte($info->{$k.'STEP'});
                        my $ip = formatIptoByte($info->{$k});
                        $info->{$k} = formatIp(increment($ip,$step));
                    } else {
                        $info->{$k} = $info->{$k} + $info->{$k.'STEP'};
                    }
                }
            }
        }
    }*/
    return 1;
}


//#**************************************************
//# 根据报文参数封装报文
//#**************************************************
func getpacket (info *map[string]string){
	_ = info
    /*info = shift;
    my ($ip, $ip6, $udp, $tcp, $icmp,$packet);
    my $len = 14;#mac
    $len+=4 if(exists $$info{'VLANID'});
    $len+=4 if (exists $$info{'MPLS.TYPE'});
    if (exists $$info{TYPE3EXT} ) {    
        if ($$info{TYPE3EXT} eq 'IPV4' ) {
            $ip->{ttl} = 128;
            $ip->{hlen} = 5;
            $ip->{ver} = 4;            
            $ip->{dest_ip} = $$info{'IP.DEST'};
            $ip->{src_ip} = $$info{'IP.SRC'};
            $ip->{ttl} = $$info{'IP.TTL'} if(exists $$info{'IP.TTL'});
            $ip->{proto} = $$info{'IP.TYPE'} if(exists $$info{'IP.TYPE'}); 
            $ip->{id} = 31418;
            $len+=20;
        } elsif ($$info{TYPE3EXT} eq 'IPV6') {
            $ip6->{ttl} = 128;
            $ip6->{ver} = 6;            
            $ip6->{dest_ip} = $$info{'IPV6.DEST'};
            $ip6->{src_ip} = $$info{'IPV6.SRC'};
            $ip6->{ttl} = $$info{'IPV6.TTL'} if(exists $$info{'IPV6.TTL'});
            $ip6->{proto} = $$info{'IPV6.TYPE'} if(exists $$info{'IPV6.TYPE'});
            $len+=40;
        } elsif ($$info{TYPE3EXT} eq 'IPV6IPV4') {
            $ip6->{ttl} = 128;
            $ip6->{ver} = 6;
            $ip6->{dest_ip} = $$info{'IPV6.DEST'};
            $ip6->{src_ip} = $$info{'IPV6.SRC'};
            $ip6->{proto} = 4;           #4in6隧道类型
            $ip6->{ttl} = $$info{'IPV6.TTL'} if(exists $$info{'IPV6.TTL'});
            $ip6->{proto} = $$info{'IPV6.TYPE'} if(exists $$info{'IPV6.TYPE'});
            $ip->{ttl} = 128;
            $ip->{hlen} = 5;
            $ip->{ver} = 4;            
            $ip->{dest_ip} = $$info{'IP.DEST'};
            $ip->{src_ip} = $$info{'IP.SRC'};
            $ip->{ttl} = $$info{'IP.TTL'} if(exists $$info{'IP.TTL'});
            $ip->{proto} = $$info{'IP.TYPE'} if(exists $$info{'IP.TYPE'}); 
            $ip->{id} = 31418;
            $len+=60;
        }
    }
    if (exists $$info{TYPE4EXT} ) {
        if ($$info{TYPE4EXT} eq 'UDP'){
            $udp->{src_port} = $$info{'UDP.SRC'};
            $udp->{dest_port} = $$info{'UDP.DEST'};
            if (defined $ip) {
                $ip->{proto} = 17 if(not exists $ip->{proto});
            }
            if(defined $ip6){
                $ip6->{proto} = 17 if(not exists $ip6->{proto});
            }
            $udp->{len} = 2;
            $len += 8;
            if (exists $$info{DATA}) {
                 $udp->{data} = pack("H*",$$info{DATA});
            } else {
                if (exists $$info{FRAMELEN} && $$info{FRAMELEN} > $len ) {
                    if(length $$info{ADDDATA} < ($$info{FRAMELEN}-$len)) {
                        $udp->{data} = "\0" x ($$info{FRAMELEN}-$len - (length $$info{ADDDATA}));
                        $udp->{data} .= $$info{ADDDATA};
                    } else {
                        $udp->{data} = "\0" x ($$info{FRAMELEN}-$len);
                    }
                }
            }
        }elsif ($$info{TYPE4EXT} eq 'TCP'){
            $tcp->{src_port} = $$info{'TCP.SRC'};
            $tcp->{dest_port} = $$info{'TCP.DEST'};
            if (defined $ip) {
                $ip->{proto} = 6 if(not exists $ip->{proto});
            }
            if(defined $ip6){
                $ip6->{proto} = 6 if(not exists $ip6->{proto});
            }
            $tcp->{reserved};
            $tcp->{flags} = 0;
            $tcp->{flags} = $$info{'TCP.FLAG'} if(exists $$info{'TCP.FLAG'});
            $tcp->{seqnum} = 0;
            $tcp->{acknum} = 0;
            $tcp->{winsize} = 1024;
            $tcp->{urg};
            $tcp->{options};
            $tcp->{hlen} = 5;
            $len += 20;
            if(!(($tcp->{flags} & 0x02) && matchswitch('-firewall'))) { #firewall syn不填充载荷
                if (exists $$info{DATA}) {
                    $tcp->{data} = pack("H*",$$info{DATA});
                }else{
                    if (exists $$info{FRAMELEN} && $$info{FRAMELEN} > $len ) {
                        if(length $$info{ADDDATA} < ($$info{FRAMELEN}-$len)) {
                            $tcp->{data} = "\0" x ($$info{FRAMELEN}-$len - (length $$info{ADDDATA}));
                            $tcp->{data} .= $$info{ADDDATA};
                        } else {
                            $tcp->{data} = "\0" x ($$info{FRAMELEN}-$len);
                        }
                    }
                }
            }
        }elsif ($$info{TYPE4EXT} eq 'ICMP'){
            if (defined $ip) {
                $ip->{proto} = 1 if(not exists $ip->{proto});
            }
            $icmp->{type} = $$info{'ICMP.TYPE'};
            if ($icmp->{type} == 8 || $icmp->{type} == 0) {
                $icmp->{code} = 0;
                $icmp->{id} = $$info{'ICMP.ID'} || 0;
                $len += 4;
                $icmp->{data} = pack('nna*a*',$icmp->{id},1,
                                     'abcdefghijklmin',$$info{ADDDATA}."\r\n");
            }
        }
    }
    if (defined $ip){
        if (defined $udp) {
            $ip->{data} = pktUdpencode($udp,$ip);
        }elsif (defined $tcp) {
            $ip->{data} = pktTcpencode($tcp,$ip);
        }elsif (defined $icmp) {
            $ip->{data} = pktIcmpencode($icmp,$ip);
        }else {
            if (exists $$info{DATA}) {
                 $ip->{data} = pack("H*",$$info{DATA});
            }
            $ip->{data} .= $$info{ADDDATA}; 
        }
        $packet = pktIpencode($ip);
    }
    if(defined $ip6){
        if (defined $packet) {   #4in6隧道
            $ip6->{data} = $packet;
        }elsif (defined $udp) {
            $ip6->{data} = pktUdpv6encode($udp,$ip6);
        }elsif (defined $tcp) {
            $ip6->{data} = pktTcpv6encode($tcp,$ip6);
        } else {
            if (exists $$info{DATA}) {
                 $ip6->{data} = pack("H*",$$info{DATA});
            }
            $ip6->{data} .= $$info{ADDDATA}."\r\n" if (not defined $ip); 
        }
        $packet = pktIpv6encode($ip6);
    }
    if ((not (defined $ip || defined $ip6)) && (exists $$info{DATA})) { #custom的时候使用
        $packet .= pack("H*",$$info{DATA});
        $packet .= $$info{ADDDATA};
    }
    if (exists $$info{'MPLS.TYPE'} ) { #暂时只支持一层标签
        my $mpls2 = ($$info{'MPLS.LABEL'}>>4);
        my $mpls3 = ($$info{'MPLS.LABEL'} & 0xf)<<4;
        $mpls3 = $mpls3 + $$info{'MPLS.EXP'}*2 + 1; #bottom =1
        $packet = pack ("nCCa*",$mpls2,$mpls3,$$info{'MPLS.TTL'},$packet);
    }
    if (defined $packet && exists $info->{'MACDEST'}) {
        my $eth;
        $eth->{src} = $$info{MACSRC};
        $eth->{dest} = $$info{MACDEST};
        $eth->{vid} = $$info{VLANID} if(exists $$info{'VLANID'});
        $eth->{type} = ($$info{TYPE3EXT} eq 'IPV4')?0x0800:0x86dd;
        $eth->{type} = 0x8847 if(exists $$info{'MPLS.TYPE'});
        $eth->{type} = '0x'.$$info{ETHTYPE} if(exists $$info{ETHTYPE});
        $eth->{data} = $packet;
        $packet = pktEthencode($eth);
    }
    
    return $packet;*/
}
/*
sub isPidOk{
    my $pid = shift;
    my $ret = waitpid($pid,WNOHANG);
    if ($ret == 0){
        return 1
    }
    if ($ret == -1) {
        print "The $pid is not find!!!!!!!!!!!!!!!!";
    }
    if ($ret == $pid) {
        print "The $pid is over!!!!!!!!!!!!!!!!";
    }
    return 1;
}
*/

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
