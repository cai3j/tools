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
                host := ntx_gethostinfo(object);
                if(_,ok1 = data["result"];!ok1) {
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
   }else if order == "createstaengine" { #创建统计引擎
        if _,ok := data["staenginename"];ok {
            fmt.Printf("%-10s%s\n","OBJECT        NAME :",$data{object}; # PORT信息
            fmt.Printf("%-10s%s\n","CreateProfile NAME :",$data{'staenginename'};
            fmt.Printf("%-10s%s\n","StaType NAME :",$data{'statype'};
            %{$ntx_data{$data{'staenginename'}}} = %data;
            if ($data{statype} ne "analysis") {
                tcpdump_creat($data{object});
            }            
        }
    }elsif($order eq 'configcapturemode'){
        fmt.Printf("%-10s%s\n","OBJECT        NAME :",$data{object}; # engen
    }elsif($order eq 'startcapture'){
        fmt.Printf("%-10s%s\n","OBJECT        NAME :",$data{object}; # engen
        my $eng = $data{object};
        if (exists $ntx_data{$eng}) {
            if ($ntx_data{$eng}{statype} eq "analysis") {
                tcpdump_start($ntx_data{$eng}{object}); #在抓包引擎的接口上抓
            }
        }
    }elsif($order eq 'stopcapture'){
        fmt.Printf("%-10s%s\n","OBJECT        NAME :",$data{object}; # engen
        my $eng = $data{object};
        if (exists $ntx_data{$eng}) {
            if ($ntx_data{$eng}{statype} eq "analysis") {
                tcpdump_stop($ntx_data{$eng}{object}); #在抓包引擎的接口上停止
            }    
        }
    }elsif($order eq 'getcapturepacket'){
        if (exists $data{'packetindex'}) {
            fmt.Printf("%-10s%s\n","OBJECT        NAME :",$data{object}; # engen
            fmt.Printf("%-10s%s\n","PacketIndex        :",$data{'packetindex'};
            my $eng = $data{object};
            my $str = tcpdump_get($ntx_data{$eng}{object},$data{'packetindex'});
            if (defined $str) {
                my $len = send(SERVER,"OK:$str",0,$client);
                print "Send:OK:$str($len)\n";
            } else {
                my $len = send(SERVER,"ERROR",0,$client);
                print "Send:ERROR($len)\n";
            }
        }
    }elsif($order eq 'createfilter'){
        if (exists $data{'filtername'}) {
            printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # port
            printf "%-10s%s\n","filtername NAME :",$data{'filtername'};
            %{$ntx_data{$data{'trafficname'}}} = %data;
        }
    }elsif($order eq 'configfilter'){
        if (exists $data{'filtername'}) {
            printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # port
            printf "%-10s%s\n","filtername NAME :",$data{'filtername'};
            %{$ntx_data{$data{'trafficname'}}} = %data;
        }
    }elsif($order eq 'destoryfilter'){
        if (exists $data{'filtername'}) {
            printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # port
            printf "%-10s%s\n","filtername NAME :",$data{'filtername'};
            delete $ntx_data{$data{'trafficname'}};
        }
    }elsif($order eq 'createtraffic'){
        if (exists $data{'trafficname'}) {
            printf "%-10s%s\n","CreateTraffic NAME :",$data{'trafficname'};
            %{$ntx_data{$data{'trafficname'}}} = %data;
        }
    }elsif($order eq 'getportstats'){
        my $string = undef;
        my $staEngine = $data{object}; #引擎名称
        my $port = $ntx_data{$staEngine}{object};
        my ($t,$r,$ts,$rs) = tcpdump_stat($port);
        $string = "GetPortStats TxFrames = $t , RxFrames = $r , rxsignature = $rs , txsignature = $ts";
        my $len = send(SERVER,$string,0,$client);
        print "Send:$string($len)\n";
    }elsif($order eq 'getstreamstats'){
        my $string = undef;
        if (exists $data{'streamname'}) {
            my $staEngine = $data{object};        #引擎名称
            my $streamname = $data{'streamname'}; #流名称
            my $port = $ntx_data{$staEngine}{object};
            printf "%-10s%s\n","OBJECT NAME :",$staEngine;
            printf "%-10s%s\n","Stream NAME :",$streamname;
            my ($t,$r) = tcpdump_stat($port,$streamname);
            $string = "GetStreamStats TxFrames = $t , RxFrames = $r";
        } else {
            $string = "GetStreamStats Error";
        }
        my $len = send(SERVER,$string,0,$client);
        print "Send:$string($len)\n";
    }elsif($order eq 'createprofile'){
        #Input: 1. args:参数列表，可包含如下参数
        #  (1) -Name Name 必选参数,Profile的名字
        #  (2) -Type Type 可选参数,Constant Burst
        #  (3) -TrafficLoad StreamLoad 可选参数，数据流发送的速率，如 -StreamLoad 1000
        #  (4) -TrafficLoadUnit TrafficLoadUnit 可选参数，数据流发送的速率单位，如 -TrafficLoadUnit fps
        #  (5) -BurstSize BurstSize, 可选参数，Burst中连续发送的报文数量
        #  (6) -FrameNum FrameNum, 可选参数，一次发送报文的数量
        #  (7) -Blocking blocking, 堵塞模式，Enable/Disable
        #  (8) -DistributeMode DistributeMode
        if (exists $data{'name'}) {
            printf "%-10s%s\n","CreateProfile NAME :",$data{'name'};
            %{$ntx_data{$data{'name'}}} = %data;
            #%{$ntx_data{$data{'name'}}{testorder}} = ();  #创建新的profile，将删除testorder信息
        }
    }elsif($order eq 'destroyprofile'){
        if (exists $data{'name'}) {
            printf "%-10s%s\n","CreateProfile NAME :",$data{'name'};
            my $profile = $data{'name'};
            if (exists $ntx_data{$profile}) {
                my @streamlist = ntx_findstream($profile);
                ntx_stopstream($port,@streamlist);
                delete $ntx_data{$profile};
            }
        }
    }elsif($order eq 'createcustompkt'){
        if (exists $data{'pduname'}) { #HexString 是具体的报文内容
            printf "%-10s%s\n","CreateCustomPkt NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel3'} = 'pkt';
        }
    }elsif($order eq 'createethheader'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateEthHeader NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel2'} = 'eth';
        }
    }elsif($order eq 'createvlanheader'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateVlanHeader NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typevlan'} = 'vlan';
        }
    }elsif($order eq 'createipv4header'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateIPV4Header NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'TypeL3'} = 'ipv4';
        }
    }elsif($order eq 'createipv6header'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateIPV6Header NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel3'} = 'ipv6';
        }
    }elsif($order eq 'createudpheader'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateUDPHeader NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel4'} = 'udp';
        }
    }elsif($order eq 'createtcpheader'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateTCPHeader NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel4'} = 'tcp';
        }
    }elsif($order eq 'createicmppkt'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateICMPPkt NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel4'} = 'icmp';
            if (exists $ntx_data{$data{'pduname'}}{'type'}) {
                $ntx_data{$data{'pduname'}}{'icmptype'} = $ntx_data{$data{'pduname'}}{'type'};
            }
        }
    }elsif($order eq 'createstream'){
        #object 是port
        if (exists $data{'streamname'} && exists $data{profilename}) {
            my $stream = $data{'streamname'};
            printf "%-10s%s\n","CreateStream NAME :",$stream;
            if (exists $ntx_data{$stream}){ #如果stream已经存在， 就清除计数
                tcpdump_clearstatics($stream);
            }
            
            %{$ntx_data{$stream}} = %data;
        }
    }elsif($order eq 'configstream'){
        if (exists $data{'streamname'} && exists $ntx_data{$data{'streamname'}}) {
            my $stream = $data{'streamname'};
            printf "%-10s%s\n","CreateStream NAME :",$stream;
            foreach my $k(keys %data) {
                $ntx_data{$stream}{$k} = $data{$k}
            }
        }
    }elsif($order eq 'destroystream'){
        if (exists $data{'streamname'}) {
            printf "%-10s%s\n","CreateProfile NAME :",$data{'name'};
            my $stream = $data{'streamname'};
            if (exists $ntx_data{$stream}) {
                ntx_stopstream($port,$stream);
                delete $ntx_data{$stream};
            }
        }
    }elsif($order eq 'addpdu'){
        #stream name : testorder
        if (exists $data{'pduname'} && exists $data{object}) {
            my $stream  = $data{object};
            printf "%-10s%s\n","Stream NAME  :",$stream;
            printf "%-10s%s\n","AddPdu       :",$data{'pduname'};
            $ntx_data{$stream}{'addpdu'} = $data{'pduname'};        
        }       
    
    }elsif($order eq 'starttraffic'){
        my $port = $data{object};
        my $profile = undef
        my @streamlist = ();
        my $onlyport = 0;
        if (exists $data{streamnamelist}) { #streamnamelist = {stream11 stream12}
            my $info = $data{streamnamelist};
            if ($info =~ /{(.*)}/){
                $info = $1;
            }
            @streamlist = split(/\s+/,$info);
            @streamlist = grep{/\S/}@streamlist;
            if (scalar @streamlist > 0) {
            $profile = ntx_findprofile($streamlist[0]);
            }
        } elsif (exists $data{streamlist}) {
            push @streamlist,$data{streamlist};
            $profile = ntx_findprofile($data{streamlist});
        } elsif (exists $data{profilelist}) {
            $profile = $data{profilelist};
            @streamlist = ntx_findstream($profile);
        } else {
            @streamlist = ntx_findstreamByPort($port);
            $onlyport = 1;
        }
        
        printf "%-10s%s\n","OBJECT NAME  :",$port;
        printf "%-10s%s\n","Profile NAME :",$profile;
        printf "%-10s%s\n","ClearStatistic :",$data{clearstatistic};
        
         if(not exists $data{clearstatistic} || (exists $data{clearstatistic} && $data{clearstatistic} == 1)){
            if ($onlyport) {
                tcpdump_clearstatics("?ALL");
            } else {
                foreach my $stream(@streamlist){ 
                    tcpdump_clearstatics($stream);
                }
            }
            sleep 1;
         }

        ntx_startstream($port,@streamlist)
    }elsif($order eq 'stoptraffic'){
        my $port = $data{object};
        my $profile = undef
        my @streamlist = ();
        if (exists $data{streamnamelist}) { #streamnamelist = {stream11 stream12}
            my $info = $data{streamnamelist};
            if ($info =~ /{(.*)}/){
            $info = $1;
            }
            @streamlist = split(/\s+/,$info);
            @streamlist = grep{/\S/}@streamlist;
            if (scalar @streamlist > 0) {
                $profile = ntx_findprofile($streamlist[0]);
            }
        } elsif (exists $data{streamlist}) {
            push @streamlist,$data{streamlist};
            $profile = ntx_findprofile($data{streamlist});
        } elsif (exists $data{profilelist}) {
            $profile = $data{profilelist};
            @streamlist = ntx_findstream($profile);
        } else {
            @streamlist = ntx_findstreamByPort($port);
        }

        printf "%-10s%s\n","OBJECT NAME  :",$port;
        printf "%-10s%s\n","Profile NAME :",$profile;
        
        ntx_stopstream($port,@streamlist)
    }elsif($order eq 'createtestport'){
        if(exists $data{portname}) {
            $data{portname} =~ s/\:\://g;
            ntx_int_init(%data);
        }
    }elsif($order eq 'cleanuptest'){
        #无法删除线程，暂不清除port
        foreach my $port(keys %interface) {
            next if (not exists $interface{$port}{object});
            DPrint("Delete port $port obj $interface{$port}{object}");
            delete $interface{$port}{object};
        }
        print "Clean all -- Not support\n";
    }elsif($order eq 'resetsession'){
        if(exists $data{object}) {
            printf "%-10s%s\n","ResetSession  :", $data{object};
            DPrint("------ResetSession--before--");
            DPrint(\%ntx_data,\%interface);
            #my $str = `ps -ef | grep udpr`;
            #DPrint($str);
            DPrint("------ResetSession----------");
            ntx_stopstream();
            ntx_int_reset(%data);
            delete $ntx_data{$_} foreach(keys %ntx_data);
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
