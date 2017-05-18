package main

import (
	"flag"
	"fmt"
	"log"
	"sync"
	"os"
	"bufio"
	"time"
	"net"
	"refect"
	"strings"
	"regexp"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)

 struct InterfaceInfo{
 	intf string;
 	pid int;
 	mac string;
 };
 
 var intf map[string] InterfaceInfo;
 
var cli *bool = flag.Bool("cli", false, "Use cli.")
var port *int = flag.Bool("port", 9090, "Set server port.")
func main() {
	fmt.Printf("Init port %d.\n", *port)
	fmt.Println("-----------------------")
	if *cli {
	    go cli_init(*port);
	}
	readloop(*port);
	os.exit(0)
}




#**************************************************
# ѭ�����Ĵ���
#**************************************************
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
        sendip(socket, client,buff,len);
    
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

func sendip(socket *UDPConn, client net.UDPAddr, pkt []bype, len int)
{
	order := binary.BigEndian.Uint16(pkt[:1])
    pkt = string(pkt[2:len]);
    //print "ORDER : $order\n";

    //print "ORDER : $order\n";
    if (1 == order) {
        sim_simple(client,pkt);
    }elsif(3 == order){
        pkt = strings.TrimSpace(pkt)
        fmt.Println ("--------------------------");
        fmt.Println ( "NTX : ",pkt);
        fmt.Println ("--------------------------");
        pkt = strings.ToLower(pkt)
        spacecomp := regexp.Compile("\\s+")
        sim_ntx(socker, client,spacecomp.Split(pkt, 100));
    }elsif(0 == $order){ #config
        config_exe($client,split(/\s+/,$pkt));
     }else{
        print "UNKNOW ORDER\n";
        return -1;
    }
    return 0;
}
ntx_data = make(map[string] interface)
func sim_ntx(socket *UDPConn, client net.UDPAddr, order string , arg []string)
{
    our %ntx_data;
    my %data = argfrase(@arg);
    printf "%-10s : %s\n","FRASE ORDER",$order;
    if(exists $data{object}){
        $data{object} =~ s/^\:\://;
    }
    while( my($k, $v) = each %data){
        print "\t$k = $v\n";
    }
    if order == 'helloserver'{
        my $string = 'hello client'; 
        my $len = send(SERVER,$string,0,$client);
        print "Send:$string($len)\n";
        
    }else if (order == 'createhost' || order == 'createaccesshost') {
        #   port1Vlan1 CreateAccessHost -HostName Host1  -UpperLayer DualStack
        #   -Ipv6Addr 2013::1 -Ipv6Mask 64 \
        #   -Ipv6LinkLocalAddr fe80::1 -Ipv4Addr 192.0.1.11
        if (exists $data{'hostname'}) {
            my $port = $data{object};  #interface
            printf "%-10s%s\n","CreateHost NAME :",$data{'hostname'};
            %{$ntx_data{$data{'hostname'}}} = %data;
            my $vid = 0;
            if (exists $ntx_data{$port} &&
                exists $ntx_data{$port}{vlanid}) {
                $vid = $ntx_data{$port}{vlanid};
                $port = $ntx_data{$port}{object};
            }
            if (exists $data{ipv4addr}) {
                tcpdump_arpd($port,$data{ipv4addr},$data{macaddr},$vid);
            }
            if (exists $data{ipv6addr}) {
                tcpdump_arpd($port,$data{ipv6addr},$data{macaddr},$vid);
            }
        }
    }elsif (order == 'sendarprequest') {
        if (exists $data{object}) {
            my $object = $data{object};  #host
            printf "%-10s%s\n","OBJECT     NAME :",$object;
            if (exists $ntx_data{$object}) {
                my %host = ntx_gethostinfo($object);
                host_sendarp(\%host);
            }
        }
    }elsif ($order == 'ping') {
        if (exists $data{object}) { #host
            my $object = $data{object};  #host
            printf "%-10s%s\n","OBJECT     NAME :",$object;
            printf "%-10s%s\n","Host       NAME :",$data{host};
            my $str = "ERROR:ARG";
            if ((exists $data{host}) && 
                (exists $ntx_data{$object})) {
                my %host = ntx_gethostinfo($object);
                if(not exists $data{result}) {
                    $str = host_ping(\%host,\%data);
                    $str = "OK:$str";
                }else{
                    $str = host_pingresult(\%host,\%data);
                    $str = "OK:$str";
                }
            }
            my $len = send(SERVER,"$str",0,$client);
            print "Send:$str($len)\n";
        }
    }elsif ($order == 'createsubint') { #������VLAN�ӿ�
        if (exists $data{'subintname'}) {
            printf "%-10s%s\n","CreateSubInt NAME :",$data{'subintname'};
            %{$ntx_data{$data{'subintname'}}} = %data;
        }
    }elsif ($order == 'configport') { #VLAN��Ϣ
        if (exists $data{object}) {
            my $object = $data{object};
            printf "%-10s%s\n","OBJECT NAME :",$object;
            delete $data{object};
            %{$ntx_data{$object}} = (%{$ntx_data{$object}},%data);
        }
    }elsif($order == 'createstaengine'){ #����ͳ������
        if (exists $data{'staenginename'}) {
            printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # PORT��Ϣ
            printf "%-10s%s\n","CreateProfile NAME :",$data{'staenginename'};
            printf "%-10s%s\n","StaType NAME :",$data{'statype'};
            %{$ntx_data{$data{'staenginename'}}} = %data;
            if ($data{statype} ne "analysis") {
                tcpdump_creat($data{object});
            }            
        }
    }elsif($order == 'configcapturemode'){
        printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # engen
    }elsif($order == 'startcapture'){
        printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # engen
        my $eng = $data{object};
        if (exists $ntx_data{$eng}) {
            if ($ntx_data{$eng}{statype} == "analysis") {
                tcpdump_start($ntx_data{$eng}{object}); #��ץ������Ľӿ���ץ
            }
        }
    }elsif($order == 'stopcapture'){
        printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # engen
        my $eng = $data{object};
        if (exists $ntx_data{$eng}) {
            if ($ntx_data{$eng}{statype} == "analysis") {
                tcpdump_stop($ntx_data{$eng}{object}); #��ץ������Ľӿ���ֹͣ
            }    
        }
    }elsif($order == 'getcapturepacket'){
        if (exists $data{'packetindex'}) {
            printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # engen
            printf "%-10s%s\n","PacketIndex        :",$data{'packetindex'};
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
    }elsif($order == 'createfilter'){
        if (exists $data{'filtername'}) {
            printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # port
            printf "%-10s%s\n","filtername NAME :",$data{'filtername'};
            %{$ntx_data{$data{'trafficname'}}} = %data;
        }
    }elsif($order == 'configfilter'){
        if (exists $data{'filtername'}) {
            printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # port
            printf "%-10s%s\n","filtername NAME :",$data{'filtername'};
            %{$ntx_data{$data{'trafficname'}}} = %data;
        }
    }elsif($order == 'destoryfilter'){
        if (exists $data{'filtername'}) {
            printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # port
            printf "%-10s%s\n","filtername NAME :",$data{'filtername'};
            delete $ntx_data{$data{'trafficname'}};
        }
    }elsif($order == 'createtraffic'){
        if (exists $data{'trafficname'}) {
            printf "%-10s%s\n","CreateTraffic NAME :",$data{'trafficname'};
            %{$ntx_data{$data{'trafficname'}}} = %data;
        }
    }elsif($order == 'getportstats'){
        my $string = undef;
        my $staEngine = $data{object}; #��������
        my $port = $ntx_data{$staEngine}{object};
        my ($t,$r,$ts,$rs) = tcpdump_stat($port);
        $string = "GetPortStats TxFrames = $t , RxFrames = $r , rxsignature = $rs , txsignature = $ts";
        my $len = send(SERVER,$string,0,$client);
        print "Send:$string($len)\n";
    }elsif($order == 'getstreamstats'){
        my $string = undef;
        if (exists $data{'streamname'}) {
            my $staEngine = $data{object};        #��������
            my $streamname = $data{'streamname'}; #������
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
    }elsif($order == 'createprofile'){
        #Input: 1. args:�����б��ɰ������²���
        #  (1) -Name Name ��ѡ����,Profile������
        #  (2) -Type Type ��ѡ����,Constant Burst
        #  (3) -TrafficLoad StreamLoad ��ѡ���������������͵����ʣ��� -StreamLoad 1000
        #  (4) -TrafficLoadUnit TrafficLoadUnit ��ѡ���������������͵����ʵ�λ���� -TrafficLoadUnit fps
        #  (5) -BurstSize BurstSize, ��ѡ������Burst���������͵ı�������
        #  (6) -FrameNum FrameNum, ��ѡ������һ�η��ͱ��ĵ�����
        #  (7) -Blocking blocking, ����ģʽ��Enable/Disable
        #  (8) -DistributeMode DistributeMode
        if (exists $data{'name'}) {
            printf "%-10s%s\n","CreateProfile NAME :",$data{'name'};
            %{$ntx_data{$data{'name'}}} = %data;
            #%{$ntx_data{$data{'name'}}{testorder}} = ();  #�����µ�profile����ɾ��testorder��Ϣ
        }
    }elsif($order == 'destroyprofile'){
        if (exists $data{'name'}) {
            printf "%-10s%s\n","CreateProfile NAME :",$data{'name'};
            my $profile = $data{'name'};
            if (exists $ntx_data{$profile}) {
                my @streamlist = ntx_findstream($profile);
                ntx_stopstream($port,@streamlist);
                delete $ntx_data{$profile};
            }
        }
    }elsif($order == 'createcustompkt'){
        if (exists $data{'pduname'}) { #HexString �Ǿ���ı�������
            printf "%-10s%s\n","CreateCustomPkt NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel3'} = 'pkt';
        }
    }elsif($order == 'createethheader'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateEthHeader NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel2'} = 'eth';
        }
    }elsif($order == 'createvlanheader'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateVlanHeader NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typevlan'} = 'vlan';
        }
    }elsif($order == 'createipv4header'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateIPV4Header NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'TypeL3'} = 'ipv4';
        }
    }elsif($order == 'createipv6header'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateIPV6Header NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel3'} = 'ipv6';
        }
    }elsif($order == 'createudpheader'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateUDPHeader NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel4'} = 'udp';
        }
    }elsif($order == 'createtcpheader'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateTCPHeader NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel4'} = 'tcp';
        }
    }elsif($order == 'createicmppkt'){
        if (exists $data{'pduname'}) {
            printf "%-10s%s\n","CreateICMPPkt NAME :",$data{'pduname'};
            %{$ntx_data{$data{'pduname'}}} = %data;
            $ntx_data{$data{'pduname'}}{'typel4'} = 'icmp';
            if (exists $ntx_data{$data{'pduname'}}{'type'}) {
                $ntx_data{$data{'pduname'}}{'icmptype'} = $ntx_data{$data{'pduname'}}{'type'};
            }
        }
    }elsif($order == 'createstream'){
        #object ��port
        if (exists $data{'streamname'} && exists $data{profilename}) {
            my $stream = $data{'streamname'};
            printf "%-10s%s\n","CreateStream NAME :",$stream;
            if (exists $ntx_data{$stream}){ #���stream�Ѿ����ڣ� ���������
                tcpdump_clearstatics($stream);
            }
            
            %{$ntx_data{$stream}} = %data;
        }
    }elsif($order == 'configstream'){
        if (exists $data{'streamname'} && exists $ntx_data{$data{'streamname'}}) {
            my $stream = $data{'streamname'};
            printf "%-10s%s\n","CreateStream NAME :",$stream;
            foreach my $k(keys %data) {
                $ntx_data{$stream}{$k} = $data{$k}
            }
        }
    }elsif($order == 'destroystream'){
        if (exists $data{'streamname'}) {
            printf "%-10s%s\n","CreateProfile NAME :",$data{'name'};
            my $stream = $data{'streamname'};
            if (exists $ntx_data{$stream}) {
                ntx_stopstream($port,$stream);
                delete $ntx_data{$stream};
            }
        }
    }elsif($order == 'addpdu'){
        #stream name : testorder
        if (exists $data{'pduname'} && exists $data{object}) {
            my $stream  = $data{object};
            printf "%-10s%s\n","Stream NAME  :",$stream;
            printf "%-10s%s\n","AddPdu       :",$data{'pduname'};
            $ntx_data{$stream}{'addpdu'} = $data{'pduname'};        
        }       
    
    }elsif($order == 'starttraffic'){
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
    }elsif($order == 'stoptraffic'){
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
    }elsif($order == 'createtestport'){
        if(exists $data{portname}) {
            $data{portname} =~ s/\:\://g;
            ntx_int_init(%data);
        }
    }elsif($order == 'cleanuptest'){
        #�޷�ɾ���̣߳��ݲ����port
        foreach my $port(keys %interface) {
            next if (not exists $interface{$port}{object});
            DPrint("Delete port $port obj $interface{$port}{object}");
            delete $interface{$port}{object};
        }
        print "Clean all -- Not support\n";
    }elsif($order == 'resetsession'){
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
    }else{
        print "UNKNOW ORDER  : $order\n";
    }
    
    return 0;
}

