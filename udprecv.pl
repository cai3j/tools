#!/usr/bin/perl -X
#udp server
use FindBin;
use lib $FindBin::Bin;
use MYTOOL qw/:all/;
use Net::Pcap;
use Socket; #导入Socket库
use Data::Dumper qw/Dumper/;

use threads ('yield',
     'stack_size' => 64*4096,
     'exit' => 'threads_only',
     'stringify');
use threads::shared;
use strict;
use IO::Handle;
autoflush STDOUT 1;
use Time::HiRes;
local $SIG{KILL}= sub{ exit;}; #当线程接收KILL的动作

#接口名 和 本地接口关系
my %interface;
#$interface{testorder_CHA1_PORT1}{INT} = "virbr1";             #host连接的接口
#$interface{testorder_CHA1_PORT1}{PID} = undef;  #抓包进程PID
#$interface{testorder_CHA1_PORT1}{BMAC} = '00:05:00:00:00:01'; #基mac
#my %killed;
#local $SIG{CHLD}= sub{  #进程退出
#    print $$."  ==".$?."===============\n";
    #my $pid = waitpid(-1,0);
    #print $pid."  =================\n";
#};
moduleinit(\@ARGV);

if (matchswitch('-h')) {
    print "  -h          show this help";
    print "  -firewall   use for firewall";
    print "  -cli        use cli";
    print "  -port:9090  Set server port";
    exit;
}
my $port = 9090;
if ((my @tmp = matchswitch('-port:')) > 0) {
    if ($tmp[0] =~ /-port:(\d+)/) {
        $port = $1;
    }
}

if (matchswitch('-cli')) {
    cli_init($port); #在后台运行会导致cpu利用率高
}

readloop($port);
exit 1; #退出程序

#**************************************************
# 循环报文处理
#**************************************************
sub readloop
{
    my $port = shift;
    #压入sockaddr_in模式，使用了全局本地压缩地址INADDR_ANY保留字
    my $localhost=sockaddr_in($port,INADDR_ANY);
    socket(SERVER,AF_INET,SOCK_DGRAM,17); #建立UDP套接字
    bind(SERVER,$localhost) or die "Can't bind port $port"; #绑定套接字
    
    print "Init OK (listen $port)\n";
    while(1){ #进入服务器循环体
        my $buff;
        my $client;
       #如果接收到数据就把数据压入$buff,保留远程地址在$client
        next unless $client = recv(SERVER,$buff,8000,0);
        #print "--------------------------\n";
        #printBlock(1,0,$buff);
        #print "--------------------------\n";
        sendip($client,$buff);
    
        #chop($buff); #减去$buff最后的输入符号
        #print "$buff\n"; #在$buff变量打入STDOUT
        #send(SERVER,"$buff\n",0,$client); #把$buff发送给客户端
    }
    close SERVER; #关闭套接字
}

sub cli_init
{
    my $port = shift;
    my $pid = fork();
    if ($pid != 0) {
        return $pid;
    }
    my $packhost=inet_aton('127.0.0.1');            #压缩主机地址
    my $address=sockaddr_in($port,$packhost); #压为sockaddr_in模式
    socket(CLI_CLIENT,AF_INET,SOCK_DGRAM,17);  #建立UDP套接字
    my $len = 0;
    while (1) {
        my $getdata =<STDIN>;
        chomp $getdata;
        if((!defined $getdata) || (length $getdata <= 0)){
            next;
        }
        $getdata = pack('n',0).$getdata;
        $len = send(CLI_CLIENT,$getdata,0,$address); 
    }
    return 0;
}
#**************************************************
# 解析报文指令，发送报文
#**************************************************
sub sendip
{
    my ($client,$pkt) = @_;
    our $longpkt;
    my $order = unpack('n',$pkt);  #前2位为命令字段
    $pkt = substr($pkt,2);
    #print "ORDER : $order\n"; #必需是奇数
    if(10 == $order){ #超长报文序列
        $longpkt->{$client} = $pkt;
        return 0;
    } else {
        if (exists $longpkt->{$client}){
            $pkt .= $longpkt->{$client};
            delete $longpkt->{$client};
        }
    }
    
    #print "ORDER : $order\n"; #必需是奇数
    if (1 == $order) {
        sim_simple($client,$pkt);
    }elsif(3 == $order){ #仿真NTX
        $pkt =~ s/^\s*{(.*)}\s*$/$1/;
        print "--------------------------\n";
        print "NTX : $pkt\n";
        print "--------------------------\n";
        $pkt = lc $pkt;
        sim_ntx($client,split(/\s+/,$pkt));
    }elsif(0 == $order){ #config
        config_exe($client,split(/\s+/,$pkt));
     }else{
        print "UNKNOW ORDER\n";
        return -1;
    }
    return 0;
}

sub config_exe
{
    my($client, $order, @arg) = @_;
    my $string = 'Unknow order!';
    our %ntx_data;
    #printf "%-10s : %s @arg\n","ORDER",$order;
    if ((not defined $order) || ($order eq 'help')) {
        $string  = "0      help\n".
                   "0      debug [on|off]\n".
                   "0      ntx|ntx-i|ntx-g\n".
                   "1|2    sim simple\n".
                   "3|4    sim ntx\n";
                   
        #print $string;
    } elsif ($order eq 'debug') {
        if (defined $arg[0]) {
            if ($arg[0] eq 'on') {
                setswitch('-d');
            } elsif ($arg[0] eq 'off') {
                clearswitch('-d');
            }
            $string = "Debug is $arg[0]!";
        }else{
            $string = "Nothing to do!";
        }
    } elsif ($order eq 'ntx-release') {
        foreach my $port (keys %interface){
            tcpdump_release($port);
            tcpdump_delport($port);
        }
        delete $ntx_data{$_} foreach(keys %ntx_data);
        $string = "OK";
    } elsif ($order eq 'ntx-i') {
        $string = Dumper(\%interface);
        foreach my $host(keys %{$ntx_data{CAP}}){
            if ($ntx_data{CAP}{$host}{PID} > 0) {
                my $pid = $ntx_data{CAP}{$host}{PID};
                my $w = $ntx_data{CAP}{$host}{PIPE}{W};
                my $r = $ntx_data{CAP}{$host}{PIPE}{R};
                if (0 == waitpid($pid,WNOHANG)){
                    print $w "STAT-G\n";
                    chomp(my $str = <$r>);
                    $str =~ s/\x1/\r/sg;
                    $str =~ s/\x2/\n/sg;
                    $string.=$str;
                }
                
            }
        }
    } elsif ($order eq 'ntx-g') {
        $string = Dumper(\%ntx_data);
    } elsif ($order eq 'ntx') {
        $string = "Show in server!";
        print "-----------ntx_data----------\n";
        print Dumper(\%ntx_data);
        print "------------interface--------\n";
        print Dumper(\%interface);
        print "-------------cap---------\n";
        foreach my $host(keys %{$ntx_data{CAP}}){
            if ($ntx_data{CAP}{$host}{PID} > 0) {
                my $w = $ntx_data{CAP}{$host}{PIPE}{W};
                print $w "STAT\n";
            }
        }
    } else {
        print "Unknow order!\n";
    }
    my $len = send(SERVER,$string,0,$client);
    DPrint("Send:($len)");
}
sub sim_simple
{
    my($client, $pkt, @arg) = @_;
    my($ret,$str) = (-1,'Work error!');
    #1 ,send dummy0 packet
    #3 ,get dummy0 mac:ip
    my ($order) = unpack('a2',$pkt);
    if ($order eq "00") {
        if ($pkt =~/00([^:]+):(.+)/s) {
            my $int = $1; #接口
            my $packet = $2;    #packet
            my $pcap = Net::Pcap::pcap_open_live($int, 1500, 1, 0, \$ret);
            if (defined $pcap) {
                $ret = Net::Pcap::pcap_sendpacket($pcap, $packet) ;
                Net::Pcap::pcap_close($pcap);
                ($ret,$str) = (0,'OK');
            } else {
                ($ret,$str) = (-1,'Interface error!');
            }            
        }
    }elsif($order == "03"){
        my $int = unpack("x2a*",$pkt); #接口
        my ($mac,$ip);
        chomp(my @info = `ifconfig -a $int`);
        if ($info[0] =~ /HWaddr\s+(\S+)/) {
            $mac = $1;
            $mac =~ s/://g;
        }
        if ($info[1] =~ /inet addr:([\d\.]+)/) {
            $ip = $1;
        }
        $ret = 0;
        $str = "INT:$int,MAC:$mac,IP:$ip";
        DPrint("Interface : $int  $str");
    }else{
        $str = sprintf "Unknow order \"%s\"",$order;
    }
    #ret id 0 OK ,info
    my $len = send(SERVER,pack("na*",$ret,$str),0,$client);
    printf "Work return : $ret, $str\n";
}

sub process_arp{
    my ($cookie, $header, $packet) = @_;
    my $pcap = $cookie->{pcap};
    my $data = $cookie->{data};
    #if (matchswitch('-d')) {
        #lock($cookie->{arpd});
        #print Dumper($cookie->{arpd});
        #printBlock(1,0,$packet);
    #}
    my $eth;
    eval{ #避免解异常报文导致退出
        $eth = pktEthdecode($packet);
        
        my $vlan = 0;
        $vlan = $eth->{vid} if(exists $eth->{vid});
        lock($cookie->{arpd});
        if (($eth->{type} == 0x0806)) {  #arp
            my $arp;
            ($arp->{head},$arp->{opcode},
                   $arp->{smac},$arp->{sip},$arp->{tmac},$arp->{tip})=
                    unpack("a6nH12a4H12a4",$eth->{data});
            my $ip = formatIp($arp->{tip});
            if (exists ${$cookie->{arpd}}{$ip.':'.$vlan} ) {
                if($eth->{dest} eq 'ffffffffffff') { #返回应答
                    my $ip = formatIp($arp->{tip});
                    print "-----------------------------------\n";
                    printf "%s -> %s (%d) %s\n", $eth->{src}, $eth->{dest},$arp->{opcode},$ip;
                    if (exists ${$cookie->{arpd}}{$ip.':'.$vlan} ) {
                        my $mac = ${$cookie->{arpd}}{$ip.':'.$vlan};
                        printf "Find a req %s %s\n",$ip,$mac;
                        $eth->{dest} = $eth->{src};
                        $eth->{src}  = $mac;
                        $eth->{data} = pack("a6nH12a4H12a4",$arp->{head},2,
                                $mac,$arp->{tip},$arp->{smac},$arp->{sip});
                        my $pkt = pktEthencode($eth);
                        Net::Pcap::pcap_sendpacket($pcap, $pkt) ;
                    }
                } else {
                    lock($cookie->{arp});
                    my $sip = formatIp($arp->{sip});
                    ${$cookie->{arp}}{$sip.':'.$vlan} = $arp->{smac};
                }
            }
        } elsif($eth->{type} == 0x0800){
            my $iptype = unpack("x9C",$eth->{data});
            DPrint("TYPE IP = $iptype");
            if ($iptype != 1) { # ICMP
                return;
            }
            my $icmpt = unpack("x20C",$eth->{data});
            DPrint("TYPE ICMP = $icmpt");
            if ($icmpt != 8 && $icmpt != 0) {
                return;
            }
            my ($ip,$icmp);
            ($ip->{h},$ip->{src_ip},$ip->{dest_ip},$ip->{data})
                    = unpack("a12a4a4a*",$eth->{data});
            my $tmp = formatIp($ip->{dest_ip});
            if (not exists ${$cookie->{arpd}}{$tmp.':'.$vlan} ) {
                return;
            }
            if($icmpt == 0) { #识别是否自己发出的请求
                ($icmp->{type},$icmp->{code},$icmp->{id},$icmp->{seq}) = 
                     unpack("aax2nn",$ip->{data});
                $tmp = formatIp($ip->{src_ip});
                $tmp = $tmp.':'.$vlan.':'.$icmp->{seq};
                #DPrint("CHECK $tmp");
                lock($cookie->{ping});
                if(exists ${$cookie->{ping}}{$tmp}) {
                    #DPrint("FIND REPLY");
                    ${$cookie->{ping}}{$tmp.'R'} = Time::HiRes::time;
                }
                return;
            }
            ($icmp->{type},$icmp->{code},$icmp->{data}) = 
                     unpack("aax2a*",$ip->{data});
            $icmp->{type} = 0;
            $ip->{data} = pktIcmpencode($icmp);
            $eth->{data} = pack "a12a4a4a*",$ip->{h},$ip->{dest_ip},
                        $ip->{src_ip},$ip->{data};
            $tmp = $eth->{dest};
            $eth->{dest} = $eth->{src};
            $eth->{src}  = $tmp;
            $tmp = pktEthencode($eth);
            Net::Pcap::pcap_sendpacket($pcap, $tmp) ;
        } elsif($eth->{type} == 0x86dd){
            my $iptype = unpack("x6C",$eth->{data});
            DPrint("TYPE IPV6 = $iptype");
            if ($iptype != 0x3a) { # ICMP
                return;
            }
            my $icmpt = unpack("x40C",$eth->{data});
            DPrint("TYPE ICMP6 = $icmpt");

            if ($icmpt != 0x87 && 0x80 != $icmpt) {
                return;
            }
            my ($ip,$icmp);
            ($ip->{l},$ip->{h},$ip->{src_ip},$ip->{dest_ip})
                    = unpack("Ca7a16a16",$eth->{data});
            ($icmp->{type},$icmp->{code},$icmp->{data}) = 
                     unpack("x40aax2a*",$eth->{data});
            if (0x80 == $icmpt) {  #rfc4443
                my $ipstr = formatIp($ip->{dest_ip});
                if (not exists ${$cookie->{arpd}}{$ipstr.':'.$vlan} ) {
                    return;
                }
                printf "Find echo req %s %s\n",$ipstr;
                $icmp->{type} = 129;
                my $tmp = $eth->{dest};
                $eth->{dest} = $eth->{src};
                $eth->{src}  = $tmp;
                $tmp = pack "Ca*a16a16",0x60,$ip->{h},
                                ,$ip->{dest_ip},$ip->{src_ip};
                $eth->{data} = $tmp.pktIcmpv6encode($icmp,$ip);
                $tmp = pktEthencode($eth);
                Net::Pcap::pcap_sendpacket($pcap, $tmp) ;
                return;
            }
            #rfc 4861    
            ($icmp->{ip},$icmp->{opttype},
             $icmp->{optlen},$icmp->{optmac}) = 
                     unpack("x4a16CCH12",$icmp->{data});
            my $ipstr = formatIp($icmp->{ip});
            if (exists ${$cookie->{arpd}}{$ipstr.':'.$vlan} ) {
                my $mac = ${$cookie->{arpd}}{$ipstr.':'.$vlan};
                printf "Find req %s %s\n",$ipstr,$mac;
                $eth->{dest} = $eth->{src};
                $eth->{src}  = $mac;
                $ip->{dest_ip} = $ip->{src_ip};
                $ip->{src_ip} = $icmp->{ip};
                my $pkt = pack "Ca*a16a16",0x60,$ip->{h},
                                ,$ip->{src_ip},$ip->{dest_ip};
                $icmp->{type} = 0x88;
                $icmp->{optmac} = $mac;
                $icmp->{data} = pack "H8a16CCH12","60000000",$icmp->{ip},
                                    2,1,$mac;
                $eth->{data} = $pkt.pktIcmpv6encode($icmp,$ip);
                $pkt = pktEthencode($eth);
                Net::Pcap::pcap_sendpacket($pcap, $pkt) ;
            }
        }
    };
    DPrint($@) if ($@);
    return;
}
sub tcpdump_caparp{
    my ($info) = @_;
    my ($ret,$err);
    my $pcap = $info->{pcap};

    my $flite = "arp or icmp or icmp6 or (vlan and (arp or icmp or icmp6))";
    DPrint("FLITE : $flite");
    $ret = Net::Pcap::pcap_compile($pcap, \$flite,$flite,0,0);
    DPrint("Set flite error") if ($ret < 0); 
    $ret = Net::Pcap::pcap_setfilter($pcap, $flite);
    my $num = 0;
    while (1) {
        $ret = Net::Pcap::pcap_loop($pcap, 0, \&process_arp, $info);
        ($ret < 0)?last:($num += $ret);
        #DPrint(sprintf("Int %s Cap $ret ($num) ",$info->{INT}));
    }
    Net::Pcap::pcap_close($pcap);
    printf "Tid %d is exit\n",threads->tid();
    sleep 5;
}

sub tcpdump_arpd{
    my ($port,$ip,$mac,$vlan) = @_;

    if (not exists $interface{$port}) {
        DPrint("Unknow interface \"$port\"");
        return;
    }
    if ( not defined $interface{$port}{PCAP}) {
        tcpdump_open($port);
    }
    my $thread = $interface{$port}{PID};
    if (not defined $thread) {
        my $info;
        my %arpd :shared;
        my %arp :shared;
        my %ping :shared;
        $interface{$port}{arpd}{num} = 0;
        $info->{pcap} = $interface{$port}{PCAP};
        $info->{arpd} = \%arpd;
        $info->{arp} = \%arp;
        $info->{ping} = \%ping;
        $interface{$port}{arpd} = \%arpd;
        $interface{$port}{arp} = \%arp;
        $interface{$port}{ping} = \%ping;
        $info->{INT}  = $port;
        $thread = threads->create(\&tcpdump_caparp,$info);
        $thread->detach();
        printf "Create arpd thread : %d (%s)\n",
                                     $thread->tid(),$port;
        $interface{$port}{PID} = $thread;
    }
    if (defined $ip && defined $mac) {
        lock($interface{$port}{arpd});
        $vlan = 0 if (not defined $vlan);
        $mac =~ s/[^0-9a-fA-F]//g;
        ${$interface{$port}{arpd}}{$ip.':'.$vlan} = $mac;
    }
    return;

}

sub process_packet{
    my ($cookie, $header, $packet) = @_;
    my $host = $cookie->{hostmac};
    if (matchswitch('-d')) {
        my %pdu = getPacketInfo($packet);
        printf "CAP %s:%s\n",
            $host,getPacketBrief(%pdu);
        #printBlock(1,0,$packet);
        #printPacketInfo(%pdu);        
    }
    eval{ #避免解异常报文导致退出
        if ($cookie->{type} eq 'packet') {
            my $num = ++${$cookie->{STAT}}->{"NUMBER"};
            if ($num > 100000) {  #最多只抓100000个包，避免内存溢出,可以停止后再开始
                DPrint("Capture too many!");
                return;
            }
            my $time = ','.$header->{tv_sec}.','.$header->{tv_usec};
            ${$cookie->{STAT}}->{"CAP$num"} = (sprintf "%*v02X",'',$packet).$time;
            #${$cookie->{STAT}}->{"CAPTIME$num"} = $header;
            #DPrint($header);
            printf "FIND ONE (%d)",$num;
            return;
        }
        my $eth = pktEthdecode($packet);
        #暂时过滤掉非ip报文
        if (0x0800 != $eth->{type} && 0x86dd != $eth->{type}) {
            return;
        }
        if ($eth->{src} eq $host) {
            ${$cookie->{STAT}}->{T}++;
            if ($packet =~/START(.+)END/s) {
                DPrint("SEND ONE : $1");
                ${$cookie->{STAT}}->{"$1.T"}++;
            }else{
                DPrint("SEND ONE");
            }
        } elsif($eth->{dest} eq $host) {
            ${$cookie->{STAT}}->{R}++;
            if ($packet =~/START(.+)END/s) {
                DPrint("RECV ONE : $1");
                ${$cookie->{STAT}}->{"$1.R"}++;
            } else {
                DPrint("RECV ONE");
            }
        }
        #if ($packet =~/START(.+)END/s) {
        #    ${$cookie->{STAT}}->{"$1.$eth->{src}.T"}++;
        #    ${$cookie->{STAT}}->{"$1.$eth->{dest}.R"}++;
        #}
    };
    DPrint($@) if ($@);
    return;
}
sub tcpdump_cappkt{
    my ($info) = @_;
    my ($ret,$err);
    my $pcap = Net::Pcap::pcap_open_live($info->{INT}, 1600, 1, 0, \$ret)
                or die "Can't open device  : $ret\n";
    printf "pcap_loop ($pcap): $info->{INT} $info->{host} \n";
    my $mac = $info->{hostmac};
    $mac =~ s/(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)/$1:$2:$3:$4:$5:$6/;
    my $flite = "ether host $mac";
    #$flite = "vlan $info->{vid} && $flite" if(exists $info->{vid});
    DPrint("FLITE : $flite");
    $ret = Net::Pcap::pcap_compile($pcap, \$err,$flite,0,0);
    if($ret < 0){
        DPrint("FLITE SET ERROR!!!!!!!!!!!!!!!!!!!!!");
        return 0 ;
    }
    $ret = Net::Pcap::pcap_setfilter($pcap, $err);
    my $num = 0;
    while ($num < 1000) {
        $ret = Net::Pcap::pcap_loop($pcap, 0, \&process_packet, $info);
        ($ret < 0)?last:($num += $ret);
        #DPrint(sprintf("Int %s Cap $ret ($num) ",$info->{INT}));
    }
    Net::Pcap::pcap_close($pcap);
    printf "Tid %d is exit\n",threads->tid();
    sleep 5;
}

sub tcpdump_open{
    my ($port) = @_;
    my $ret;
    print "open $port\n";
    if (not exists $interface{$port}) {
        DPrint("Can't find interface \"$port\"");
        return;
    }
    if (not defined $interface{$port}{PCAP}) {
        $interface{$port}{PCAP} =
            Net::Pcap::pcap_open_live($interface{$port}{INT}, 1500, 1, 0, \$ret)
                or die "Can't open device  : $ret\n";
    }
    return ;
}
sub tcpdump_close{
    my ($port) = @_;

    print "Close $port\n";
    if (not exists $interface{$port}) {
        DPrint("Can't find interface \"$port\"");
        return;
    }
    if (defined $interface{$port}{PCAP}) {
        my $pcap = $interface{$port}{PCAP};
        Net::Pcap::pcap_close($pcap);
    }
    print "Close $port OK\n";
    delete $interface{$port}{PCAP};
    return ;
}

sub tcpdump_send{
    my ($port,$packet,$num,$timeout) = @_;
    my $ret = -1;
    $timeout = 0 if (not defined $timeout);
    $num = 1 if (not defined $num || $num < 0);
    DPrint("Send port : $port ($num)");
    if (matchswitch('-d')) {
        printBlock(1,0,$packet);
    }
    if (not exists $interface{$port}) {
        return $ret;
    }
    if ( not defined $interface{$port}{PCAP}) {
        tcpdump_open($port);
    }
    
    foreach(1..$num){
        $ret = Net::Pcap::pcap_sendpacket($interface{$port}{PCAP}, $packet) ;
        Time::HiRes::sleep($timeout) if($timeout > 0);
    }
    
    return $ret;
}

sub tcpdump_clearstatics
{
    my $stream = shift;
    our %ntx_data;
    foreach my $host(keys %{$ntx_data{STA}}){
        if ($stream == "?ALL") {
            foreach my $i (keys %{$ntx_data{STA}{$host}{STAT}}){
                delete $ntx_data{STA}{$host}{STAT}->{$i}; 
            }
        }
        if (exists $ntx_data{STA}{$host}{STAT}->{"$stream.R"}){
            delete $ntx_data{STA}{$host}{STAT}->{"$stream.R"}
        }
        if (exists $ntx_data{STA}{$host}{STAT}->{"$stream.T"}){
            delete $ntx_data{STA}{$host}{STAT}->{"$stream.T"}
        }
    }
}
#为这个端口下所有host创建抓包， 以便分析是入向还是出向
sub tcpdump_creat{
    my ($portin) = @_;
    if (not exists $interface{$portin}) {
        DPrint("Unknow interface \"$portin\"");
        return;
    }
    DPrint("PORT $portin");
    our %ntx_data;
    tcpdump_release($portin);
    foreach my $host(keys %ntx_data){
        if (not exists $ntx_data{$host}{hostname}){
            next;
        }
        my $port = $ntx_data{$host}{object};  #host对应的接口
        if (($portin ne $port) &&
            ($portin ne $ntx_data{$port}{object})) {
            next;
        }
        $ntx_data{CAP}{$host}{STAT} = {R => 0};
        my $info;
        $info->{STAT} = \$ntx_data{CAP}{$host}{STAT};
        $info->{INT} = $interface{$portin}{INT};
        if (exists $ntx_data{$port}{VlanId}) {
            $info->{vid} = $ntx_data{$port}{VlanId};
        }
        $info->{hostname} = $host;
        if(exists $ntx_data{$host}{'Ipv6Addr'}){
            $info->{host} = $ntx_data{$host}{'Ipv6Addr'};
        } else {
            $info->{host} = $ntx_data{$host}{'Ipv4Addr'};
        }
        $info->{hostmac} = $ntx_data{$host}{'MacAddr'};
        $info->{hostmac} =~ s/[^\da-fA-F]//sg;
        #$info->{hostmac} = pack "H*",$info->{hostmac};    
        share($ntx_data{CAP}{$host}{STAT});
        #perl 5.8.8 rhel5 中当主线程用socket时，不能用asyn创建线程
        my $thread = threads->create(\&tcpdump_cappkt,$info);
        $thread->detach();
        printf "Create tcpdump thread : %d (%s- %s)\n",
                                 $thread->tid(),$info->{INT},$host;
        $thread->detach();
        $ntx_data{CAP}{$host}{PID} = $thread;
        printf "Create tcpdump  : %d ($host)\n",,$thread->tid();    
    }
}
sub tcpdump_cappkt2{
    my ($info) = @_;
    my ($ret,$err);
    my $pcap = Net::Pcap::pcap_open_live($info->{INT}, 1500, 1, 0, \$ret)
                or die "Can't open device  : $ret\n";
    printf "pcap_loop2 ($pcap): $info->{INT}\n";

    my $num = 0;
    while ($num < 1000) {
        $ret = Net::Pcap::pcap_loop($pcap, 0, \&process_packet, $info);
        ($ret < 0)?last:($num += $ret);
        #DPrint(sprintf("Int %s Cap $ret ($num) ",$info->{INT}));
    }
    Net::Pcap::pcap_close($pcap);
    printf "Tid2 %d is exit\n",threads->tid();
    sleep 5;
}

#为这个端口创建抓包引擎
sub tcpdump_start{
    my ($portin,$flite) = @_;
    if (not exists $interface{$portin}) {
        DPrint("Unknow interface \"$portin\"");
        return;
    }
    DPrint("PORT $portin");
    our %ntx_data;

    my $info;
    $info->{STAT} = \$ntx_data{CAP}{$portin}{STAT};
    $info->{INT} = $interface{$portin}{INT};
    $info->{type} = "packet";
    $info->{flite} = $flite;
    share($interface{$portin}{STAT});
    #perl 5.8.8 rhel5 中当主线程用socket时，不能用asyn创建线程
    my $thread = threads->create(\&tcpdump_cappkt2,$info);
    $thread->detach();
    printf "Create2 tcpdump thread : %d (%s)\n",
                             $thread->tid(),$info->{INT};
    $ntx_data{CAP}{$portin}{PID}     = $thread;
    printf "Create tcpdump  : %d ($portin)\n",$thread->tid();
    
    return;
}

sub tcpdump_stop{
    my ($port) = @_;
    our %ntx_data;
    DPrint("tcpdump_stop $port");
    if (not exists $ntx_data{CAP}{$port}) {
        return;
    }
    my $pid = $ntx_data{CAP}{$port}{PID};
    if ($pid <= 0) {
        return;
    }

    #采用线程时
    $ntx_data{CAP}{$port}{PID}->kill('KILL');
    delete $ntx_data{CAP}{$port}{PID};
    #处理结束

}
sub tcpdump_get{
    my ($port,$index) = @_;
    our %ntx_data;
    DPrint("tcpdump_stop $port $index");
    if (exists $ntx_data{CAP}{$port}{STAT}->{"CAP$index"}) {
        return $ntx_data{CAP}{$port}{STAT}->{"CAP$index"};
    }

    return undef;
}
#为所有接口释放抓包
sub tcpdump_release{
    my ($portin) = @_;
    our %ntx_data;
    DPrint("RELEASE CAP: $portin");
    #printStack();
    #释放所有抓包引擎
    foreach(keys %{$ntx_data{CAP}}){
        if (not exists $ntx_data{$_}{hostname}){
            next;
        }
        my $port = $ntx_data{$_}{object};  #host对应的接口
        if (($portin ne $port) &&
            ($portin ne $ntx_data{$port}{object})) {
            next;
        }
        DPrint("RELESE CAP : HOST $_");
        my $pid = $ntx_data{CAP}{$_}{PID};
        if ($ntx_data{CAP}{$_}{PID} > 0) {
            DPrint("RELEASE CAP PID: $pid");
            #采用线程时
            $ntx_data{CAP}{$_}{PID}->kill('KILL');
            delete $ntx_data{CAP}{$_}{PID};
            #处理结束
        }
    }
#释放所有统计引擎
    foreach(keys %{$ntx_data{STA}}){
        if (not exists $ntx_data{$_}{hostname}){
            next;
        }
        my $port = $ntx_data{$_}{object};  #host对应的接口
        if (($portin ne $port) &&
            ($portin ne $ntx_data{$port}{object})) {
            next;
        }
        DPrint("RELESE CAP : HOST $_");
        my $pid = $ntx_data{STA}{$_}{PID};
        if ($ntx_data{STA}{$_}{PID} > 0) {
            DPrint("RELEASE STA PID: $pid");
            #采用线程时
            $ntx_data{CAP}{$_}{PID}->kill('KILL');
            delete $ntx_data{CAP}{$_}{PID};
            #处理结束
        }
    }
}

#将所有接口抓包进行统计，计算总和
sub tcpdump_stat{
    my ($portin,$stream) = @_;
    my ($t,$r,$ts,$rs) = (0,0,0,0);
    our %ntx_data;
    print "Get port stat : $portin $stream\n";
    foreach my $host(keys %{$ntx_data{STA}}){
        if (defined $stream) {
            if (exists $ntx_data{STA}{$host}{STAT}->{"$stream.T"}) {
                $t += $ntx_data{STA}{$host}{STAT}->{"$stream.T"};
            }
            if (exists $ntx_data{STA}{$host}{STAT}->{"$stream.R"}) {
                $r += $ntx_data{STA}{$host}{STAT}->{"$stream.R"};
            }
        } else {
            $t += $ntx_data{STA}{$host}{STAT}->{T};
            $r += $ntx_data{STA}{$host}{STAT}->{R};
            foreach my $stream1 (keys(%{$ntx_data{STA}{$host}{STAT}})) {
                print "=== $stream1 ====\n";
                if ($stream1 =~ /\.T/) {
                    $ts += $ntx_data{STA}{$host}{STAT}->{$stream1};
                } elsif ($stream1 =~ /\.R/) {
                    $rs += $ntx_data{STA}{$host}{STAT}->{$stream1};
                }
            }
        }
        
    }
    return ($t,$r,$ts,$rs);
}
sub tcpdump_delport{
    my ($port) = @_;
    
    if (not exists $interface{$port}) {
        return
    }
    
    tcpdump_close($port);
    if (exists $interface{$port}{ARPD}{PID}) {
        my $pid = $interface{$port}{ARPD}{PID};
        if ($pid > 0) {
            DPrint("RELEASE CAP PID: $pid");
            #采用进程时
            kill 9,$pid;
            $pid = waitpid $pid,0;
            DPrint("PID $pid is over");
            
            close $interface{$port}{ARPD}{PIPE}{R};
            close $interface{$port}{ARPD}{PIPE}{W};
            $interface{$port}{ARPD}{PIPE}{R} = undef;
            $interface{$port}{ARPD}{PIPE}{W} = undef;
            $interface{$port}{ARPD}{PID} = undef;
            delete $interface{$port}{ARPD}{PIPE};
        }
        
        delete $interface{$port};
    }
}

#**************************************************
# NTX指令仿真处理
#**************************************************
sub sim_ntx
{
    my($client, $order, @arg) = @_;
    our %ntx_data;
    my %data = argfrase(@arg);
    printf "%-10s : %s\n","FRASE ORDER",$order;
    if(exists $data{object}){
        $data{object} =~ s/^\:\://;
    }
    while( my($k, $v) = each %data){
        print "\t$k = $v\n";
    }
    if($order eq 'helloserver'){
        my $string = 'hello client'; 
        my $len = send(SERVER,$string,0,$client);
        print "Send:$string($len)\n";
        
    }elsif ($order eq 'createhost' or $order eq 'createaccesshost') {
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
    }elsif ($order eq 'sendarprequest') {
        if (exists $data{object}) {
            my $object = $data{object};  #host
            printf "%-10s%s\n","OBJECT     NAME :",$object;
            if (exists $ntx_data{$object}) {
                my %host = ntx_gethostinfo($object);
                host_sendarp(\%host);
            }
        }
    }elsif ($order eq 'ping') {
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
    }elsif ($order eq 'createsubint') { #创建子VLAN接口
        if (exists $data{'subintname'}) {
            printf "%-10s%s\n","CreateSubInt NAME :",$data{'subintname'};
            %{$ntx_data{$data{'subintname'}}} = %data;
        }
    }elsif ($order eq 'configport') { #VLAN信息
        if (exists $data{object}) {
            my $object = $data{object};
            printf "%-10s%s\n","OBJECT NAME :",$object;
            delete $data{object};
            %{$ntx_data{$object}} = (%{$ntx_data{$object}},%data);
        }
    }elsif($order eq 'createstaengine'){ #创建统计引擎
        if (exists $data{'staenginename'}) {
            printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # PORT信息
            printf "%-10s%s\n","CreateProfile NAME :",$data{'staenginename'};
            printf "%-10s%s\n","StaType NAME :",$data{'statype'};
            %{$ntx_data{$data{'staenginename'}}} = %data;
            if ($data{statype} ne "analysis") {
                tcpdump_creat($data{object});
            }            
        }
    }elsif($order eq 'configcapturemode'){
        printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # engen
    }elsif($order eq 'startcapture'){
        printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # engen
        my $eng = $data{object};
        if (exists $ntx_data{$eng}) {
            if ($ntx_data{$eng}{statype} eq "analysis") {
                tcpdump_start($ntx_data{$eng}{object}); #在抓包引擎的接口上抓
            }
        }
    }elsif($order eq 'stopcapture'){
        printf "%-10s%s\n","OBJECT        NAME :",$data{object}; # engen
        my $eng = $data{object};
        if (exists $ntx_data{$eng}) {
            if ($ntx_data{$eng}{statype} eq "analysis") {
                tcpdump_stop($ntx_data{$eng}{object}); #在抓包引擎的接口上停止
            }    
        }
    }elsif($order eq 'getcapturepacket'){
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
    }else{
        print "UNKNOW ORDER  : $order\n";
    }
    
    return 0;
}

#创建CHASSIS1 的接口
#-portlocation 101/4 或 101/virbr1
#-portname ::CHASSIS1/1/4
#-porttype ETHERNET
#-object CHASSIS1
sub ntx_int_init {
    my (%int) = @_;
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
}
#重置 CHASSIS1
#-object CHASSIS1
sub ntx_int_reset {
    my (%int) = @_;
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
    }
}
#根据stream找profile
sub ntx_findprofile
{
    my $stream = shift;
    our %ntx_data;
    foreach(keys %ntx_data){
        if (exists $ntx_data{$_}{profilename} &&
            exists $ntx_data{$_}{streamname}) {
            if ($ntx_data{$_}{streamname} eq $stream) {
                return $ntx_data{$_}{profilename}
            }
        }
    }
    return undef;
}

#根据profile找到所属的stream
sub ntx_findstream
{
    my $profile = shift;
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
    return @stream;
}

#根据port找到所属的stream
sub ntx_findstreamByPort
{
    my $port = shift;
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
    return @stream;
}

sub ntx_startstream{
    my($port,@streamlist) = @_;
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
}

sub ntx_stopstream{
    my($port,@streamlist) = @_;
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
    }
}

sub ntx_gethostinfo
{
    my ($hostname) = @_;
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
    $host{port} = $port;
    return %host;
}


#获取stream的pdu信息
sub ntx_getpdu
{
    my $stream = shift;
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
    return %pdudata;
}

#**************************************************
# 转换NTX指令为内部指令
#**************************************************
sub ntx_getinfo
{
    my (%data) = @_;
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
    
    return %info; 
}
#学习ARP
sub host_sendarp
{
    my ($host,$destip) = @_;
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
}

#获取mac， 无目的ip，取网关mac
sub host_getmac
{
    my ($arplist,$host,$destip) = @_;
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
    return ${$arplist}{$destip.':'.$vid};
}

#ping 一个主机
#暂不支持一个host多个ping实例
sub host_ping
{
    my ($pinglist,$arplist,$host,$ping) = @_;
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
    return 1;
}

#获取ping的结果
#暂不支持一个host多个ping实例
sub host_pingresult{
    my ($host,$ping) = @_;
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
}

#**************************************************
# 大数的递增处理 11 22 33 44 + 00 01 00 20
#**************************************************
sub increment{
    my ($data,$num) = @_;
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
    return $data;
}

#**************************************************
# 获取下一个包的信息
#**************************************************
sub getInfoNext{
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
    }
    return 1;
}


#**************************************************
# 根据报文参数封装报文
#**************************************************
sub getpacket{
    my $info = shift;
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
    
    return $packet;
}

#**************************************************
# 参数解析 order -s1 1 -s2 2 -s3
#**************************************************
sub argfrase
{
    my @arg = @_;
    my %switch = ();
    my ($key,$info,$c);
    foreach(@arg){
        next if (/^\s*$/);         
        if (/^-(.+)/) {
            $key = $1;
            $switch{$key} = undef;
            $c = 0;
        }else{
            if (defined $key) {
                if (defined $switch{$key}) {
                    $switch{$key} .= ' '.$_;
                }else{
                    $switch{$key} = $_;
                }
                if (/^{/) {
                    $c = 1;
                }elsif(/}$/){
                    $c = 0;
                }
                if (not $c) {
                    $key = undef;
                }
            }
        }
    }
    return %switch;
}

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

sub pktEthdecode {
    my($pkt, $parent, @rest) = @_;
    my $self = {};

    # Class fields

    $self->{_parent} = $parent;
    $self->{_frame} = $pkt;

    # Decode ethernet packet

    if (defined($pkt)) {

        my($sm_lo, $sm_hi, $dm_lo, $dm_hi, $tcid);

        ($dm_hi, $dm_lo, $sm_hi, $sm_lo, $self->{type})
                    = unpack('NnNnn' ,$pkt);

        # Check for 802.1Q VLAN tag and unpack to account for 4-byte offset
        if ($self->{type} == 0x8100) {
            $self->{tpid} = 0x8100;

            ( $tcid, $self->{type}, $self->{data} ) = unpack('x14nna*' , $pkt);

            # Break down VLAN tag TCI into: PCP, CFI, VID
            $self->{pcp} = $tcid & 0xE000 >> 13;
            $self->{cfi} = $tcid & 0x1000 >> 12;
            $self->{vid} = $tcid & 0x0FFF;
        }
        else {
            $self->{data} = unpack('x14a*' , $pkt);
        }

        # Convert MAC addresses to hex string to avoid representation problems

        $self->{src} = sprintf "%08x%04x", $sm_hi, $sm_lo;
        $self->{dest} = sprintf "%08x%04x", $dm_hi, $dm_lo;
    }

    return $self;
}
sub pktEthencode
{
    my $self = shift;
    my($src,$dest);
    $src = $self->{src};
    $dest = $self->{dest};
    my $p = undef;
    $src =~ s/[^0-9a-fA-F]//g;
    $dest =~ s/[^0-9a-fA-F]//g;
    if (exists $self->{vid} && ($self->{vid} > 0)) {
        $self->{pcp} = 0 if(not exists $self->{pcp});
        $self->{cfi} = 0 if(not exists $self->{cfi});
        my $tcid = ($self->{pcp} <<13) + ($self->{cfi} <<12) + $self->{vid};
        $p = pack("H12H12nnna*",$dest,$src,0x8100,$tcid,
                   eval($self->{type}),$self->{data});
    } else {
        $p = pack("H12H12na*",$dest,$src,eval($self->{type}),$self->{data});
    }
    #printBlock(1,0,$p);
    return $p;
}

sub pktArpGencode
{
    my $self = shift;
    $self->{dest} =~ s/[^\da-fA-F]//g;
    $self->{ip} = gethostbyname($self->{ip});
    my $p = pack("H12H12","FFFFFFFFFFFF",$self->{dest});
    if (exists $self->{vid} && $self->{vid}>0){
        $p .= pack("nn", 0x8100,$self->{vid}) ;
    }
    $p .= pack("nnnCCnH12a4H12a4H*",
               0x0806,
               0x0001,  #eth
               0x0800,  #ipv4
               0x06,
               0x04,
               0x0001,  #opcode req
               $self->{dest},$self->{ip},
               "000000000000",$self->{ip},
               "000000000000000000000000000000000000"
               ); 
    return $p;
}

sub pktArpRequest
{
    my $self = shift;
    $self->{dest} =~ s/[^\da-fA-F]//g;
    $self->{srcip} = gethostbyname($self->{srcip});
    $self->{dstip} = gethostbyname($self->{dstip});
    my $p = pack("H12H12","FFFFFFFFFFFF",$self->{dest});
    if (exists $self->{vid} && $self->{vid} > 0) {
        $p .= pack("nn", 0x8100,$self->{vid});
    }
    $p .= pack("nnnCCnH12a4H12a4H*",
               0x0806,
               0x0001,  #eth
               0x0800,  #ipv4
               0x06,
               0x04,
               0x0001,  #opcode req
               $self->{dest},$self->{srcip},
               "000000000000",$self->{dstip}
               ); 
    return $p;
}

sub pktIpencode
{
    my $self = shift;
    my ($hdr,$packet,$zero,$tmp,$offset);
    my ($src_ip, $dest_ip);

    # create a zero variable
    $zero = 0;

    # adjust the length of the packet 
    $self->{len} = ($self->{hlen} * 4) + length($self->{data});

    $tmp = $self->{hlen} & 0x0f;
    $tmp = $tmp | (($self->{ver} << 4) & 0xf0);

    $offset = $self->{flags} << 13;
    $offset = $offset | (($self->{foffset} >> 3) & 0x1fff);

    # convert the src and dst ip
    $src_ip = gethostbyname($self->{src_ip});
    $dest_ip = gethostbyname($self->{dest_ip});

    # construct header to calculate the checksum
    $hdr = pack('CCnnnCCna4a4a*', $tmp, $self->{tos},$self->{len}, 
         $self->{id}, $offset, $self->{ttl}, $self->{proto}, 
         $zero, $src_ip, $dest_ip, $self->{options});

    $self->{cksum} = htons(in_cksum($hdr));

    # make the entire packet
    $packet = pack('CCnnnCCna4a4a*a*', $tmp, $self->{tos},$self->{len}, 
         $self->{id}, $offset, $self->{ttl}, $self->{proto}, 
         $self->{cksum}, $src_ip, $dest_ip, $self->{options},
         $self->{data});

    return($packet);
}

sub pktUdpchecksum {

    my( $self, $ip ) = @_;

    my $proto = 17;

    # Pack pseudo-header for udp checksum

    my $src_ip = gethostbyname($ip->{src_ip});
    my $dest_ip = gethostbyname($ip->{dest_ip});

    #no warnings;

    my $packet = pack 'a4a4CCnnnnna*' =>

      # fake ip header part
      $src_ip, $dest_ip, 0, $proto, $self->{len},

      # proper UDP part
      $self->{src_port}, $self->{dest_port}, $self->{len}, 0, $self->{data};

    $packet .= "\x00" if length($packet) % 2;

    $self->{cksum} = htons(in_cksum($packet)); 

}

sub pktUdpencode {

    my $self = shift;
    my ($ip) = @_;
    my ($packet);

    # Adjust the length accodingly
    $self->{len} = 8 + length($self->{data});

    # First of all, fix the checksum
    pktUdpchecksum($self,$ip);

    # Put the packet together
    $packet = pack("nnnna*", $self->{src_port},$self->{dest_port},
                $self->{len}, $self->{cksum}, $self->{data});

    return($packet); 
}

#
# TCP Checksum
#

sub pktTcpchecksum {

    my $self = shift;
    my ($ip) = @_;
    my ($packet,$zero,$tcplen,$tmp);
    my ($src_ip, $dest_ip,$proto,$count);

    $zero = 0;
    $proto = 6;
    $tcplen = ($self->{hlen} * 4)+ length($self->{data});

    no warnings qw/ uninitialized /;
    $tmp = $self->{hlen} << 12;
    $tmp = $tmp | (0x0f00 & ($self->{reserved} << 8));
    $tmp = $tmp | (0x00ff & $self->{flags});

    # Pack pseudo-header for tcp checksum

    $src_ip = gethostbyname($ip->{src_ip});
    $dest_ip = gethostbyname($ip->{dest_ip});

    $packet = pack('a4a4nnnnNNnnnna*a*',
            $src_ip,$dest_ip,$proto,$tcplen,
            $self->{src_port}, $self->{dest_port}, $self->{seqnum},
            $self->{acknum}, $tmp, $self->{winsize}, $zero,
            $self->{urg}, $self->{options},$self->{data});

    # pad packet if odd-sized
    $packet .= "\x00" if length( $packet ) % 2;

    $self->{cksum} = htons(in_cksum($packet));
}

sub pktTcpencode {

    my $self = shift;
    my ($ip) = @_;
    my ($packet,$tmp);

    # First of all, fix the checksum
    pktTcpchecksum($self,$ip);

    $tmp = $self->{hlen} << 12;
    $tmp = $tmp | (0x0f00 & ($self->{reserved} << 8));
    $tmp = $tmp | (0x00ff & $self->{flags});

    # Put the packet together
    $packet = pack('n n N N n n n n a* a*',
            $self->{src_port}, $self->{dest_port}, $self->{seqnum},
            $self->{acknum}, $tmp, $self->{winsize}, $self->{cksum},
            $self->{urg}, $self->{options},$self->{data});


    return($packet);

}

sub pktIpv6encode
{
    my $self = shift;
    my ($hdr,$packet,$zero,$tmp);
    my ($src_ip, $dest_ip);
    
    $self->{ver} = 6 if (not exists $self->{ver});
    $self->{len} = length $self->{data};
    $tmp = (($self->{ver} << 4) & 0xf0) ;

    # convert the src and dst ip
    $src_ip = formatIptoByte($self->{src_ip});
    $dest_ip = formatIptoByte($self->{dest_ip});
    # make the entire packet
    $packet = pack('CCnnCCa*a*a*', $tmp, 0,0,$self->{len},
         $self->{proto}, $self->{ttl},$src_ip, $dest_ip, 
         $self->{data});

    return($packet);
}

sub pktUdpv6checksum {

    my( $self, $ip ) = @_;

    my $proto = 17;

    # Pack pseudo-header for udp checksum

    my $src_ip = formatIptoByte($ip->{src_ip});
    my $dest_ip = formatIptoByte($ip->{dest_ip});

    #no warnings;

    my $packet = pack 'a16a16CCnnnnna*' =>

      # fake ip header part
      $src_ip, $dest_ip, 0, $proto, $self->{len},

      # proper UDP part
      $self->{src_port}, $self->{dest_port}, $self->{len}, 0, $self->{data};

    $packet .= "\x00" if length($packet) % 2;

    $self->{cksum} = htons(in_cksum($packet)); 

}

sub pktUdpv6encode {

    my $self = shift;
    my ($ip) = @_;
    my ($packet);

    # Adjust the length accodingly
    $self->{len} = 8 + length($self->{data});

    # First of all, fix the checksum
    pktUdpv6checksum($self,$ip);

    # Put the packet together
    $packet = pack("nnnna*", $self->{src_port},$self->{dest_port},
                $self->{len}, $self->{cksum}, $self->{data});

    return($packet); 
}

#
# TCP Checksum
#

sub pktTcpv6checksum {

    my $self = shift;
    my ($ip) = @_;
    my ($packet,$zero,$tcplen,$tmp);
    my ($src_ip, $dest_ip,$proto,$count);

    $zero = 0;
    $proto = 6;
    $tcplen = ($self->{hlen} * 4)+ length($self->{data});

    no warnings qw/ uninitialized /;
    $tmp = $self->{hlen} << 12;
    $tmp = $tmp | (0x0f00 & ($self->{reserved} << 8));
    $tmp = $tmp | (0x00ff & $self->{flags});

    # Pack pseudo-header for tcp checksum

    $src_ip = formatIptoByte($ip->{src_ip});
    $dest_ip = formatIptoByte($ip->{dest_ip});

    $packet = pack('a16a16nnnnNNnnnna*a*',
            $src_ip,$dest_ip,$proto,$tcplen,
            $self->{src_port}, $self->{dest_port}, $self->{seqnum},
            $self->{acknum}, $tmp, $self->{winsize}, $zero,
            $self->{urg}, $self->{options},$self->{data});

    # pad packet if odd-sized
    $packet .= "\x00" if length( $packet ) % 2;

    $self->{cksum} = htons(in_cksum($packet));
}

sub pktTcpv6encode {

    my $self = shift;
    my ($ip) = @_;
    my ($packet,$tmp);

    # First of all, fix the checksum
    pktTcpv6checksum($self,$ip);

    $tmp = $self->{hlen} << 12;
    $tmp = $tmp | (0x0f00 & ($self->{reserved} << 8));
    $tmp = $tmp | (0x00ff & $self->{flags});

    # Put the packet together
    $packet = pack('n n N N n n n n a* a*',
            $self->{src_port}, $self->{dest_port}, $self->{seqnum},
            $self->{acknum}, $tmp, $self->{winsize}, $self->{cksum},
            $self->{urg}, $self->{options},$self->{data});

    return($packet);

}

sub pktIcmpv6checksum {

    my( $self, $ip ) = @_;

    my $proto = 58;

    #no warnings;

    my $packet = pack 'a16a16nCCCCna*' =>

      # fake ip header part
      $ip->{src_ip}, $ip->{dest_ip}, 4 + length $self->{data},0, $proto,

      # proper UDP part
      $self->{type}, $self->{code}, 0, $self->{data};

    $packet .= "\x00" if length($packet) % 2;

    $self->{cksum} = htons(in_cksum($packet));

}

sub pktIcmpv6encode {
    my $self = shift;
    my ($ip) = @_;
    my ($packet);
    $self->{cksum} = 0;

    # Checksum the packet
    pktIcmpv6checksum($self,$ip);

    # Put the packet together
    $packet = pack("CCna*", $self->{type}, $self->{code}, 
                $self->{cksum}, $self->{data});

    return($packet); 
}

sub pktIcmpencode {
    my $self = shift;
    my ($ip) = @_;
    my ($packet);
    $self->{cksum} = 0;
    $packet = pack("CCna*", $self->{type}, $self->{code},
                $self->{cksum}, $self->{data});
    # Checksum the packet
    $self->{cksum} = htons(in_cksum($packet));    

    # Put the packet together
    $packet = pack("CCna*", $self->{type}, $self->{code}, 
                $self->{cksum}, $self->{data});

    return($packet); 
}


# Utility functions useful for all modules
#

# Calculate IP checksum

sub in_cksum {

    my ($packet) = @_;
    my ($plen, $short, $num,  $count, $chk);

    $plen = length($packet);
    $num = int($plen / 2);
    $chk = 0;
    $count = $plen;

    foreach $short (unpack("S$num", $packet)) {
        $chk += $short;
        $count = $count - 2;
    }

    if($count == 1) {
        $chk += unpack("C", substr($packet, $plen -1, 1));
    }

    # add the two halves together (CKSUM_CARRY -> libnet)
    $chk = ($chk >> 16) + ($chk & 0xffff);
    return(~(($chk >> 16) + $chk) & 0xffff);
}

# Network/host byte order conversion routines.  Network byte order is
# defined as being big-endian.

sub htons
{
    my ($in) = @_;

    return(unpack('n*', pack('S*', $in)));
}

sub htonl
{
    my ($in) = @_;

    return(unpack('N*', pack('L*', $in)));
}

sub ntohl
{
    my ($in) = @_;

    return(unpack('L*', pack('N*', $in)));
}

sub ntohs
{
    my ($in) = @_;

    return(unpack('S*', pack('n*', $in)));
}
