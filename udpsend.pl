#!/usr/bin/perl -X
#udp client
use Socket; #����Socket��
use IO::Socket::INET; 
if (@ARGV < 2) {
    print "host port order args\n";
    print "\thost   server ip\n";
    print "\tport   server port\n";
    print "\torder  exec order(0 help)\n";
    print "\targs   exec arguments\n";
    exit(1);
}
my($host,$port,$order,@args) = @ARGV;
$order = 0 if (not defined $order);

my $get = 0;
if ($order >0 && $order%2 == 0) {
    $order -= 1;
    $get = 1;
}elsif($order == 0){
    $get = 1;
}
my $sock = IO::Socket::INET->new(
        PeerPort => $port,
        PeerAddr => $host,
        Proto => 'udp',
        Broadcast => 1,
        Timeout =>  3
    ) or die "Can't bind : $@\n";


$data = pack('n',$order);
$data .= join(" ",@args);
if ($get) {
    my $len = $sock->send($data,0); #���׽��ַ����ַ�������
    $sock->recv($buff,8000); #��������, MSG_DONTWAIT
    if (defined $buff && (length $buff > 0)) {
        print"$buff\n"; #�ѽ��պ�����ݴ���STDOUT
    }
} else {
	my $len = $sock->send($data,0);   #���׽��ַ����ַ�������
}
$sock->close();
exit 0; #�˳�����

