echo TEST1 
echo
echo Website1:
echo 
python3 measure-webserver.py pcap1.pcap 93.184.216.34 80
echo
echo TEST2
echo
echo Website1
echo
python3 measure-webserver.py pcap2.pcap 93.184.216.34 80
echo
echo Website2
echo
python3 measure-webserver.py pcap2.pcap 17.253.144.10 80
echo
echo TEST3
echo
echo Website1
echo
python3 measure-webserver.py pcap3.pcap 188.184.100.182 80
echo
echo Website2
echo
python3 measure-webserver.py pcap3.pcap 34.223.124.45 80
