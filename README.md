# kernel-pof-switch
A Protocol Oblivious Forwarding (POF) Switch working in kernel space.

There is a widely used POF switch working in userspace, which is opensourced by http://www.poforwarding.org/. But caused by nature, it is very unefficient in packet fowarding, so I decide to reconstruct it, making it more efficient by working in kernel space.

1. HOW TO INSTALL
#make
#make install

2. HOW TO USE
#pofswitch --file ./userspace/pofswitch_config.conf
for more info, try
#pofswitch -h




