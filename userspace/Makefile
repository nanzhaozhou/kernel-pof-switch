pofswitch: pof_config.o pof_switch.o
	gcc pof_config.o pof_switch.o -o pofswitch

pof_config.o: pof_config.c 
	gcc -c pof_config.c -o pof_config.o

pof_switch.o: pof_switch.c 
	gcc -c pof_switch.c -o pof_switch.o

clean:
	rm -f *.o pofswitch


