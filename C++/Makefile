all: atomic_swap_host atomic_swap_client

CPPFLAGS=-I./ 

#Exclude the library directories
SOURCES := $(shell find . -name '*.cpp')
# Objs are all the sources, with .cpp replaced by .o
OBJS := $(SOURCES:.cpp=.o)

.PHONY: server clean


atomic_swap_host: host.o
	g++ -g $(CPPFLAGS) host.o ../target/debug/libasmr.a -lssl -lcrypto -lpthread -lstdc++ -Wl,--no-as-needed -ldl -o atomic_swap_host
	chmod 755 atomic_swap_host

atomic_swap_client: client.o
	g++ -g $(CPPFLAGS) client.o ../target/debug/libasmr.a -lssl -lcrypto -lpthread -lstdc++ -Wl,--no-as-needed -ldl -o atomic_swap_client
	chmod 755 atomic_swap_client

.cpp.o:
	g++ -o $@ $(CPPFLAGS) $(CFLAGS) -c $<

#ALL_DEPS := $(patsubst %.o,%.h,$(MAIN_OBS))
#-include $(ALL_DEPS)
	
clean:
	rm -rf *~ atomic_swap_host atomic_swap_client
	find ./ -name "*.o" | xargs -n 1 rm -f
	find ./ -name "*.d" | xargs -n 1 rm -f
	