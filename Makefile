TARGET = pcap
SRCS =$(shell ls *.cpp)
OBJS = $(SRCS:.cpp=.o)
CC = g++
LIBS = -lpcap -ansi -pedantic

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

.cpp.o:
	$(CC) -c $<

clean:
	rm -f $(TARGET) $(OBJS)
