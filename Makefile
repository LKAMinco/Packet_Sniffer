TARGET = xhrabo15
OUTPUT = ipk-sniffer

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	g++ -g -Wall -o $(OUTPUT) $(TARGET).cpp -lpcap
clean:
	$(RM) $(OUTPUT)