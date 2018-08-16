CC = g++
LDLIBS = -lnetfilter_queue
TARGET = netfilter_test 

SRC_DIR = src
INCLUDE_DIR = include
BINARY_DIR = bin

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.cpp, %.o, $(wildcard $(SRC_DIR)/*.cpp))
HEADERS = $(wildcard $(INCLUDE_DIR)/*.h)

$(TARGET): $(OBJECTS)
	@mkdir -p $(BINARY_DIR)
	@echo "[+] Make Binary File"
	@$(CC) $(LDLIBS) -o $(BINARY_DIR)/$@ $(OBJECTS)

%.o: %.cpp $(HEADERS)
	@echo "[+] Compile $< File"
	@$(CC) $(LDLIBS) -c -o $@ $< -I$(INCLUDE_DIR)

clean:
	@rm -f $(BINARY_DIR)/$(TARGET)
	@rm -f $(SRC_DIR)/*.o

