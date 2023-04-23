# the compiler: python
PYTHON = python3

#CFLAGS  = -g -Wall --std c++17 -Wextra -pedantic -Werror -g
# The build target 
TARGET = bt-monitor.py

venv:
	$(PYTHON) -m venv .venv
	
run: 
	$(PYTHON) $(TARGET) -t $(PCAP_FILE) -p $(MODE)

help:
	$(PYTHON) $(TARGET) -h