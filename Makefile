CXX = g++
CXXFLAGS = -Wall -Wextra
LDFLAGS = -lssl -lcrypto

# Additional libs per target
OQS_LIBS = -loqs
CURL_LIBS = -lcurl

# Targets
all: gen_sig_keys server client

gen_sig_keys: gen_sig_keys.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(OQS_LIBS)

server: server.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(OQS_LIBS)

client: client.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(OQS_LIBS) $(CURL_LIBS)

clean:
	rm -f gen_sig_keys server client
