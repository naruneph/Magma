magma: magma.cpp
	g++ -Wall -std=c++11 -o magma magma.cpp
clean:
	rm -rf magma *.o
