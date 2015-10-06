Transparent Proxy
=================

Simple class for concept usage and demonstration HTTP/HTTPS transparent proxy with allow / deny capabilities.

### Technical details and goals

 - allowed list by host and URL (only in HTTP connections);
 - epoll based;
 - using nonblocking sockets and async connect to remote upstream;
 - no external dependencies, using native std::regex;
 - root permissions not required;
 - simple to extend futures (such as default redirection if connections is disallowed);


Tested on 3.19 Linux kernel, GCC 4.9 and Clang 3.6 (other versions of kernel and compiler should work too).
Compile and run:


##### redirecting HTTP and HTTPS to out proxy port 8000
	iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8000
	iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8000

##### allowing forwarding (for DNS requests)
	echo "1" > /proc/sys/net/ipv4/ip_forward

##### compiling with g++ or clang++
	g++ main.cpp transparent_proxy.cpp util.cpp --std=c++1y -Wall -W -Wpedantic -o proxy

##### and running (prefered to run as non privileged user)
	./proxy


##### sample output:
	[2015-09-08 19:59:21:565]	HTTP
	[2015-09-08 19:59:21:566]	    host: code.jquery.com
	[2015-09-08 19:59:21:567]	    port: 80
	[2015-09-08 19:59:21:567]	     url: /jquery.min.js
	[2015-09-08 19:59:21:568]	allowed connection to 'code.jquery.com' by allowed URL pattern
	[2015-09-08 19:59:21:831]	addresses: 94.31.29.53 94.31.29.230 
	[2015-09-08 19:59:36:503]	HTTP
	[2015-09-08 19:59:36:503]	    host: google.com
	[2015-09-08 19:59:36:504]	    port: 80
	[2015-09-08 19:59:36:504]	     url: /
	[2015-09-08 19:59:36:504]	connection to 'google.com' disallowed
	[2015-09-08 19:59:39:971]	HTTP
	[2015-09-08 19:59:39:971]	    host: vk.com
	[2015-09-08 19:59:39:972]	    port: 80
	[2015-09-08 19:59:39:972]	     url: /
	[2015-09-08 19:59:39:972]	allowed connection to 'vk.com' by host pattern
	[2015-09-08 19:59:40:195]	addresses: 87.240.131.120 87.240.131.97 87.240.131.99 
	[2015-09-08 19:59:48:417]	HTTPS
	[2015-09-08 19:59:48:417]	    host: google.com
	[2015-09-08 19:59:48:417]	    port: 443
	[2015-09-08 19:59:48:417]	connection to 'google.com' disallowed

