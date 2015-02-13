/*
Webserver in c, developed by Daniel Andréasson

The server implements HTTP1.0 Protocol which a few exceptions
GET and HEAD request-types are implemented, the other types are not and will result in a "501 Not Implemented" error
The codes that are implemented are also limited and those are:
	- 200 OK
	- 400 Bad Request
	- 403 Forbidden
	- 404 Not Found
	- 500 Internal Server Error
	- 501 Not Implemented

The server should be able to log via syslog or be able to log to a file if flag is set (CLF is used)
The server should be able to start with a few flags:
	-p for port number
	-d for run as daemon
	-l log to logfile

The server should NOT create any zombie processes
The webserver should use some sort of chroot to make access of private files harder (make /var/www as root for example)
The server should implement some sort of protection against hacking or DoS-attacks. (URL validation)

ALL HTML formatted output from the server should follow the HTML4.0 specification.
The server is supposed to be able to serve all kind of clients:
	- Internet Explorer (Windows only)
	- Mozilla Firefox (Windows & Linux)
	- Google Chrome (Windows & Linux)
	- Konqueror (Linux only)
	- Lynx (Linux only)

Useful tools:
	- sendfile() is a Linux system call to send a file to a socket
	- tcpdump is a network sniffer without GUI
	- Ethereal is a GUI network protocol analyser
	- Hammerhead is A web testing tool, installed in the security lab
	- netcat is a networking utility which reads and writes data across network connections, using the TCP/IP protocol
	- wget is a Linux-utility for non-interactive download of files from the Web

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <err.h>
#include <pthread.h>
#include <strings.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <assert.h>
#include <signal.h>
#include <syslog.h>
#include <ctype.h>

//Variables for the config and flags, doing them global so I don't need to send them around
int port;
char *path = NULL;
int dFlag = 0;
char *logFile = NULL;

//Self-defined struct to be able to send 2 arguments to void *requestHandler (thread-function)
struct arg_struct {
	int arg1;
	struct sockaddr_in arg2;
}args;

//Function to send messages on socket, so I don't have to do the messages to a char and see how long they are and shit
void send_On_Socket(int sock_descriptor, char *msg){
	int len = strlen(msg);
	if (send(sock_descriptor, msg, len, 0) == -1){
		printf("Error in send... Tried to send: '%s'\n", msg);
	}
}

//Function to read from config-file
void readConfig(){
	int n=0;
	char line[50];
	char *holder = (char *)malloc(sizeof(char) * 50);
	FILE *fd;

	fd = fopen (".lab3-config", "r");
	if(fd == NULL){
		printf("ERROR in readConfig(): Could Not Read %s\nNow Exiting...\n", ".lab3-config");
		exit(-1);
	} else {
		// Reads lines from config-file
		// Hardcoded to when n=0 set path to that line and when not set port to that line
		while(fgets(line, 50, fd) != NULL){
			if( n==0 ){			
				//path = line;				
				snprintf(holder, 50, "%s", line);
			} else if( n==1 ){
				port = atoi(line);
			}
			n++;
		}
	}
	fclose(fd);

	int len = strlen(holder);
	holder[ (len - 1) ] = '\0';
	path = holder;
}

//Function to make server detach from terminals, aka making it a daemon
void daemonize(){
	pid_t pid;
	int fd0, fd1, fd2;

	umask(0);

	pid = fork();
	if(pid != 0){
		exit(0);
	}
	setsid();

	pid = fork();
	if(pid != 0){
		exit(0);
	}
	
	fd0 = open("/dev/null", "rw");
	fd1 = dup(0);
	fd2 = dup(0);
}

//Function to see if file exists
int file_exist (char *filename){
	//Code to check if file exists, returns true if it exists, false if it doesn't (0 / 1)
	struct stat buffer;
	int result = stat(filename, &buffer);	
	return result == 0;
}

//Function to clean up the .pid-file if the process receives and SIGTERM-signal
void termination_handler(){
	printf("\nReceived SIGINT/SIGTERM signal, cleaning up .pid and exiting...\n");
	//Need to remove chroot somehow, or mount /var/run and make it a bad resource to request?
	if(unlink("/var/run/myWebserver.pid") == -1){
		printf("Failed to remove /var/run/myWebserver.pid\n");
	}
	exit(-1);
	//Maybe something else to do, but from what I know the operative system cleans up allocated memory and open file descriptors that aren't shared with other processes.
}

//Thread to sit and wait for a SIGTERM/SIGINT signal
void *waitForSignal(){
	while(1){
		signal(SIGINT, termination_handler);
		signal(SIGTERM, termination_handler);
	}
}

//Function to determine if process is running already, otherwise create the pid for it
void check_if_running(){
	int result = (file_exist("/var/run/myWebserver.pid"));
	if( result == 1){
		printf("/var/run/myWebserver.pid already exists.\nIs the server already running?\n\n");
		exit(-1);
	} else {
		FILE *fd;
		char print[5];
		snprintf(print, sizeof(print), "%d\n", getpid()); 
		fd = fopen("/var/run/myWebserver.pid", "w");
		fwrite(print, 1, sizeof(print), fd);
		fclose(fd);
	}
}

//Function to log the request properly
void CommonLogFormat(char *ip, char *request, char *resource, int Status_Code, int Bytes_Sent, char *comment, char *tidBuf){
	//Make a new string that we will put in the line that the Log will store
	char newLine[1024];
	bzero(&newLine, sizeof(newLine));
	//Formatting the string as I want it, aka in CLF (Common Logfile Format)
	//The second %s is supposed to be if some user does the request, but it's only used when authorizing which I haven't implemented, therefore it's static "-"
	snprintf(newLine, sizeof(newLine), "%s - %s [%s] %d %d Resource:%s", ip, "-", tidBuf, Status_Code, Bytes_Sent, resource);

	//Run syslog or log to file depending if char *logFile is null or has a value (if you choose anything through arguments)
	if(logFile == NULL){
		openlog("MyWebserver", LOG_PID, LOG_DAEMON);
		syslog(LOG_NOTICE, "%s\n", newLine);
		closelog();
	} else {
		FILE *fd=fopen(logFile, "a");
		if (fd == NULL){
			printf("ERROR in CommonLogFormat(%s, %s, %s, %d, %d, %s): Could Not Open file %s!\n", ip, request, resource, Status_Code, Bytes_Sent, comment, logFile);
		}
		//"Print" the line into the file
		fprintf(fd, "%s\n", newLine);
		//Close the file descriptor
		fclose(fd);
	}
}


void *handleRequest(){
	//Setting the local variables for this function (thread)
	//Doing a new variable called thread_fd for arg1 since it's used alot in this function (thread) while arg2 will just be passed to another function.
	
	struct arg_struct threadArgs = args;
	int thread_fd=threadArgs.arg1;

	//printf("Local args are: %d (socket descriptor) and %s (IP-address of connecting socket) \n", threadArgs.arg1, inet_ntoa(threadArgs.arg2.sin_addr));
	//printf("Public args are: %d (socket descriptor) and %s (IP-address of connecting socket) \n", args.arg1, inet_ntoa(args.arg2.sin_addr));

	//Create a string to store the request and try to read from socket
	int n;
	char message[1024];
	bzero(&message, sizeof(message));
	n = read(thread_fd, message, sizeof(message));
	if (n < 0){
		printf("ERROR in handleRequest(): Could Not Read From Socket");
    	}
	
	//Setting up variables for browser_request splitting
	char *filename;
	char *partial;
	char *search=" ";
	char *request;	
	char absolute_Path[100];

	//Split the browser_request
	partial = strtok(message, search);
	request = partial;
	int i=0;
	while ( partial != NULL){
		//printf("%d %s\n", i, partial);
		if(partial[0]=='/'){
			//Special-case for if "/" is requested, "redirect" them to index.html, the "Startpage"
			if(strlen(partial) == 1){
				partial = "/index.html";			
			}
			//Move pointer one forward so I skip the /, doesn't matter anyways since /Filename and Filename is the same since we're in root directory
			//partial++;
			//memmove(partial, token+1, strlen(token));
			filename=partial;
			//printf("Filename = %s\n", filename);
		}
		partial = strtok(NULL, search);
		i++;
	}
/*
	int badURL = 0;
	i = strlen(filename);
	if(strstr(filename, "/etc/passwd")){
			badURL = -1;
	} else if(strstr(filename, "/forbidden")){
			badURL = -1;
	} else if( i>50 ){
			badURL = -1;
	}
*/
	char *result;
	result = realpath(filename, absolute_Path);
	if( !result ) {
		printf("ERROR in realpath()");
	}

	printf("#4\n");
	int Status_Code;
	char Response[50];
	//Check if file exists and set Status_Code to appropriate
	//Request-types that are implemented are "GET" and "HEAD"
	if((strstr(request, "GET") || strstr(request, "HEAD"))){
		if(file_exist(filename)){
			Status_Code = 200;
			snprintf(Response, sizeof(Response), "%s", "OK");
		}else {
			Status_Code = 404;
			snprintf(Response, sizeof(Response), "%s", "Not Found");
			filename = "error/not_found.html";
		}
	//Check if the request was any of the non-implemented and return code "501 Not Implemented" if so, and otherwise "400 Bad Request"
	} else if(strstr(request, "POST") || strstr(request, "PUT") || strstr(request, "DELETE") || strstr(request, "TRACE") 
					|| strstr(request, "OPTIONS") || strstr(request, "CONNECT") || strstr(request, "PATCH")){
		Status_Code = 501;
		snprintf(Response, sizeof(Response), "Not implemented: %s", request);
		filename = "error/not_implemented.html";
	} else {
		Status_Code = 400;
		snprintf(Response, sizeof(Response), "Bad request");
		filename = "error/bad_request.html";
	}
	
	//Something else to show "Internal Server Error"

	//Maka a struct that can store properties of file
	struct stat st;

	//If Status_Code is 200 the file exists (and is readable), then set Bytes_Sent to size of file
	//Otherwise set Bytes_Sent to 0
	int Bytes_Sent;
	if(Status_Code == 200){
		stat(filename, &st);
		Bytes_Sent = (int)st.st_size;
	} else {
		Bytes_Sent = 0;
	}
	
	//Find out content-type of file
	char line[100];
	FILE *fd;

	fd = fopen("MIME", "r");
	if(fd == NULL){
		printf("ERROR in handleRequest(), Could Not Read File %s", "MIME");
	} else {
		while(fgets(line, 100, fd) != NULL){
			if( strstr(line, filename) ){
				break;
			}
		}
	}

	char *Content_Type;
	char *Charset;

	char *Split;
	Split = strtok(line, " ");
	int k=0;
	while ( Split != NULL){
		//printf("%d %s\n", k, Split);
		if(k==1){
			Content_Type=Split;
		} else if(k==2){
			Charset=Split;
		}
		Split = strtok(NULL, " ");
		k++;
	}
	Content_Type[strlen(Content_Type)-1]='\0';
	setenv("TZ", "GMT-2", 1);
	tzset();
	time_t tid;
	struct tm * timeinfo;
	time(&tid);
	timeinfo = localtime(&tid);	
	char tidBuf[100];
	char logBuf[100];
	//Format the time_struct to how HTTP/1.0 wants it	
	strftime(tidBuf, sizeof(tidBuf), "%a, %d %h %y %X %Z", timeinfo);
	strftime(logBuf, sizeof(logBuf), "%e/%h/%g:%X %z", timeinfo);
	
	//CommonLogFormat() logs the request; Arguments to provide: (Connecting IP, Request type, Requested Resource, Status Code, Bytes Sent, Comment To Status Code)
	//Maybe run this as a thread? So it doesn't block the request being handled
	CommonLogFormat( inet_ntoa(threadArgs.arg2.sin_addr), request, absolute_Path, Status_Code, Bytes_Sent, Response, logBuf);

	char responseHeader[1024];
	//Fill responseHeader with the HTML response header material, depending on Status_Code and Response (for example 200 OK or 501 Not Implemented)
	bzero(&responseHeader, sizeof(responseHeader));
	//Implement a solution with "file" command with flag -i set. Field 2 and 3 are the content-type and charset variable for the file
	snprintf(responseHeader, sizeof(responseHeader), "HTTP/1.0 %d %s\r\nDate: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConection: Keep-Alive\r\n\n", Status_Code, Response, tidBuf, Content_Type, Bytes_Sent);
	send_On_Socket( thread_fd, responseHeader);

	//Open a file and read through it and use send_On_Socket for each fread
	/* 	
	if ( strstr(request, "GET")) {
		int fs;
		fs = open(filename, "r");
		
		size_t bytes_sent;
		off_t offset = 0;

		if((bytes_sent = sendfile(thread_fd, fs, &offset, Bytes_Sent)) != Bytes_Sent){
			printf("Incomplete transfer");
		}
		close(fs);
	}
	*/

	if ( strstr(request, "GET") ) {
			FILE *fs;
		if( strstr(Charset, "bin") ){
			fs = fopen(filename, "rb");
			if(fs == NULL){
				//Maybe send an error to syslog instead of print?
				printf("ERROR in handleRequest(): File '%s' Not Found.\n", filename);
			} else {
				char sdbuf[8196];
				bzero(&sdbuf, sizeof(sdbuf));
				int bytes = 0;
				fseek(fs, 0, SEEK_END);
				rewind(fs);
				int line;
				while(bytes < Bytes_Sent){
					line = fread(sdbuf, 1, sizeof(sdbuf), fs);
					bytes += line;
					write(thread_fd, sdbuf, line);					
					//send_On_Socket(thread_fd, sdbuf);
					bzero(&sdbuf, sizeof(sdbuf));
				}
			}
		} else {
			fs = fopen(filename, "r");
			if(fs == NULL){
				//Maybe send an error to syslog instead of print?
				printf("ERROR in handleRequest(): File '%s' Not Found.\n", filename);
			} else {
				char sdbuf[8196];
				bzero(&sdbuf, sizeof(sdbuf));
				int bytes = 0;
				fseek(fs, 0, SEEK_END);
				rewind(fs);
				int line;
				while(bytes < Bytes_Sent){
					line = fread(sdbuf, 1, sizeof(sdbuf), fs);
					bytes += line;
					write(thread_fd, sdbuf, line);					
					//send_On_Socket(thread_fd, sdbuf);
					bzero(&sdbuf, sizeof(sdbuf));
				}
			}
		}
		fclose(fs);
	}
	close(thread_fd);
}

int main(int argc, char **argv){
	//Create a thread that waits for SIGINT or SIGTERM to remove the .pid file
	pthread_t signalThread;
	pthread_create(&signalThread, NULL, *waitForSignal, NULL);
	pthread_detach(signalThread);

	//Declaring variables used for the server-part, the socket and the sockadrr structs for accepting sockets and storing IP and such	
	int one = 1;
	int client_fd;
	int n;
	struct sockaddr_in svr_addr, cli_addr;
	socklen_t sin_len = sizeof(cli_addr);
	int c;
	opterr = 0;

	//Reading config before flags because port is supposed to be able to be overwritten
	readConfig();

	printf("#1\n");
	while ((c = getopt (argc, argv, "p:l:d")) != -1){
		switch(c){
			case 'd':
				dFlag = 1;
				break;
			case 'l':
				logFile = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case '?':
				if (optopt == 'c'){
					printf("Option -%c requires and argument.\n", optopt);
				} else if (isprint (optopt)){
					printf("Unknown option -%c\n", optopt);
				} else {
					printf("Unknown option character %x+n", optopt);
				}
			return 1;
			default:
				exit(-1);
		}
	}

	printf("#2\n");
	if(dFlag == 1){
		daemonize();
	}	
	check_if_running();	
	printf("#3\n");

	//Set working_directory since path has been struggling
	/*	
	char working_directory[]="/home/seclab/Webserver_DropBox/Folder";
	printf("path = '%s', strlen = %d\r\n", path, strlen(path));
	printf("working_directory = '%s', strlen = %d\r\n", working_directory, strlen(working_directory));
	if( strcmp(path, working_directory)==0 ){
		printf("Identical strings: path working_directory");
	} else{
		printf("Not identical strings: path working_driectory");
	}
	*/
	
	if( chroot("./Folder") == 0 ){
		chdir("/");
	} else {
		printf("ERROR in main(): Chroot Failed\nAre You Root?\n");
		exit(-1);
	}
	//If -d flag is set, run daemonize-function to detach from a terminal


	//Creating socket and checking if it fails, if it does the server can't work and exits
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0){
		printf("ERROR in main(): Can Not Open Socket\nNow Exiting...\n");
		exit(-1);
 	}
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));

	//Setting up socket properties
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = INADDR_ANY;
	svr_addr.sin_port = htons(port);
 
	//Binding socket and checking if it fails, if it does the server can't work and exits
	if (bind(sock, (struct sockaddr *) &svr_addr, sizeof(svr_addr)) == -1) {
		close(sock);
		printf("ERROR in main(): Can Not Bind Socket to Port %d\nIs the process already running?\nNow Exiting...\n", port);
		exit(-1);
  	}

	//Listening for connections
	//Infinite-loop to accept each connection and send away a thread to handle each request
	listen(sock, 128);
	while ( 1 ) { //while (true)
		client_fd = accept(sock, (struct sockaddr *) &cli_addr, &sin_len);

		//printf("Connection from %s:%d...\n", inet_ntoa(cli_addr.sin_addr), (int)ntohs(cli_addr.sin_port));
		if (client_fd == -1) {
      			printf("ERROR in main(): Can Not Accept\n");
      			continue;
    		}
		args.arg1 = client_fd;
		args.arg2 = cli_addr;
		pthread_t thread;
		pthread_create(&thread, NULL, *handleRequest, NULL);
		pthread_detach(thread);
		//phtread_join(thread, NULL);
  	}
}
