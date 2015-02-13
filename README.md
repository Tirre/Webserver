# Webserver

Simple webserver in c, developed by Daniel Andréasson

The server implements HTTP1.0 Protocol which a few exceptions
GET and HEAD request-types are implemented, the other methods are not and will result in a "501 Not Implemented" error
The codes that are implemented are also limited and those are:
	- 200 OK
	- 400 Bad Request
	- 403 Forbidden
	- 404 Not Found
	- 500 Internal Server Error
	- 501 Not Implemented

The server could be started with a few flags, which are:
	-p <port> for explicit port number
	-d for run as daemon
	-l <filename> for logging to filename
	
The webserver uses chroot (because it was needed for the laboraiton I did it for), but can be removed in exchange for a www-user.
The server has some URL-validation, but commented in this version. Feel free to play around with it.
The solution for figuring out MIME-type of file is somewhat bad, right now it's a file that keeps the information of "file -i *" of that directory.

The server is supposed to be able to serve all kind of clients:
	- Internet Explorer (Windows only)
	- Mozilla Firefox (Windows & Linux)
	- Google Chrome (Windows & Linux)
	- Konqueror (Linux only)
	- Lynx (Linux only)
