# Webserver

Simple webserver in c, developed by Daniel Andréasson

The server implements HTTP1.0 Protocol which a few exceptions
GET and HEAD request-types are implemented, the other methods are not and will result in a "501 Not Implemented" error
The codes that are implemented are also limited and those are:<br>
	- 200 OK<br>
	- 400 Bad Request<br>
	- 403 Forbidden<br>
	- 404 Not Found<br>
	- 500 Internal Server Error<br>
	- 501 Not Implemented<br>

The server could be started with a few flags, which are:<br>
	-p <port> for explicit port number<br>
	-d for run as daemon<br>
	-l <filename> for logging to filename<br>
	
The webserver uses chroot (because it was needed for the laboraiton I did it for), but can be removed in exchange for a www-user.
The server has some URL-validation, but commented in this version. Feel free to play around with it.
The solution for figuring out MIME-type of file is somewhat bad, right now it's a file that keeps the information of "file -i *" of that directory.

The server is supposed to be able to serve all kind of clients:<br>
	- Internet Explorer (Windows only)<br>
	- Mozilla Firefox (Windows & Linux)<br>
	- Google Chrome (Windows & Linux)<br>
	- Konqueror (Linux only)<br>
	- Lynx (Linux only)<br>
