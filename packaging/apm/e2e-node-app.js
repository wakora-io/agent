'use strict';
var http = require('http');
var port = Number(process.argv[2] || 3007);
http.createServer(function (req, res) {
	res.writeHead(200, { 'Content-Type': 'text/plain' });
	res.end('ok');
}).listen(port, '127.0.0.1');
