'use strict';
var http = require('http');
var fs = require('fs');
var out = process.argv[2] || '/tmp/spans.log';
http.createServer(function (req, res) {
	var chunks = [];
	req.on('data', function (c) { chunks.push(c); });
	req.on('end', function () {
		if (req.url.indexOf('/v1/traces') === 0) fs.appendFileSync(out, Buffer.concat(chunks));
		res.writeHead(200, { 'Content-Type': 'application/json' });
		res.end('{}');
	});
}).listen(4318, '127.0.0.1');
