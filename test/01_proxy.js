const assert = require('assert');
const crypto = require('crypto');
const zlib = require('zlib');
const request = require('request');
const fs = require('fs');
const http = require('http');
const net = require('net');
const nodeStatic = require('node-static');
const WebSocket = require('ws');
const Proxy = require('../');

const fileStaticA = new nodeStatic.Server(`${__dirname}/wwwA`);
const fileStaticB = new nodeStatic.Server(`${__dirname}/wwwB`);
const testHost = '127.0.0.1';
const testPortA = 40005;
const testPortB = 40006;
const testProxyPort = 40010;
const testWSPort = 40007;
const testUrlA = `http://${testHost}:${testPortA}`;
const testUrlB = `http://${testHost}:${testPortB}`;

const getHttp = (url, cb) => {
  request({ url }, (err, resp, body) => {
    cb(err, resp, body);
  });
};

const proxyHttp = (url, keepAlive, cb) => {
  request({
    url,
    proxy: `http://127.0.0.1:${testProxyPort}`,
    ca: fs.readFileSync(`${__dirname}/../.http-mitm-proxy/certs/ca.pem`),
    agentOptions: {
      keepAlive,
    },
  }, (err, resp, body) => {
    cb(err, resp, body);
  });
};

const countString = (str, substr, cb) => {
  let pos = str.indexOf(substr);
  const len = substr.length;
  let count = 0;

  if (pos > -1) {
    let offSet = len;

    while (pos !== -1) {
      count++;
      offSet = pos + len;
      pos = str.indexOf(substr, offSet);
    }
  }

  cb(count);
};

describe('proxy', () => {
  let srvA = null;
  let srvB = null;
  let proxy = null;
  const testHashes = {};
  const testFiles = [
    '1024.bin',
  ];
  let wss = null;

  before(() => {
    testFiles.forEach((val) => {
      testHashes[val] = crypto.createHash('sha256').update(fs.readFileSync(`${__dirname}/www/${val}`, 'utf8'), 'utf8').digest().toString();
    });

    srvA = http.createServer((req, res) => {
      req.addListener('end', () => {
        fileStaticA.serve(req, res);
      }).resume();
    }).listen(testPortA, testHost);

    srvB = http.createServer((req, res) => {
      req.addListener('end', () => {
        fileStaticB.serve(req, res);
      }).resume();
    }).listen(testPortB, testHost);

    wss = new WebSocket.Server({
      port: testWSPort,
    }).on('connection', (ws) => {
      // just reply with the same message
      ws.on('message', (message) => {
        ws.send(message);
      });
    });
  });

  beforeEach((done) => {
    proxy = new Proxy();
    proxy.listen({ port: testProxyPort }, done);
    proxy.onError((ctx, err, errorKind) => {
      const url = (ctx && ctx.clientToProxyRequest) ? ctx.clientToProxyRequest.url : '';
      console.log(`proxy error: ${errorKind} on ${url}:`, err);
    });
  });

  afterEach(() => {
    proxy.close();
    proxy = null;
  });

  after(() => {
    srvA.close();
    srvA = null;
    srvB.close();
    srvB = null;
    wss.close();
    wss = null;
  });

  describe('ca server', () => {
    it('should generate a root CA file', (done) => {
      fs.access(`${__dirname}/../.http-mitm-proxy/certs/ca.pem`, (err) => {
        let rtv = null;
        if (err) {
          rtv = `${__dirname}/../.http-mitm-proxy/certs/ca.pem ${err}`;
        } else {
          rtv = true;
        }
        assert.equal(true, rtv, 'Can access the CA cert');
        done();
      });
    });
  });

  describe('http server', () => {
    describe('get a 1024 byte file', () => {
      it('a', (done) => {
        getHttp(`${testUrlA}/1024.bin`, (err, resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }

          let len = 0;

          if (Object.prototype.hasOwnProperty.call(body, 'length')) len = body.length;
          assert.equal(1024, len, 'body length is 1024');
          assert.equal(testHashes['1024.bin'], crypto.createHash('sha256').update(body, 'utf8').digest().toString(), 'sha256 hash matches');
          done();
        });
      });

      it('b', (done) => {
        getHttp(`${testUrlB}/1024.bin`, (err, resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }

          let len = 0;
          if (Object.prototype.hasOwnProperty.call(body, 'length')) len = body.length;
          assert.equal(1024, len, 'body length is 1024');
          assert.equal(testHashes['1024.bin'], crypto.createHash('sha256').update(body, 'utf8').digest().toString(), 'sha256 hash matches');
          done();
        });
      });
    });
  });

  describe('proxy server', () => {
    it('should handle socket errors in connect', (done) => {
      // If a socket disconnects during the CONNECT process, the resulting
      // error should be handled and shouldn't cause the proxy server to fail.
      const socket = net.createConnection(testProxyPort, testHost, () => {
        socket.write(`CONNECT ${testHost}:${testPortA}\r\n\r\n`);
        socket.destroy();
      });

      socket.on('close', () => {
        proxyHttp(`${testUrlA}/1024.bin`, false, (err, resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }
          let len = 0;
          if (Object.prototype.hasOwnProperty.call(body, 'length')) {
            len = body.length;
          }
          assert.equal(1024, len);
          assert.equal(testHashes['1024.bin'], crypto.createHash('sha256').update(body, 'utf8').digest().toString());
          done();
        });
      });
    });

    describe('proxy a 1024 byte file', () => {
      it('a', (done) => {
        proxyHttp(`${testUrlA}/1024.bin`, false, (err, _resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }

          let len = 0;
          if (Object.prototype.hasOwnProperty.call(body, 'length')) len = body.length;
          assert.equal(1024, len);
          assert.equal(testHashes['1024.bin'], crypto.createHash('sha256').update(body, 'utf8').digest().toString());
          done();
        });
      });

      it('b', (done) => {
        proxyHttp(`${testUrlB}/1024.bin`, false, (err, resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }

          let len = 0;
          if (Object.prototype.hasOwnProperty.call(body, 'length')) len = body.length;
          assert.equal(1024, len);
          assert.equal(testHashes['1024.bin'], crypto.createHash('sha256').update(body, 'utf8').digest().toString());
          done();
        });
      });
    });

    describe('ssl', () => {
      it.skip('proxys to google.com using local ca file', (done) => {
        proxyHttp('https://www.google.com/', false, (err, resp) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }

          assert.equal(200, resp.statusCode, '200 Status code from Google.');
          done();
        });
      }).timeout(15000);
    });

    describe('proxy a 1024 byte file with keepAlive', () => {
      it('a', (done) => {
        proxyHttp(`${testUrlA}/1024.bin`, true, (err, resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }

          let len = 0;
          if (Object.prototype.hasOwnProperty.call(body, 'length')) len = body.length;
          assert.equal(1024, len);
          assert.equal(testHashes['1024.bin'], crypto.createHash('sha256').update(body, 'utf8').digest().toString());
          done();
        });
      });

      it('b', (done) => {
        proxyHttp(`${testUrlB}/1024.bin`, true, (err, resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }
          let len = 0;
          if (Object.prototype.hasOwnProperty.call(body, 'length')) len = body.length;
          assert.equal(1024, len);
          assert.equal(testHashes['1024.bin'], crypto.createHash('sha256').update(body, 'utf8').digest().toString());
          done();
        });
      });
    });

    describe('ssl with keepAlive', () => {
      it.skip('proxys to google.com using local ca file', (done) => {
        proxyHttp('https://www.google.com/', true, (err, resp) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }

          assert.equal(200, resp.statusCode, '200 Status code from Google.');
          done();
        });
      }).timeout(15000);
    });

    describe('host match', () => {
      it('proxy and modify AAA 5 times if hostA', (done) => {
        proxy.onRequest((ctx, callback) => {
          const testHostNameA = `127.0.0.1:${testPortA}`;

          if (ctx.clientToProxyRequest.headers.host === testHostNameA) {
            const chunks = [];

            ctx.onResponseData((_ctx, chunk, onResponseDataCallback) => {
              chunks.push(chunk);
              return onResponseDataCallback(null, null);
            });

            ctx.onResponseEnd((onResponseEndContext, onREsponseEndCallback) => {
              let body = (Buffer.concat(chunks)).toString();

              for (let i = 0; i < 5; i++) {
                const off = (i * 10);
                body = `${body.substr(0, off)}AAA${body.substr(off + 3)}`;
              }

              onResponseEndContext.proxyToClientResponse.write(body);
              return onREsponseEndCallback();
            });
          }

          return callback();
        });

        proxyHttp(`${testUrlA}/1024.bin`, false, (err, resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }

          let len = 0;
          if (Object.prototype.hasOwnProperty.call(body, 'length')) len = body.length;

          assert.equal(1024, len);

          countString(body, 'AAA', (count) => {
            assert.equal(5, count);
            proxyHttp(`${testUrlB}/1024.bin`, false, (errB, respB, bodyB) => {
              if (errB) console.log(`errB: ${errB.toString()}`);
              let lenB = 0;
              if (Object.prototype.hasOwnProperty.call(bodyB, 'length')) lenB = bodyB.length;
              assert.equal(1024, lenB);
              countString(bodyB, 'AAA', (countB) => {
                assert.equal(0, countB);
                done();
              });
            });
          });
        });
      });
    });

    describe('chunked transfer', () => {
      it('should not change transfer encoding when no content modification is active', (done) => {
        proxyHttp(`${testUrlA}/1024.bin`, false, (err, resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }

          let len = 0;
          if (Object.prototype.hasOwnProperty.call(body, 'length')) len = body.length;
          assert.equal(1024, len);
          assert.equal(null, resp.headers['transfer-encoding']);
          assert.equal(1024, resp.headers['content-length']);
          done();
        });
      });

      it('should use chunked transfer encoding when global onResponseData is active', (done) => {
        proxy.onResponseData((ctx, chunk, callback) => {
          callback(null, chunk);
        });

        proxyHttp(`${testUrlA}/1024.bin`, false, (err, resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }

          let len = 0;

          if (Object.prototype.hasOwnProperty.call(body, 'length')) len = body.length;

          assert.equal(1024, len);
          assert.equal('chunked', resp.headers['transfer-encoding']);
          assert.equal(null, resp.headers['content-length']);

          done();
        });
      });

      it('should use chunked transfer encoding when context onResponseData is active', (done) => {
        proxy.onResponse((ctx, callback) => {
          ctx.onResponseData((_ctx, chunk, onResponseDataCallback) => {
            onResponseDataCallback(null, chunk);
          });
          callback(null);
        });

        proxyHttp(`${testUrlA}/1024.bin`, false, (err, resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }

          let len = 0;
          if (Object.prototype.hasOwnProperty.call(body, 'length')) len = body.length;
          assert.equal(1024, len);
          assert.equal('chunked', resp.headers['transfer-encoding']);
          assert.equal(null, resp.headers['content-length']);
          done();
        });
      });

      it('should use chunked transfer encoding when context ResponseFilter is active', (done) => {
        proxy.onResponse((ctx, callback) => {
          ctx.addResponseFilter(zlib.createGzip());
          callback(null);
        });

        proxyHttp(`${testUrlA}/1024.bin`, false, (err, resp, body) => {
          if (err) {
            done(new Error(`${err.message} ${JSON.stringify(err)}`));
            return;
          }
          let len = 0;

          if (Object.prototype.hasOwnProperty.call(body, 'length')) len = body.length;

          assert.equal(true, len < 1024); // Compressed body
          assert.equal('chunked', resp.headers['transfer-encoding']);
          assert.equal(null, resp.headers['content-length']);

          done();
        });
      });
    });
  }).timeout(5000);

  describe('websocket server', () => {
    it('send + receive message without proxy', (done) => {
      const ws = new WebSocket(`ws://localhost:${testWSPort}`);
      const testMessage = 'does the websocket server reply?';

      ws.on('open', () => {
        ws.on('message', (data) => {
          assert.equal(data, testMessage);
          ws.close();
          done();
        });

        ws.send(testMessage);
      });
    });

    it('send + receive message through proxy', (done) => {
      const ws = new WebSocket(`ws://localhost:${testProxyPort}`, {
        host: `localhost:${testWSPort}`,
      });
      const testMessage = 'does websocket proxying work?';

      ws.on('open', () => {
        ws.on('message', (data) => {
          assert.equal(data, testMessage);
          ws.close();
          done();
        });

        ws.send(testMessage);
      });
    });

    it('websocket callbacks get called', (done) => {
      const stats = {
        connection: false,
        frame: false,
        send: false,
        message: false,
        close: false,
      };

      const ws = new WebSocket(`ws://localhost:${testProxyPort}`, {
        host: `localhost:${testWSPort}`,
      });

      const testMessage = 'does rewriting messages work?';
      const rewrittenMessage = 'rewriting messages does work!';

      proxy.onWebSocketConnection((ctx, callback) => {
        stats.connection = true;
        return callback();
      });

      proxy.onWebSocketFrame((ctx, type, fromServer, message, flags, callback) => {
        let msg = message;

        stats.frame = true;
        msg = rewrittenMessage;
        return callback(null, msg, flags);
      });

      proxy.onWebSocketSend((ctx, message, flags, callback) => {
        stats.send = true;
        return callback(null, message, flags);
      });

      proxy.onWebSocketMessage((ctx, message, flags, callback) => {
        stats.message = true;
        return callback(null, message, flags);
      });

      proxy.onWebSocketClose((ctx, code, message, callback) => {
        stats.close = true;
        callback(null, code, message);
      });

      ws.on('open', () => {
        ws.on('message', (data) => {
          assert.equal(data, rewrittenMessage);
          ws.close();
        });

        ws.on('close', () => {
          setTimeout(() => {
            assert(stats.connection);
            assert(stats.frame);
            assert(stats.send);
            assert(stats.message);
            if (!stats.close) {
              setTimeout(() => {
                assert(stats.close);
                done();
              }, 500);
            } else {
              done();
            }
          }, 0);
        });

        ws.send(testMessage);
      });
    });
  }).timeout(2000);
}).timeout(30000);
