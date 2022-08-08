const tls = require('node:tls');

module.exports = class TLSChecker {
  static TLS_METHOD = [
    'TLS_method',
    'TLSv1_3_client_method',
    'TLSv1_2_client_method',
    'TLSv1_1_client_method',
    'TLSv1_client_method',
    //'SSLv3_client_method'
  ];

  static GOOD_VERSIONS = [
    'TLSv1.3',
    'TLSv1.2'
  ];
  
  static NG_VERSIONS = [
    'TLSv1.1',
    'TLSv1'
  ];

  static setMethod(array) {
    this.TLS_METHOD = array.slice();
  }

  static setGoodVersions(array) {
    this.GOOD_VERSIONS = array.slice();
  }

  static setNgVersions(array) {
    this.NG_VERSIONS = array.slice();
  }


  host = null;
  port = 443;
  servername = null;
  ALPNProtocols = ['http/3', 'http/2', 'http/1.1'];

  constructor(options) {
    this.#init(options);
  }

  #init(options) {
    if (options) {
      this.host          = options.host || this.host;
      this.servername    = options.servername || options.host || this.host;
      this.port          = options.port || this.port;
      this.ALPNProtocols = options.protocols?.slice() || this.ALPNProtocols;
    }
  }

  #convertResult(result) {
    return Object.assign({ success: !!result.value }, result.value || result.reason);
  }

  #toVersion(method) {
    return method
      .replace(/(_client|_server)?_method/, '')
      .replace(/_/g, '.')
    ;
  }

  #getSupported(results) {
    const supported = new Set();
    const unsupported = new Set();

    results.forEach((result) => {
      if (result.success && result.version) {
        supported.add(result.version);
      }
      if (!result.success && result.version) {
        unsupported.add(result.version);
      }
    });

    return {
      supported: [...supported],
      unsupported: [...unsupported]
    };
  }

  #checkVersions(supported) {
    const GOOD_VERSIONS = this.constructor.GOOD_VERSIONS;
    const ok = supported.some((version) => {
      return GOOD_VERSIONS.includes(version);
    });

    const NG_VERSIONS = this.constructor.NG_VERSIONS;
    const ng = supported.some((version) => {
      return NG_VERSIONS.includes(version);
    });

    return ok && !ng;
  }

  getOptions(method) {
    const options = {
      host: this.host,
      servername: this.servername,
      port: this.port,
      ALPNProtocols: this.ALPNProtocols
    };

    if (method) {
      const contextOption = {};
      if (method === 'TLSv1_3_client_method') {
        contextOption.maxVersion = contextOption.minVersion = 'TLSv1.3';
      } else {
        contextOption.secureProtocol = method;
      }
      options.secureContext = tls.createSecureContext(contextOption)
    };

    return options;
  }

  connect(method) {
    return new Promise((resolve, reject) => {
      const result = {
        checkedMethod: method,
        time: Date.now()
      };

      try {
        result.options = this.getOptions(method);
      } catch(err) {
        result.options = this.getOptions();
        result.data = err;
        reject(result);
        return;
      }

      const socket = tls.connect(result.options);

      socket.on('error', (err) => {
        result.version = this.#toVersion(result.checkedMethod);
        result.data = err;
        socket.end();
        reject(result);
      });

      socket.on('secureConnect', (e) => {
        result.version = socket.getProtocol();
        result.data = socket.getCipher();
        socket.end();
        resolve(result);
      });
    });
  }

  check() {
    if (!this.host || !this.port) {
      throw new Error('TLSChecker.prototype.check needs host and port.');
    }

    const promises = [];
    const methods = this.constructor.TLS_METHOD;
    for (let method of methods) {
      promises.push(this.connect(method));
    }

    return Promise.allSettled(promises)
      .then((results) => {
        const _results = results.map(this.#convertResult);

        const supportedInfo = this.#getSupported(_results);
        _results.supported = supportedInfo.supported;
        _results.unsupported = supportedInfo.unsupported;
        _results.isGood = this.#checkVersions(_results.supported);

        return _results;
      })
    ;
  }
}
