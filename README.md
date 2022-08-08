# TLSChecker
Check TLS version

Command

```
npm run start host=example.com
```

or Node.js

```
const TLSChecker = require('./TLSChecker');

const checker = new TLSChecker(getArgs());
checker.check()
  .then((results) => {
    console.log(results);
  })
;
```

# Options

|name|type|default|example|
|---|---|---|---|
|host|string|(none)|yourdomain.com|
|port|number|443|443|
|servername|string|(host)|yourdomain.com|
|ALPNProtocols|TypedArray<String>|['http/3', 'http/2', 'http/1.1']|['http/3', 'http/2', 'http/1.1']|

# Customize

```
const TLSChecker = require('./TLSChecker');

// check methods
TLSChecker.setMethod([
  'TLS_method',
  'TLSv1_3_client_method',
  'TLSv1_2_client_method',
  'TLSv1_1_client_method',
  'TLSv1_client_method'
]);

// good supported versions
TLSChecker.setGoodVersions([
  'TLSv1.3',
  'TLSv1.2'
]);

// bad supported versions
TLSChecker.setNgVersions([
  'TLSv1.1',
  'TLSv1'
]);
```
