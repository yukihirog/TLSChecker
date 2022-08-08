const TLSChecker = require('./TLSChecker');

function getArgs() {
  const obj = {};
  process.argv.slice(2).forEach((arg) => {
    const pair = arg.split('=');
    obj[pair[0]] = pair[1];
  });
  return obj;
}

const checker = new TLSChecker(getArgs());
checker.check()
  .then((results) => {
    console.log(results);
  })
;