var tx = require('ethereumjs-tx');
var utils =  require('ethereumjs-util');
var BigNumber = require('bignumber.js');

function _serialRawTxToJson(rawTx){

  var ttx = new tx(new Buffer(rawTx, 'hex'));
  BigNumber.config({ EXPONENTIAL_AT: 20000000 });
  var rawString = ttx.value.toString('hex');
  var bigValue = new BigNumber(0);
  if (rawString !== '') {
    bigValue = new BigNumber(rawString, 16);
  }
  if (ttx.to.length  === 0){
    console.log('converting contract');
    var js = {
      from : ttx.getSenderAddress().toString('hex'),
      nonce : utils.bufferToInt(ttx.nonce),
      gasPrice : utils.bufferToInt(ttx.gasPrice),
      gasLimit : utils.bufferToInt(ttx.gasLimit),
      //toAddress : ttx.to.toString('hex'),
      value : bigValue.toString(),
      codeOrData : (ttx.data).toString('hex'),
      r : (ttx.r).toString('hex'),
      s : (ttx.s).toString('hex'),
      v : (ttx.v).toString('hex'),
      hash : ttx.hash().toString('hex')
    };
  }
  else {
    console.log('converting tx');
    js = {
      from : ttx.getSenderAddress().toString('hex'),
      nonce : utils.bufferToInt(ttx.nonce),
      gasPrice : utils.bufferToInt(ttx.gasPrice),
      gasLimit : utils.bufferToInt(ttx.gasLimit),
      value : bigValue.toString(),
      to : (ttx.to).toString('hex'),
      codeOrData : (ttx.data).toString('hex'),
      r : (ttx.r).toString('hex'),
      s : (ttx.s).toString('hex'),
      v : (ttx.v).toString('hex'),
      hash : ttx.hash().toString('hex')
    };
  }
  return js;
}

var blockappsapi = function(host) {

  if(host === undefined) {
    host = 'http://stablenet.blockapps.net';
  }

  this.host = host;
  console.log(host);
};

blockappsapi.parseResponse = function(text, key) {
  var value = 0;
  if(text !== '[]'){
    value = JSON.parse(text)[0][key];
  }
  return value;
};

blockappsapi.prototype.getBalance = function(address, callback) {

  // on node.js make sure we've imported
  // var XMLHttpRequest = require('xhr2').XMLHttpRequest;

  var xhr = new XMLHttpRequest();
  xhr.open('GET', this.host + '/query/account?address=' + address, true);
  //xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8')

  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
      var balance = blockappsapi.parseResponse(xhr.responseText, 'balance');//*1000000000000000000
      callback(undefined, new BigNumber(balance));
    }
  };
  xhr.send('');
};


blockappsapi.prototype.injectTransaction = function(signedTx, callback) {
  var js = _serialRawTxToJson(signedTx);
  var xhr = new XMLHttpRequest();
  xhr.open('POST', this.host + '/includetransaction', true);
  xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');

  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
      var txHash = xhr.responseText.slice(xhr.responseText.lastIndexOf('=') + 1);
      callback(undefined, txHash);
    }
  };
  console.log(js);
  xhr.send(JSON.stringify(js));
};

blockappsapi.prototype.getNonce = function(address, callback) {
  // on node.js make sure we've imported
  // var XMLHttpRequest = require('xhr2').XMLHttpRequest;

  var xhr = new XMLHttpRequest();
  xhr.open('GET', this.host + '/query/account?address=' + address, true);
  //xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8')

  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
      var nonce = blockappsapi.parseResponse(xhr.responseText, 'nonce');
      callback(undefined, nonce);
    }
  };
  xhr.send('');
};

blockappsapi.prototype.estimateGas = function(txObject, callback) {
  console.log('estimateGas() not yet implemented');
  return;
};


blockappsapi.prototype.getStorage = function(address, callback){

  console.log('address is : ' + address);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', this.host + '/query/storage?address=' + address, true);

  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
      var bal = 0;
      if(xhr.responseText !== '[]'){
        var res = JSON.parse(xhr.responseText);
        bal = res[res.length - 1].value;
      }
      //console.log('storage is: ' + bal)
      callback(undefined, bal);
    }
  };
  xhr.send('');
};

module.exports = blockappsapi;
