var tx = require('ethereumjs-tx');
var utils =  require('ethereumjs-util');

var blockappsapi = function() {

    this.host = "http://stablenet.blockapps.net"
}

blockappsapi.prototype.getBalance = function(address, callback) {

    // on node.js make sure we've imported
    // var XMLHttpRequest = require('xhr2').XMLHttpRequest;

    var xhr = new XMLHttpRequest();
    xhr.open("GET", this.host + "/query/account?address=" + address, true)
    //xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8')

    xhr.onreadystatechange = function() {
         if (xhr.readyState == 4 && xhr.status == 200) {
               var bal = 0
               if(xhr.responseText != "[]"){
                  bal = JSON.parse(xhr.responseText)[0]["balance"]//*1000000000000000000
               }

               console.log("balance is: " + bal)
               callback(bal)
            }
         }
         xhr.send('');
     }



blockappsapi.prototype.injectTransaction = function(signedTx) {
     var js = _serialRawTxToJson(signedTx)
     var xhr = new XMLHttpRequest()
     xhr.open("POST", this.host+"/includetransaction", true)
     xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');  

     xhr.onreadystatechange = function() {
            if (xhr.readyState == 4 && xhr.status == 200) {
               console.log("response: " + xhr.responseText)
               return(xhr.responseText);
            }
         }
         console.log(js)
         xhr.send(JSON.stringify(js));
}




blockappsapi.prototype.getNonce = function(address, callback) {
    // on node.js make sure we've imported
    // var XMLHttpRequest = require('xhr2').XMLHttpRequest;

    var xhr = new XMLHttpRequest();
    xhr.open("GET", this.host + "/query/account?address=" + address, true)
    //xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8')

    xhr.onreadystatechange = function() {
         if (xhr.readyState == 4 && xhr.status == 200) {
               var bal = 0
               if(xhr.responseText != "[]"){
                  bal = JSON.parse(xhr.responseText)[0]["nonce"]
               }

               console.log("nonce is: " + bal)
               callback(bal)
            }
         }
         xhr.send('');
     }

blockappsapi.prototype.estimateGas = function(txObject) {
    return;
}

function _serialRawTxToJson(rawTx){

            var ttx = new tx(new Buffer(rawTx, 'hex'));
              console.log("to is: " + ttx.to.toString('hex'))
             if (ttx.to.length  == 0){
              console.log("converting contract")
               js = {
                from : ttx.getSenderAddress().toString('hex'),
                        nonce : utils.bufferToInt(ttx.nonce),
                            gasPrice : utils.bufferToInt(ttx.gasPrice),
                          gasLimit : utils.bufferToInt(ttx.gasLimit),
                      //toAddress : ttx.to.toString('hex'),
                            value : utils.bufferToInt(ttx.value).toString(), 
                      codeOrData : (ttx.data).toString('hex'), 
                        r : (ttx.r).toString('hex'),
                      s : (ttx.s).toString('hex'),
                      v : (ttx.v).toString('hex'),
                        hash : ttx.hash().toString('hex')
                     };
                }
            else {
              console.log("converting tx")
              js = {
                from : ttx.getSenderAddress().toString('hex'),
                        nonce : utils.bufferToInt(ttx.nonce),
                            gasPrice : utils.bufferToInt(ttx.gasPrice),
                          gasLimit : utils.bufferToInt(ttx.gasLimit),
                            value : utils.bufferToInt(ttx.value).toString(), 
                            to : (ttx.to).toString('hex'),
                      codeOrData : (ttx.data).toString('hex'), 
                        r : (ttx.r).toString('hex'),
                      s : (ttx.s).toString('hex'),
                      v : (ttx.v).toString('hex'),
                        hash : ttx.hash().toString('hex')
                     };
                }

                return js;
         };

module.exports = blockappsapi;
