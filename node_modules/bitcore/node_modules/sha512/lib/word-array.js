module.exports = WordArray

/** An array of 32-bit words. */
function WordArray(words, sigBytes) {
  this.words = words || [];

  if (sigBytes != undefined) {
      this.sigBytes = sigBytes;
  } else {
      this.sigBytes = this.words.length * 4;
  }
}

/**
 * Concatenates a word array to this word array.
 *
 * @param {WordArray} wordArray The word array to append.
 *
 * @return {WordArray} This word array.
 *
 * @example
 *
 *     wordArray1.concat(wordArray2);
 */
WordArray.prototype.concat = function (wordArray) {
  if (Buffer.isBuffer(wordArray))
    wordArray = WordArray.fromBuffer(wordArray)

        // Shortcuts
        var thisWords = this.words;
        var thatWords = wordArray.words;
        var thisSigBytes = this.sigBytes;
        var thatSigBytes = wordArray.sigBytes;

        // Clamp excess bits
        this.clamp();

        // Concat
        if (thisSigBytes % 4) {
            // Copy one byte at a time
            for (var i = 0; i < thatSigBytes; i++) {
                var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
            }
        } else if (thatWords.length > 0xffff) {
            // Copy one word at a time
            for (var i = 0; i < thatSigBytes; i += 4) {
                thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
            }
        } else {
            // Copy all words at once
            thisWords.push.apply(thisWords, thatWords);
        }
        this.sigBytes += thatSigBytes;

        // Chainable
        return this;
}

/**
 * Removes insignificant bits.
 *
 */
WordArray.prototype.clamp = function () {
  // Shortcuts
  var words = this.words;
  var sigBytes = this.sigBytes;

  // Clamp
  words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
  words.length = Math.ceil(sigBytes / 4);
}

WordArray.prototype.clone = function() {
  var wa = new WordArray(this.words.slice(0))
  return wa
}

WordArray.prototype.toBuffer = function() {
  var buf = new Buffer(this.words.length * 4)
  for (var i = 0; i < this.words.length; ++i) {
    var w = this.words[i]
    buf.writeUInt32BE(w, i*4, true)
  }
  return buf 
}

WordArray.fromBuffer = function(buf) {
  var len = buf.length
  var dif = len % 4
  var w = []

  if (!process.browser) {
    for (var i = 0; i < len; i += 4) {
      var n = buf.readUInt32BE(i, true) 
      w.push(n)
    }
    return new WordArray(w, buf.length)
  } else { //bug in browserify / buffer
    for (var i = 0; i < len - dif; i += 4) {
      var n = buf.readUInt32BE(i)
      w.push(n)
    }
    var lw = 0x0
    var off = len - dif
    for (var j = 0; j < dif; j += 1) {
      lw |=  (buf.readUInt8(off + j) << ((3-j)*8))
    }
    if (dif > 0)
      w.push(lw)
    return new WordArray(w, buf.length)
  } 
}


