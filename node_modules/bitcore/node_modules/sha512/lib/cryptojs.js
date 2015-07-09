var WordArray = require('./word-array')

var Base = (function () {
  function F() {}

  return {
    /**
     * Creates a new object that inherits from this object.
     *
     * @param {Object} overrides Properties to copy into the new object.
     *
     * @return {Object} The new object.
     *
     * @static
     *
     * @example
     *
     *     var MyType = CryptoJS.lib.Base.extend({
     *         field: 'value',
     *
     *         method: function () {
     *         }
     *     });
     */
    extend: function (overrides) {
      // Spawn
      F.prototype = this;
      var subtype = new F();

      // Augment
      if (overrides) {
        subtype.mixIn(overrides);
      }

      // Create default initializer
      if (!subtype.hasOwnProperty('init')) {
        subtype.init = function () {
          subtype.$super.init.apply(this, arguments);
        };
      }

      // Initializer's prototype is the subtype object
      subtype.init.prototype = subtype;

      // Reference supertype
      subtype.$super = this;

      return subtype;
    },

    /**
     * Extends this object and runs the init method.
     * Arguments to create() will be passed to init().
     *
     * @return {Object} The new object.
     *
     * @static
     *
     * @example
     *
     *     var instance = MyType.create();
     */
    create: function () {
      var instance = this.extend();
      instance.init.apply(instance, arguments);

      return instance;
    },

    /**
     * Initializes a newly created object.
     * Override this method to add some logic when your objects are created.
     *
     * @example
     *
     *     var MyType = CryptoJS.lib.Base.extend({
     *         init: function () {
     *             // ...
     *         }
     *     });
     */
      init: function () {
    },


    mixIn: function (properties) {
      for (var propertyName in properties) {
        if (properties.hasOwnProperty(propertyName)) {
          this[propertyName] = properties[propertyName];
        }
      }

      // IE won't copy toString using the loop above
      if (properties.hasOwnProperty('toString')) {
        this.toString = properties.toString;
      }
    },


    clone: function () {
      return this.init.prototype.extend(this);
    }
  };
}());


/**
 * Abstract buffered block algorithm template.
 *
 * The property blockSize must be implemented in a concrete subtype.
 *
 * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
 */
var BufferedBlockAlgorithm = Base.extend({
  /**
   * Resets this block algorithm's data buffer to its initial state.
   *
   * @example
   *
   *     bufferedBlockAlgorithm.reset();
   */
    reset: function () {
      // Initial values
      this._data = new WordArray();
      this._nDataBytes = 0;
    },

    /**
     * Adds new data to this block algorithm's buffer.
     *
     * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
     *
     * @example
     *
     *     bufferedBlockAlgorithm._append('data');
     *     bufferedBlockAlgorithm._append(wordArray);
     */
    _append: function (data) {
      //console.dir(data)

      if (Buffer.isBuffer(data)) {
        data = WordArray.fromBuffer(data)
      }

      // Append
      this._data.concat(data);
      this._nDataBytes += data.sigBytes;
    },

    /**
     * Processes available data blocks.
     *
     * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
     *
     * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
     *
     * @return {WordArray} The processed data.
     *
     * @example
     *
     *     var processedData = bufferedBlockAlgorithm._process();
     *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
     */
    _process: function (doFlush) {
      // Shortcuts
      var data = this._data;
      var dataWords = data.words;
      var dataSigBytes = data.sigBytes;
      var blockSize = this.blockSize;
      var blockSizeBytes = blockSize * 4;

      // Count blocks ready
      var nBlocksReady = dataSigBytes / blockSizeBytes;
      if (doFlush) {
          // Round up to include partial blocks
          nBlocksReady = Math.ceil(nBlocksReady);
      } else {
          // Round down to include only full blocks,
          // less the number of blocks that must remain in the buffer
          nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
      }

      // Count words ready
      var nWordsReady = nBlocksReady * blockSize;

      // Count bytes ready
      var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

      // Process blocks
      if (nWordsReady) {
        for (var offset = 0; offset < nWordsReady; offset += blockSize) {
          // Perform concrete-algorithm logic
          this._doProcessBlock(dataWords, offset);
        }

        // Remove processed words
        var processedWords = dataWords.splice(0, nWordsReady);
        data.sigBytes -= nBytesReady;
      }

      // Return processed words
      return new WordArray(processedWords, nBytesReady);
    },

    /**
     * Creates a copy of this object.
     * @example
     *
     *     var clone = bufferedBlockAlgorithm.clone();
     */
    clone: function () {
      var clone = Base.clone.call(this);
      clone._data = this._data.clone();

      return clone;
    },

      _minBufferSize: 0
    });

/**
 * Abstract hasher template.
 *
 * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
 */
var Hasher = BufferedBlockAlgorithm.extend({
  /**
   * Configuration options.
   */
  cfg: Base.extend(),

  /**
   * Initializes a newly created hasher.
   * @example
   *
   *     var hasher = CryptoJS.algo.SHA256.create();
   */
  init: function (cfg) {
    // Apply config defaults
    this.cfg = this.cfg.extend(cfg);

    // Set initial values
    this.reset();
  },

  reset: function () {
    // Reset data buffer
    BufferedBlockAlgorithm.reset.call(this);

    // Perform concrete-hasher logic
    this._doReset();
  },

  update: function (messageUpdate) {
    if (typeof messageUpdate == 'string')
      messageUpdate = WordArray.fromBuffer(new Buffer(messageUpdate, 'utf8'))

    if (Buffer.isBuffer(messageUpdate))
      messageUpdate = WordArray.fromBuffer(messageUpdate)

    // Append
    this._append(messageUpdate);

    // Update the hash
    this._process();

    // Chainable
    return this;
  },

  finalize: function (messageUpdate) {
    if (typeof messageUpdate == 'string')
      messageUpdate = WordArray.fromBuffer(new Buffer(messageUpdate, 'utf8'))

    if (Buffer.isBuffer(messageUpdate))
      messageUpdate = WordArray.fromBuffer(messageUpdate)


    // Final message update
    if (messageUpdate) {
      this._append(messageUpdate);
    }

    // Perform concrete-hasher logic
    var hash = this._doFinalize();

    return hash.toBuffer()
  },

  blockSize: 512/32,

  /** TODO: DELETE
   * Creates a shortcut function to a hasher's object interface.
   * @example
   *
   *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
   */
  _createHelper: function (hasher) {
    return function (message, cfg) {
      return new hasher.init(cfg).finalize(message);
    };
  }

});

module.exports.Hasher = Hasher


