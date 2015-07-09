var sha512 = require('../')

require('terst')

var testVectors = require('./sha512-vectors.test.js')

describe('sha512', function() {
  describe('> when test vectors with Buffer', function() {
    it('should produce the correct result', function() {
      testVectors.forEach(function(v, i) {
        var out = sha512(new Buffer(v[0], 'utf8'))
        EQ (out.toString('hex'), v[1])
      })
    })
  })

  describe('> when test vectors with string', function() {
    it('should produce the correct result', function() {
      testVectors.forEach(function(v, i) {
        var out = sha512(v[0])
        EQ (out.toString('hex'), v[1])
      })
    })
  })
})
