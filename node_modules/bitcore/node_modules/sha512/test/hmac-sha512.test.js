var hmac = require('../').hmac

require('terst')

describe('hmac-sha512', function() {
  describe('> when buffer input', function() {
    it('should produce the correct result', function() {
      var inp = new Buffer("hello man")
      var key = new Buffer("super secret")
      var outp = "292f154b455f464131e8af89478e0a2af37fecf5de2e9cf998df1d9447f5856d146a1660708564bb7fd76d2fe80ab92a31af70e1d69a34f6b5b4839bdb26cbab"
      var hasher = hmac(key)
    
      EQ (hasher.finalize(inp).toString('hex'), outp)
    })
  })

  describe('> when string input', function() {
    it('should produce the correct result', function() {
      var inp = "hello man"
      var key = "super secret"
      var outp = "292f154b455f464131e8af89478e0a2af37fecf5de2e9cf998df1d9447f5856d146a1660708564bb7fd76d2fe80ab92a31af70e1d69a34f6b5b4839bdb26cbab"
      var hasher = hmac(key)
    
      EQ (hasher.finalize(inp).toString('hex'), outp)
    })
  })
})
