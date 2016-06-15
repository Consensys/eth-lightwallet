var expect = require('chai').expect;
var Random = require('../../lib/generators/random');

describe("Random", function () {
  describe("randomBytes", function() {
    it('returns randomBytes', function(done) {
      Random.randomBytes(8, function(e,val) {
        expect(val).to.not.equal(undefined);
        expect(val.length).to.equal(8);
        Random.randomBytes(8, function(e, val2) {
          expect(val2).to.not.equal(val);
          expect(val.length).to.equal(8);
          done();
        })
      })
    });
  });

  describe("setProvider", function() {
    it('sets new provider', function(done) {
      Random.setProvider(function(length,callback) {callback(null, "foo")});
      Random.randomBytes(8, function(e,val) {
        expect(val).to.equal("foo");
        Random.setProvider(Random.naclProvider);
        done();
      })
    });
  });

});
