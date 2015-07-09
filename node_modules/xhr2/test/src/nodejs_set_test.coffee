describe 'XMLHttpRequest', ->
  describe '.nodejsSet', ->
    beforeEach ->
      @xhr = new XMLHttpRequest
      @customXhr = new XMLHttpRequest

    describe 'with a httpAgent option', ->
      beforeEach ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.

        @customAgent = { custom: 'httpAgent' }
        @customXhr.nodejsHttpAgent = @customAgent

        @default = XMLHttpRequest::nodejsHttpAgent
        @agent = { mocking: 'httpAgent' }
        XMLHttpRequest.nodejsSet httpAgent: @agent

      it 'sets the default nodejsHttpAgent', ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.
        expect(@xhr.nodejsHttpAgent).to.equal @agent

      it 'does not interfere with custom nodejsHttpAgent settings', ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.
        expect(@customXhr.nodejsHttpAgent).to.equal @customAgent

      afterEach ->
        XMLHttpRequest.nodejsSet httpAgent: @default

    describe 'with a httpsAgent option', ->
      beforeEach ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.

        @customAgent = { custom: 'httpsAgent' }
        @customXhr.nodejsHttpsAgent = @customAgent

        @default = XMLHttpRequest::nodejsHttpsAgent
        @agent = { mocking: 'httpsAgent' }
        XMLHttpRequest.nodejsSet httpsAgent: @agent

      it 'sets the default nodejsHttpsAgent', ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.
        expect(@xhr.nodejsHttpsAgent).to.equal @agent

      it 'does not interfere with custom nodejsHttpsAgent settings', ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.
        expect(@customXhr.nodejsHttpsAgent).to.equal @customAgent

      afterEach ->
        XMLHttpRequest.nodejsSet httpsAgent: @default

  describe '#nodejsSet', ->
    beforeEach ->
      @xhr = new XMLHttpRequest
      @customXhr = new XMLHttpRequest

    describe 'with a httpAgent option', ->
      beforeEach ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.

        @customAgent = { custom: 'httpAgent' }
        @customXhr.nodejsSet httpAgent: @customAgent

      it 'sets nodejsHttpAgent on the XHR instance', ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.
        expect(@customXhr.nodejsHttpAgent).to.equal @customAgent

      it 'does not interfere with default nodejsHttpAgent settings', ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.
        expect(@xhr.nodejsHttpAgent).not.to.equal @customAgent

    describe 'with a httpsAgent option', ->
      beforeEach ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.

        @customAgent = { custom: 'httpsAgent' }
        @customXhr.nodejsSet httpsAgent: @customAgent

      it 'sets nodejsHttpsAgent on the XHR instance', ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.
        expect(@customXhr.nodejsHttpsAgent).to.equal @customAgent

      it 'does not interfere with default nodejsHttpsAgent settings', ->
        return unless XMLHttpRequest.nodejsSet  # Skip in browsers.
        expect(@xhr.nodejsHttpsAgent).not.to.equal @customAgent
