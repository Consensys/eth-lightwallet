module.exports = {
  "step one" : function (browser) {
    browser
      .url("file://" + __dirname + "/../../dist/index.html")
      .waitForElementVisible('body', 1000)
      .waitForElementVisible('nav', 1000)
      .assert.elementPresent('nav')
      .click('.ns-LinkTo--widgets')
      .pause(200)
      .assert.containsText('h1', 'Widgets')
  },

  "step two" : function (browser) {
    browser
      .assert.elementPresent('.ns-LinkTo--widgets')
      .waitForElementVisible('.ns-LinkTo--widget', 1000)
      .click('.ns-LinkTo--widget')
      .pause(200)
      .assert.containsText('h1', 'Widget WD1')
      .end();
  }
};
