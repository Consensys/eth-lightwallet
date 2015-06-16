// dicss -- directly injected css
var DICSS = (function() {
    'use strict';

    if ( ({})<=8 ) {
        // yeah, you get it...
    }

    var stylesheet, styletag = document.createElement('style');
    styletag.setAttribute('id', 'dicss_wrapper');
    document.body.appendChild(styletag);
    stylesheet = styletag.sheet ? styletag.sheet : styletag.styleSheet;

    function addRule(selector, rule) {
        var rules = '', property, value;
        if (rule.constructor === String) {
            rules += rule;
        } else {
            for (property in rule) {
                if (rule.hasOwnProperty(property)) {
                    value = rule[property];
                    if (value instanceof Object) {
                        property = (/^:|&/.test(property) ? '' : ' ') + property.replace('&', '');
                        addRule(selector + property, value);
                        continue;
                    }
                    rules += property + ':' + value + ';';
                }
            }
        }
        if (!rules) {
            return;
        }
        if (stylesheet.insertRule) {
            stylesheet.insertRule(selector + ' { ' + rules + ' } ', stylesheet.cssRules.length);
        } else {
            // IE <9
            if (stylesheet.addRule) {
                stylesheet.addRule(selector, rules);
            }
        }
    }

    function removeRule(selector, property) {
        var i, j, selectors,
            rules = stylesheet.cssRules || stylesheet.rules || [];
        selector = selector.toLowerCase();

        for (i = 0; i < rules.length; i++) {
            selectors = rules[i].selectorText.toLowerCase().split(/[, ]+/);
            for (j = 0; j < selectors.length; j++) {
                if (selectors[j] === selector) {
                    if (selectors.length === 0) {
                        rules[i].style.removeProperty(property);
                    } else {
                        Array.prototype.splice.call(selectors, j, 1);
                        rules[i].selectorText = selectors.join(', ');
                    }
                    break;
                }
            }
        }
    }

    function extend(obj) {
        var attr;
        for (attr in obj) {
            if (obj.hasOwnProperty(attr)) {
                window.DICSS[attr] = obj[attr];
            }
        }
    }

    return {
        "putIn": function(selector, properties) {
            if (properties !== void 0) {
                addRule.apply(this, arguments);
                return
            }
            try {
                selector = JSON.parse(selector);
            } catch (err) {
                if (typeof selector === 'string') {
                    throw 'You forgot to put the DICSS in - ' + err;
                }
            }
            for (properties in selector) {
                if (selector.hasOwnProperty(properties)) {
                    addRule(properties, selector[properties]);
                }
            }
        },
        "pullOut": removeRule
    };
})();

module.exports = DICSS