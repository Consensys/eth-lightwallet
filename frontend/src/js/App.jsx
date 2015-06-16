import React  from 'react/addons'
import Router from 'react-router-component'
import DICSS from './plugins/dicss/dicss'

var Locations = Router.Locations
var Location  = Router.Location
var NotFound  = Router.NotFound

import WalletController from './views/pages/WalletController.jsx'
import NotFoundPage from './views/pages/404Page.jsx'

export default React.createClass({
  componentDidMount() {

  },
  render() {

    DICSS.putIn("*", {"box-sizing": "border-box"})
    
    DICSS.putIn("body", {"padding": "1em 2em"})
    
    DICSS.putIn("h1, h2, h3, h4, h5", {'margin-bottom': '0'})
    
    DICSS.putIn("h2", {'margin-top': '0'})
    
    DICSS.putIn("hr", {'clear': 'both'})
    
    DICSS.putIn("textarea", {'min-height': '15em'})
    
    DICSS.putIn(".pure-g > *", {'padding': '0 1em'})
    
    DICSS.putIn(".pure-g > *:last-child", {'padding-right': '0'})
    
    DICSS.putIn(".eth-logo ", { 'float': 'left',
                                'max-height': '37px',
                                'display': 'inline-block',
                                'vertical-align': 'top'})
    
    DICSS.putIn(".eth-title", {'float': 'left',
                               'display': 'inline-block',
                               'vertical-align': 'top',
                               'margin-top': '2px'})

    DICSS.putIn(".nav-link", {'float': 'right'})
    DICSS.putIn("#documentText", {'min-height': '600px',
                                  'padding': '.5em .6em',
                                  'border': '1px solid #ccc',
                                  'box-shadow': '0 1px 3px #ddd',
                                  'border-radius': '4px',
                                  'vertical-align': 'middle',
                                  'display': 'block',
                                  'margin': '.25em 0'})
    DICSS.putIn(".pure-button", {'float': 'right'} )
    
    DICSS.putIn(".eth-logo", {'background': "url('images/ethereum-grayscale.png')",
                              'background-size': 'contain',
                              'width': '25px',
                              'height': '50px'})

    return (
      <div id="app-container" className="app-container">
        <Locations id="controllers-container" className="controllers-container">
            <Location path="/"             handler = { WalletController } />
            <Location path="/document(/*)" handler = { WalletController } />
            <NotFound                      handler = { NotFoundPage } />
        </Locations>
      </div>
    )
  }
})