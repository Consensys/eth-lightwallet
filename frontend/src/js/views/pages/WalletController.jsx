import React from 'react/addons'
import Router from 'react-router-component'
import Reflux from 'reflux'
import DICSS from '../../plugins/dicss/dicss.js'

import WalletRefluxStore from '../../stores/WalletRefluxStore.jsx'

import WalletDemoPage from '../../views/pages/WalletDemoPage.jsx'

var Locations = Router.Locations
var Location  = Router.Location
var NotFound  = Router.NotFound

export default React.createClass({
  mixins: [Reflux.ListenerMixin],
  componentWillMount() { this.listenTo(WalletRefluxStore, this.publishedDataStatus) },
  publishedDataStatus(data) { data.event === 'updatedStoreData' ? this.forceUpdate() : null },
  render() { 
    return ( 
      <Locations id="pages-container" className="pages-container">
          <Location path="/"            handler = { WalletDemoPage } storeData={WalletRefluxStore.data}/>
          <Location path="/wallet/demo" handler = { WalletDemoPage } storeData={WalletRefluxStore.data}/>
      </Locations>
    ) 
  }
})