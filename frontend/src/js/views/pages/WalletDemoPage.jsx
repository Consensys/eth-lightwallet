import React from 'react/addons'

import WalletRefluxStore from '../../stores/WalletRefluxStore.jsx'

import Header       from '../../components/Header.jsx'

export default React.createClass({

  uiStoreDoc() {
    WalletRefluxStore.storeDocumentInIpfs(this.props.storeData.documentText)
  },
  uiRetrieveDoc() {
    WalletRefluxStore.loadDocumentFromIpfs(this.props.storeData.documentLink)
  },
  uiSubmitToBlockchain() {
    WalletRefluxStore.createAndPopulateData(this.props.storeData.documentLink, 
                                             [this.props.storeData.sigAddr1, this.props.storeData.sigAddr2], 
                                             [this.props.storeData.sigName1, this.props.storeData.sigName2])
  },
  uiHandleAddressOrNameChange(name, event) {
    switch (name) {
      case 'sigName1':
        WalletRefluxStore.setStoreData({sigName1: event.target.value})
        break;
      case 'sigAddr1':
        WalletRefluxStore.setStoreData({sigAddr1: event.target.value})
        break;
      case 'sigName2':
        WalletRefluxStore.setStoreData({sigName2: event.target.value})
        break;
      case 'sigAddr2':
        WalletRefluxStore.setStoreData({sigAddr2: event.target.value})
        break;
    }
  },
  uiHandleDocumentTextChange(event) {
    WalletRefluxStore.setStoreData({ documentText: event.target.value })
  },
  uiHandleDocumentLinkChange(event) {
    WalletRefluxStore.setStoreData({ documentLink: event.target.value })
  },

  updateDocumentLink(data) {
    WalletRefluxStore.setStoreData({ documentLink: data.data.documentLink })
  },
  updateDocumentText(data) {
    WalletRefluxStore.setStoreData({ documentText: data.data.documentText })
  },
  updateAddress(data) {
    WalletRefluxStore.setStoreData({ ethContractAddress: data.data.address })
  },
  updateUserID(data) {
    WalletRefluxStore.setStoreData({ myID: data.data.accounts[0] })
  },

  render() {
    return (
      <div className = "page-document-sign">
        <Header storeData={this.props.storeData} />
        <main>
          <form className="pure-form pure-form-stacked">
            <fieldset>
              <div className="pure-g">

                <div className="pure-u-1-1">


                </div>

              </div>
            </fieldset>
          </form>
        </main>
      </div>
    )
  }
})