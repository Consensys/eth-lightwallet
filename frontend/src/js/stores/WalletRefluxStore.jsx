import React   from 'react/addons'
import Reflux  from 'reflux'
import Request from 'axios'
import _ 	   from 'lodash'

export default Reflux.createStore({

	data: {

	},
	
	init() {
	
		// Broadcast Store is ready
	    this.trigger({
	    	store: 'WalletRefluxStore',
	    	event: 'initStore',
	    	data: 'WalletRefluxStore Initialized'
	    })
	   	
	   	// Get Default User for this demo
	   	this.getAccounts()
	},

	setStoreData(data) {
		_.assign(this.data, data)
		this.updatedStoreData('setStoreData', this.data[data])
	},

	updatedStoreData(functionName, data) {
		console.log(this.data)
		this.trigger({
			store: 'WalletRefluxStore',
			event: 'updatedStoreData',
			functionName: functionName,
			data: data
		})
	},

	callAPI(functionName, input) {

		// AVAILABLE NODES (via @chrislundkvist)
		// http://104.131.53.68:38080
		// http://104.236.65.136:38080

		// Request({
		//   method: 'post',
		//   url: 'http://104.236.65.136:38080' + '/api/documentSign/' + functionName,
		//   data: JSON.stringify(input),
		// }).then((data) => { 
		// 	this.setStoreData(data.data) 
		// }).catch((data) => {
		// 	alert.log('Could not find contract.. you may need to wait.. try again in a minute')
		// 	console.log(data);
		// })
    },

    getAccounts(documentLink) {
		this.callAPI('getAccounts', {})
    },
    getDocumentLink(contractAddress) {
		this.callAPI('getDocumentLink',  {'contractAddress' : contractAddress})
    },
    getSignatureData(contractAddress) {
		this.callAPI('getSignatureData', {'contractAddress' : contractAddress})
    },


    createAndPopulateData(documentLink, sigAddresses, sigNames) {	
		this.callAPI('createAndPopulateData', { 'documentLink' : documentLink,
								    		    'sigAddresses' : sigAddresses,
								    		    'sigNames'     : sigNames })
    },
    signDocument(contractAddress) {
		this.callAPI('signDocument', {'contractAddress' : contractAddress})
    },


    storeDocumentInIpfs(documentText) {
		this.callAPI('storeDocumentInIpfs', {'documentText' : documentText})
    },
    loadDocumentFromIpfs(documentLink) {
		this.callAPI('loadDocumentFromIpfs', {'documentLink' : documentLink})
    },
})