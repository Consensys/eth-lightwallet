import React from 'react/addons'

export default React.createClass({

	// createInvoice: () => {
	//   console.log('createInvoice', arguments)

	//     var data = {
	//       address: this.state.address 
	//     }

	//     var json_data = this.callAPI("createInvoice", data)

	//     this.getInvoiceData()
	// },

	// getInvoice: () => {
	//   console.log('getInvoiceData', arguments)

	//     var data = {
	//       address: this.state.address 
	//     }

	//     var json_data = this.callAPI("getInvoiceData", data)

	//     this.setState({
	//       paymentAddress:   json_data["paymentAddress"],
	//       invoiceTimestamp: json_data["invoiceTimestamp"]
	//     })
	// },

	// createContract: () => {
	//   console.log('createInvoice', arguments)

	//     var data = {
	//       address: this.state.address 
	//     }

	//     var json_data = this.callAPI("createInvoice", data)

	//     this.getInvoiceData()
	// },

	// getContract: () => {
	//   console.log('getContract', arguments)

	//     var data = {
	//       address: this.state.address 
	//     }

	//     var json_data = this.callAPI("getContract", data)

	//     this.setState({
	//       paymentAddress:   json_data["paymentAddress"],
	//       invoiceTimestamp: json_data["invoiceTimestamp"]
	//     })
	// },

	getInitialState: () => {
	  return {
	  	dummy: 'ok'
	  }
	},

	callAPI: (functionName, input) => {
	  console.log('callAPI', arguments)

	  var message = JSON.stringify(input)

	  var client   = new XMLHttpRequest()
	  var base_url = "http://104.131.53.68:38080"
	  var url      = base_url + "/api/orderInvoice/" + functionName

	  client.open("PUT", url, false)
	  client.setRequestHeader("Content-Type", "application/json")
	  client.send(message)
	  
	  var json_data = JSON.parse(client.response)

	  console.log(json_data);

	  return(json_data)

	},

	createlegalDoc: () => {

	},
	
	getlegalDoc: () => {

	},

	handleSearch: () => {
		if(this.refs.existingInvoiceAddress){
			this.callAPI(this.refs.existingInvoiceAddress);
		}
		if(this.refs.existingContractAddress){
			this.callAPI(this.refs.existingContractAddress);
		}		
	},

	render: function() {

		return(
		  <section className="choice-view">
		  	<form onSubmit={this.handleSearch}>
			    <label>Look up {this.props.legalDocType}</label>
			    <input type="text" ref={"existing" + this.props.legalDocType + 'Address'} placeholder={this.props.legalDocType + "Address"}/>
			    <br/>
			    <span>---- OR ----</span>
			    <br/>
			    <button className="btn-cta" ref={"btn-create-"+this.props.legalDocType.toLowerCase()} onClick={this.createlegalDoc.bind(this,this.props.legalDocType)}>Create New {this.props.legalDocType}</button>
			</form>
		  </section>
		)
	}
})