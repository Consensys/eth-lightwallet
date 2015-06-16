require('./styles/styles.styl');

import React  from  'react/addons'
import Router from  'react-router-component'
import a11y   from  'react-a11y'

import App    from  './js/App.jsx'

a11y({throw: true})

document.addEventListener("DOMContentLoaded", (event) => {
	React.render(<App/>, document.getElementById("app"));
});