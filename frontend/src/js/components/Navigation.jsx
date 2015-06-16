import React  from 'react/addons'
import Router from 'react-router-component'
import DICSS from '../plugins/dicss/dicss.js'

var Link = Router.Link

export default React.createClass({
    componentWillMount() { 
        // DICSS.putIn('nav', {
        //               'display': 'inline-block',
        //               'vertical-align': 'top',
        //               'float': 'right',

        //               'ul': {
        //                 'margin': '0', 
        //                 'padding': '0',
        //                 'display': 'flex',

        //                 'li': {
        //                   'margin-left': '10px',
        //                   'flex': '1 0 auto',
        //                   'list-style': 'none',
        //                   'background': '#EEE',
                          
        //                   '&:first-child': {
        //                     'margin-left': '0',
        //                   },

        //                   '&:hover': {
        //                     'background': 'blue',
        //                     'a': {
        //                       'color': 'white'
        //                     }
        //                   },

        //                   'a': {        
        //                     'color': 'white',
        //                     'color': '#333',
        //                     'text-decoration': 'none',
        //                     'display': 'block',
        //                     'width': '100%',
        //                     'height': '100%',
        //                     'padding': '.75em'
        //                   }
        //                 }
        //               }
        //             })
    },
    render: () => {
        return(
            <nav>
                <ul>
                    <li><Link href="/document/sign"><i className="fa fa-pencil"></i> Document Sign</Link></li>
                    <li><Link href="/document/data"><i className="fa fa-file-o"></i> Document Status</Link></li>
                </ul>
            </nav>
        )
    }
})