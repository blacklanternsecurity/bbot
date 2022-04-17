import React from 'react'
import { 
  CCard, 
  CCardBody,
  CDataTable,
  CLink,
  CRow,
  CCol,
} from '@coreui/react'
import Api from './ApiUtil'
//import MessageBox from './MessageBox'
//import ConfirmDialog from './ConfirmDialog'

class PluginList extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      loading: true,
      plugins: [],
    }
  }

  componentDidMount() {
    Api.get("/plugins/")
    .then(res => { 
      this.setState({
        plugins: res.data,
        loading: false
      })
    })
    .catch(err => { 
      console.log(err) 
    })
  }

  render () {
    return (
      <>
        <div className="d-flex mb-2 justify-content-between">
          <h4>Plugins</h4>
        </div>
        <CRow>
          <CCol xs="12" md="12" className="mb-4">
            <CCard>
              <CCardBody>
                <CDataTable
                  items={this.state.plugins ? this.state.plugins : []}
                  fields={this.state.fields}
                  itemsPerPage={10}
                  hover
                  sorter
                  outlined
                  loading={this.state.loading}
                  pagination
                  scopedSlots={{
                    'name': (item: any, i: number) => (                         
                      <td>                                                      
                        <CLink to={`/plugins/${item.id}`}>{item.name}</CLink>      
                      </td>                                                     
                    ),                                                          
                  }}
                /> 
              </CCardBody>
            </CCard>
          </CCol>
        </CRow>
      </>
    )
  }
}

export default PluginList
