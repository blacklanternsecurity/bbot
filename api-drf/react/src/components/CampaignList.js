import React from 'react'
import { 
  CButton,
  CTooltip,
  CCard, 
  CCardBody,
  CDataTable,
  CLink,
  CRow,
  CCol,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import Api from './ApiUtil'
//import MessageBox from './MessageBox'
//import ConfirmDialog from './ConfirmDialog'

class CampaignList extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      loading: true,
      campaigns: [],
    }
  }

  componentDidMount() {
    Api.get("/campaigns/")
    .then(res => { 
      this.setState({
        campaigns: res.data,
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
          <h4>Campaigns</h4>
          <CLink className="mt-2 float-right" to="/campaigns/new">
            <CTooltip content="New Campaign">
              <CButton variant="outline" size="sm" color="success">
                <CIcon name="cilPlus" />
              </CButton>
            </CTooltip>
          </CLink>
        </div>
        <CRow>
          <CCol xs="12" md="12" className="mb-4">
            <CCard>
              <CCardBody>
                <CDataTable
                  items={this.state.campaigns ? this.state.campaigns : []}
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
                        <CLink to={`/campaigns/${item.id}`}>{item.name}</CLink>      
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

export default CampaignList
