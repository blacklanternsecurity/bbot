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

class EngagementList extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      loading: true,
      engagements: [],
    }
  }

  componentDidMount() {
    Api.get("/engagements/")
    .then(res => { 
      this.setState({
        engagements: res.data,
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
          <h4>Engagements</h4>
          <CLink className="mt-2 float-right" to="/engagements/new">
            <CTooltip content="New Engagement">
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
                  items={this.state.engagements ? this.state.engagements : []}
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
                        <CLink to={`/engagements/${item.id}`}>{item.name}</CLink>      
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

export default EngagementList
