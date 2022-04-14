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

class EngagementDetail extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      loading: true,
      engagement: null,
    }
  }

  componentDidMount() {
    Api.get(`/engagements/${this.props.engId}/`)
    .then(res => { 
      this.setState({
        engagement: res.data,
        loading: false
      })
    })
    .catch(err => { 
      console.log(err) 
    })
  }

  render () {
    if (!this.state || !this.state.engagement) return null
    return (
      <>
        <div className="d-flex mb-2 justify-content-between">
          <h4>{this.state.engagement.name}</h4>
        </div>
        <CRow>
          <CCol xs="12" md="12" className="mb-4">
            <CCard>
              <CCardBody>
                {this.state.engagement.id}
              </CCardBody>
            </CCard>
          </CCol>
        </CRow>
      </>
    )
  }
}

export default EngagementDetail
