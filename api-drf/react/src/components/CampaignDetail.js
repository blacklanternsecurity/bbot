import React from 'react'
import { 
  CCard, 
  CCardBody,
  CRow,
  CCol,
} from '@coreui/react'
import Api from './ApiUtil'
//import MessageBox from './MessageBox'
//import ConfirmDialog from './ConfirmDialog'

class CampaignDetail extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      loading: true,
      campaign: null,
    }
  }

  componentDidMount() {
    Api.get(`/campaigns/${this.props.cmpId}/`)
    .then(res => { 
      this.setState({
        campaign: res.data,
        loading: false
      })
    })
    .catch(err => { 
      console.log(err) 
    })
  }

  render () {
    if (!this.state || !this.state.campaign) return null
    return (
      <>
        <div className="d-flex mb-2 justify-content-between">
          <h4>{this.state.campaign.name}</h4>
        </div>
        <CRow>
          <CCol xs="12" md="12" className="mb-4">
            <CCard>
              <CCardBody>
                {this.state.campaign.id}
              </CCardBody>
            </CCard>
          </CCol>
        </CRow>
      </>
    )
  }
}

export default CampaignDetail
