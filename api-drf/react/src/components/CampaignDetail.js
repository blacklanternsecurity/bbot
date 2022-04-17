import React from 'react'
import { 
  CButton,
  CCard, 
  CCardBody,
  CCardHeader,
  CCol,
  CDataTable,
  CLink,
  CNav,
  CNavItem,
  CNavLink,
  CRow,
  CTabContent,
  CTabPane,
  CTabs,
  CTooltip,
} from '@coreui/react'
import Api from './ApiUtil'
import CIcon from '@coreui/icons-react'
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
    Api.get(`/campaigns/${this.props.cmpId}/?expand=agents,scans`)
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
            <CTabs activeTab="scans">
            <CCard>
              <CCardHeader className="pb-0 pr-3 pl-3">
                  <CNav variant="tabs" className="border-bottom-0">
                    <CNavItem><CNavLink data-tab="scans">Scans</CNavLink></CNavItem>
                  </CNav>
              </CCardHeader>
              <CCardBody className="pb-0">
                  <CTabContent>
                    <CTabPane data-tab="scans">
                      <CDataTable
                        items={this.state.campaign.scans ? this.state.campaign.scans : []}
                        fields={this.state.fields}
                        itemsPerPage={10}
                        hover
                        sorter
                        outlined
                        loading={this.state.loading}
                        pagination
                        scopedSlots={{
                        }}
                      /> 
                    </CTabPane>
                  </CTabContent>
                </CCardBody>
                <CLink className="mb-3 ml-3" to={`/campaigns/${this.props.cmpId}/create-scan`}>
                  <CTooltip content="New Scan">
                    <CButton variant="outline" size="sm" color="success">
                      <CIcon name="cilPlus" />
                    </CButton>
                  </CTooltip>
                </CLink>
              </CCard>
            </CTabs>
          </CCol>
        </CRow>
      </>
    )
  }
}

export default CampaignDetail
