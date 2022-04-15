import React from 'react'
import { 
  CButton,
  CButtonGroup,
  CCard, 
  CCardBody,
  CCardHeader,
  CCol,
  CDataTable,
  CNav,
  CNavItem,
  CNavLink,
  CRow,
  CTabContent,
  CTabPane,
  CTabs,
  CTooltip,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import Api from './ApiUtil'
import MessageBox from './MessageBox'
import ConfirmDialog from './ConfirmDialog'

class AgentDetail extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      loading: true,
      agent: null,
      fields: [ { key: 'id' } ],
    }
  }

  componentDidMount() {
    Api.get(`/agents/${this.props.agtId}/`)
    .then(res => { 
      this.setState({
        agent: res.data,
        loading: false
      })
    })
    .catch(err => { 
      console.log(err) 
    })
  }

  confirmDelete = () => {
    if (!(this.state && this.state.agent)) return null
    const id = this.state.agent.agent_id
      console.log(this.state.agent)
    const name = this.state.agent.username
    ConfirmDialog({
      label: "Delete", 
      action: this.deleteAgent.bind(this, id, name), 
      title: `Delete ${name}?`, 
      msg: "Are you sure you want to delete this agent?",
    })
  }

  deleteAgent = (id, name) => {
    Api.delete(`/agents/${id}/`)
    .then(res => {
      if (res.status === 204) {
        MessageBox('success', `Successfully deleted agent '${name}'`)
        window.location.hash = "/agents"
      } else {
        MessageBox('danger', `An error occurred while deleting agent '${name}'`)
        console.log(res)
      }
    })
  }

  render () {
    if (!this.state || !this.state.agent) return null
    return (
      <>
        <div className="d-flex mb-2 justify-content-between">
          <h4>{this.state.agent.username}</h4>
          <CButtonGroup>
            <CTooltip content="Delete">
              <CButton variant="outline" size="sm" color="danger" onClick={() => { this.confirmDelete() }}>
                <CIcon name="cilXCircle" />
              </CButton>
            </CTooltip>
          </CButtonGroup>
        </div>
        <CRow>
          <CCol xs="12" md="12" className="mb-4">
            <CTabs activeTab="sessions">
            <CCard>
              <CCardHeader className="pb-0 pr-3 pl-3">
                  <CNav variant="tabs" className="border-bottom-0">
                    <CNavItem><CNavLink data-tab="sessions">Sessions</CNavLink></CNavItem>
                  </CNav>
              </CCardHeader>
              <CCardBody>
                  <CTabContent>
                    <CTabPane data-tab="sessions">
                      <CDataTable
                        items={this.state.agent.sessions ? this.state.agent.sessions : []}
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
              </CCard>
            </CTabs>
          </CCol>
        </CRow>
        {this.state.deployModal}
      </>
    )
  }
}

export default AgentDetail
