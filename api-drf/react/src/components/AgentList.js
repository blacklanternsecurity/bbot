import React from 'react'
import { 
  CButton,
  CButtonGroup,
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
import MessageBox from './MessageBox'
import ConfirmDialog from './ConfirmDialog'
import NewAgentModal from './NewAgentModal'

class AgentList extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      loading: true,
      agents: [],
      fields: [
        { key: 'username',  label: 'Agent Name', _style: { width: '30%' } },
        { key: 'agent_id',  label: 'Agent ID',   _style: { width: '50%' } },
        { key: 'connected', label: 'Connected?', _style: { width: '20%' } },
        { key: 'actions',   label: '', sorter: false, filter: false },
      ],
    }
  }

  createAgent = () => {
    this.setState({ 
      createModal: React.createElement(NewAgentModal, {
        hideCallback: this.hideModal,
      }),
    })
  }

  hideModal = () => {
    this.setState({
      createModal: null
    })
  }

  confirmDelete = (agtId, rowIndex) => {
    let name = this.state.agents[rowIndex].username
    console.log(agtId)
    ConfirmDialog({
      label: "Delete", 
      action: this.deleteAgent.bind(this, agtId, rowIndex), 
      title: `Delete ${name}?`, 
      msg: "Are you sure you want to delete this agent?",
    })
  }

  deleteAgent = (agtId, rowIndex) => {
    Api.delete(`/agents/${agtId}/`)
    .then(res => {
      if (res.status === 204) {
        let rows = this.state.agents
        let removed = rows.splice(rowIndex, 1)[0]
        this.setState({agents: rows})
        MessageBox('success', `Successfully deleted agent '${removed.username}'`)
      } else {
        let name = this.state.agents[rowIndex].username
        MessageBox('danger', `An error occurred while deleting agent '${name}'`)
        console.log(res)
      }
    })
  }

  componentDidMount() {
    Api.get("/agents/")
    .then(res => { 
      this.setState({
        agents: res.data,
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
          <h4>Agents</h4>
          <CTooltip content="New Agent">
            <CButton variant="outline" size="sm" color="success" onClick={() => { this.createAgent() }}>
              <CIcon name="cilPlus" />
            </CButton>
          </CTooltip>
        </div>
        <CRow>
          <CCol xs="12" md="12" className="mb-4">
            <CCard>
              <CCardBody>
                <CDataTable
                  items={this.state.agents ? this.state.agents : []}
                  fields={this.state.fields}
                  itemsPerPage={10}
                  hover
                  sorter
                  outlined
                  loading={this.state.loading}
                  pagination
                  scopedSlots={{
                    'username': (item: any, i: number) => (                         
                      <td>                                                      
                        <CLink to={`/agents/${item.agent_id}`}>{item.username}</CLink>      
                      </td>                                                     
                    ),                                                          
                    'actions': (item, i) => (
                      <td className="p-0 align-middle">
                        <CButtonGroup className="float-right mr-2">
                          <CTooltip content="Delete">
                            <CButton
                              className="align-middle"
                              variant="outline"
                              color="danger"
                              size="sm"
                              onClick={() => { this.confirmDelete(item.agent_id, i) }}
                            >
                              <CIcon name="cilXCircle" />
                            </CButton>
                          </CTooltip>
                        </CButtonGroup>
                      </td>
                    ),
                  }}
                /> 
              </CCardBody>
            </CCard>
          </CCol>
        </CRow>
        {this.state.createModal}
      </>
    )
  }
}

export default AgentList
