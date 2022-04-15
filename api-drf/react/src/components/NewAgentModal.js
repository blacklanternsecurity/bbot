import React from 'react'
import { 
  CButton,
  CInput,
  CLabel,
  CModal,
  CModalBody,
  CModalFooter,
  CModalHeader,
  CRow,
} from '@coreui/react'
import Api from './ApiUtil'
import MessageBox from './MessageBox'

class NewAgentModal extends React.Component {
  constructor(props) {
    super(props)
    this.agent_name = React.createRef()
  }

  componentDidMount() {
    this.setState({
      loading: false,
      show: true,
      agent_name: null,
    })
  }

  handleChange(e: any) {
    this.setState({ [e.target.name]: e.target.value })
  }

  create = () => {
    Api.post(`/agents/`, { 
      "username": this.state.agent_name,
    }).then((res: any) => {
      if (res && res.status === 201) {
        this.setState({
          createError: ""
        })
        window.location.hash = `/agents/${res.data.agent_id}`
      }
    }).catch((err) => {
      console.log(err)
      MessageBox('danger', `An error occurred while creating the agent`)
    })
  }

  hideModal = () => {
    this.setState({
      show: false,
    }, () => {
      this.props.hideCallback()
    })
  }

  render() {
    if (!this.state) return null
    return (
      <div id='modal-container' className='mt-5 fixed-top'>
        <CModal 
          id='new-host-modal' 
          show={this.state.show} onOpened={() => this.agent_name.current.focus()} 
          onClose={() => this.hideModal()}
        > 
          <CModalHeader closeButton><h5>Create Agent</h5></CModalHeader>
          <CModalBody label="Role">
            <CRow>
              <CLabel htmlFor="agent_name" className="col-sm-4 pt-2">Agent Name</CLabel>
              <CInput 
                className="mb-4 col-sm-6" 
                name="agent_name" 
                onChange={(e: any) => this.handleChange(e)}
                defaultValue={this.state.agent_name}
                innerRef={this.agent_name}
              />
            </CRow>
            <CRow>
              <span className="col-sm-3" />
              <span className="text-danger">{this.state.createError}</span>
            </CRow>
          </CModalBody>
          <CModalFooter>
            <CButton data-dismiss="modal" color="primary" onClick={this.create}>Create</CButton>{' '}
            <CButton color="secondary" onClick={() => this.hideModal()}>Cancel</CButton>
          </CModalFooter>
        </CModal>
      </div>
    )
  }
}

export default NewAgentModal
