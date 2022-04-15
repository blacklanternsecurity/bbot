import React from 'react'
import ReactDOM from 'react-dom'
import { 
  CButton,
  CModal,
  CModalHeader,
  CModalBody,
  CModalFooter,
} from '@coreui/react'

class ConfirmDialogComponent extends React.Component {
  constructor(props, container) {
    super(props)
    this.state = {
      msg: props.msg,
      title: props.title,
      action: props.action,
      label: props.label,
      modal: true,
      confirmRef: React.createRef(),
    }
  }

  toggle = () => {
    this.setState({modal: !this.state.modal})
  }

  doAction = () => {
    this.state.action()
    this.toggle()
  }

  render() {
    return (
      <>
        <CModal
          show={this.state.modal}
          onClose={this.toggle}
          onOpened={() => {this.state.confirmRef.current.focus()}}
        >
          <CModalHeader closeButton><h5>{this.state.title}</h5></CModalHeader>
          <CModalBody>
          {this.state.msg}
          </CModalBody>
          <CModalFooter>
            <CButton 
              innerRef={this.state.confirmRef}
              color="primary"
              onClick={this.doAction}
            >{this.state.label}</CButton>{' '}
            <CButton
              color="secondary"
              onClick={this.toggle}
            >Cancel</CButton>
          </CModalFooter>
        </CModal>
      </>
    )
  }
}

const ConfirmDialog = (props: DialogProps) => {

  let k = `alert${Date.now()}`
  ReactDOM.render(<ConfirmDialogComponent key={k} {...props} />, 
    document.getElementById('alert-container')
  )
}

export default ConfirmDialog
