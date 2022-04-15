import React from 'react'
import ReactDOM from 'react-dom'
import { 
  CAlert,
} from '@coreui/react'

class MessageBoxComponent extends React.Component {
  constructor(props, container) {
    super(props)
    this.state = {
      msg: props.msg,
      type: props.type,
    }
  }

  render() {
    return (
      <CAlert fade closeButton show={3} className='mt-5 fixed-top mx-auto w-25' color={this.state.type}>
        {this.state.msg}
      </CAlert>
    )
  }
}

const MessageBox = (type: string, msg: string) => {
  let k = `alert${Date.now()}`
  ReactDOM.render(<MessageBoxComponent key={k} type={type} msg={msg} />, document.getElementById('alert-container'))
}

export default MessageBox
