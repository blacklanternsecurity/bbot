import React from 'react'
import {
} from '@coreui/react'
import { MultiSelectContainer } from '../../MultiSelect'
import Creatable from 'react-select/creatable';

class TargetsPane extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      campaign: this.props.campaign,
      targets: [],
    }
    this.targets = React.createRef();
  }

  componentDidMount() {
    console.log("Targets init")
  }

  handleTargetsChange(e) {
    const targets = e.map(t => {return t.value})
    this.props.onTargetsChange(targets)
    this.handleChange({"target": {"name": "targets", "value": targets}})
  }

  handleChange(e) {
    this.setState({ [e.target.name]: e.target.value }, () => { console.log(this.state)})
  }

  render() {
    return (
      <>
        <MultiSelectContainer className="pl-0 pr-0 mb-4">
          <Creatable
            isMulti={true}
            className="multi-select"
            classNamePrefix="multi-select"
            formatCreateLabel={(t) => { return `Add target: ${t}` }}
            onChange={(e) => this.handleTargetsChange(e, this)}
          />
        </MultiSelectContainer>
      </>
    )
  }
}

export default TargetsPane
