import React from 'react'
import {
} from '@coreui/react'
import { MultiSelectContainer } from '../../MultiSelect'
import Select from 'react-select'
import Api from '../../ApiUtil'
import MessageBox from '../../MessageBox'

class ModulesPane extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      campaign: this.props.campaign,
      modules: [],
      modules_options: [],
    }
    this.modules = React.createRef();
  }

  componentDidMount() {
    Api.get("/modules/")
    .then(res => {
      if (res.status === 200) {
        const modules_res = res.data.modules.map((m, i) => {
          return {
            label: m,
            value: m,
            key: i
          }
        })
        this.setState({
          modules_options: modules_res,
        })
      } else {
        console.log(res)
        MessageBox("error", "Failed to retrieve module list")
      }
    }).catch(err => {
      console.log(err)
      MessageBox("error", "Failed to retrieve module list")
    })
  }

  handleModulesChange(e) {
    const modules = e.map(m => {return m.value})
    this.props.onModulesChange(modules)
    this.handleChange({"target": {"name": "modules", "value": e}})
  }

  handleChange(e) {
    this.setState({ [e.target.name]: e.target.value })
  }

  render() {
    return (
      <>
        <MultiSelectContainer className="pl-0 pr-0 mb-4">
          <Select
            isMulti={true}
            className="multi-select"
            classNamePrefix="multi-select"
            options={this.state.modules_options}
            formatCreateLabel={(m) => { return `Enable module: ${m}` }}
            onChange={(e) => this.handleModulesChange(e, this)}
            value={this.state.modules}
            closeMenuOnSelect={false}
          />
        </MultiSelectContainer>
      </>
    )
  }
}

export default ModulesPane
