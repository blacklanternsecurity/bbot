import React from 'react'
import { 
  CSelect,
} from '@coreui/react'
import Api from '../../ApiUtil'
import MessageBox from '../../MessageBox'

class BasicInfoPane extends React.Component {
  constructor(props) {
    super(props)
    const init_name = this.props.scan ? this.props.scan.name : ""
    this.state = {
      name: init_name,
      campaigns: [],
      campaign: this.props.campaign,
    }
    this.name = React.createRef();
    this.campaign = React.createRef();
    this.agent = React.createRef();
  }

  componentDidMount() {
    Api.get("/campaigns/?expand=agents")
    .then(res => {
      if (res.status === 200) {
        this.setState({
          campaigns: res.data,
        }, () => {
          if (this.props.campaign) {
            const c = this.props.campaign
            this.campaign.current.value = c
            this.props.onCampaignChange(c)
          } else {
            this.props.onCampaignChange(this.state.campaigns[0].id)
          }
          const a = this.getCurrentCampaignAgents()
          if (a.length > 0)
              this.props.onAgentChange(a[0].id)
        })
      } else {
        console.log(res)
        MessageBox("error", "Failed to retrieve campaign list")
      }
    }).catch(err => {
      console.log(err)
      MessageBox("error", "Failed to retrieve campaign list")
    })
  }

  getCurrentCampaignAgents = () => {
    if (!this.state) return []

    const c = this.state.campaigns.filter(c => c.id === this.state.campaign)
    if (c.length === 0)
      return []

    return c[0].agents
  }

  handleNameChange(e) {
    this.props.onNameChange(e.target.value)
    this.handleChange(e) 
  }

  handleCampaignChange(e) {
    this.props.onCampaignChange(e.target.value)
    this.handleChange(e)
  }

  handleAgentChange(e) {
    console.log(e.target.value)
    this.props.onAgentChange(e.target.value)
    this.handleChange(e)
  }

  handleChange(e) {
    this.setState({ [e.target.name]: e.target.value })
  }

  render() {
    return (
      <>
        <label htmlFor='name'>Scan name</label>
        <input 
          type='text' 
          autoComplete="off" 
          name='name' required autoFocus 
          defaultValue={this.state.name} 
          onChange={(e) => this.handleNameChange(e, this) } 
          className='form-control' 
          id='name' 
          placeholder='Example Scan' 
          ref={this.name} 
        />

        <label htmlFor='campaign' className="mt-4">Campaign</label>
        <CSelect 
          name="campaign" 
          key="campaign" 
          id="campaign" 
          innerRef={this.campaign}
          onChange={(e) => this.handleCampaignChange(e, this)} 
          defaultValue={this.props.campaign ? this.props.campaign : ""}
        >
          {this.state.campaigns.map((p, idx) => (
            <option key={idx} value={p.id}>{p.name}</option>
          ))}
        </CSelect>

        <label htmlFor='agent' className="mt-4">Campaign</label>
        <CSelect 
          name="agent" 
          key="agent" 
          id="agent" 
          innerRef={this.agent}
          onChange={(e) => this.handleAgentChange(e, this)} 
          defaultValue={this.state.agent ? this.state.agent : ""}
        >
          {this.getCurrentCampaignAgents().map((a, idx) => (
            <option key={idx} value={a.id}>{a.username}</option>
          ))}
        </CSelect>

      </>
    )
  }
}

export default BasicInfoPane
