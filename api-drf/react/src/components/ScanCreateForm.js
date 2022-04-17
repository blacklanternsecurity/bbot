import React from 'react'
import PagedForm from './FormUtil'
import Api from './ApiUtil'
import MessageBox from './MessageBox'
import BasicInfoPane from './scan/panes/Basic'
import TargetsPane from './scan/panes/Targets'
import ModulesPane from './scan/panes/Modules'

export default class ScanCreateForm extends PagedForm {
  constructor(props) {
    super(props)
    this.state = {
      loading: true,
      scan: null,
    }
  }

  componentDidMount() {
    if (this.props && this.props.scanId) {
      Api.get(`/scans/${this.props.scanId}/`)
      .then(res => {
        this.setState({
          scan: res.data,
          loading: false,
          activeTab: 0,
          name: res.data.name,
        }, () => {
          this.insertPanes()
          this.forceUpdate()
        })
      })
    } else {
      this.setState({
        name: '',
        activeTab: 0,
        title: 'New Scan',
      }, () => {
        this.insertPanes()
        this.forceUpdate()
      })
    }
  }

  componentDidCatch(error, info) {
    console.log(error);
  }

  syncName = (childName) => {
    this.setState({ name: childName })
  }

  syncCampaign = (childCampaign) => {
    this.setState({ campaign: childCampaign })
  }

  syncAgent = (childAgent) => {
    this.setState({ agent: childAgent })
  }

  syncTargets = (childTargets) => {
    this.setState({ targets: childTargets })
  }

  syncModules = (childModules) => {
    this.setState({ modules: childModules })
  }

  nextClick = () => {
    if (this.isLastPane()) {
      console.log(this.state)
      const form = {...this.state}
      delete form["activeTab"]

      if (this.state.scan) {
        delete form["scan"]
        const url = `/scans/${this.props.scanId}/`
        Api.patch(url, form)
        .then(res => {
          console.log(res)
          if (res.status === 200) {
            window.location.hash = url
            MessageBox("success", `Successfully updated scan ${res.data.name}`)
          }
        })
      } else {
        Api.post("/scans/", form)
        .then(res => {
          console.log(res)
          if (res.status === 201) {
            if (this.props.cmpId !== null) {
              window.location.hash = `/campaigns/${this.props.cmpId}`
            } else {
              window.location.hash = '/scans'
            }
            MessageBox("success", `Successfully created scans '${form.name}'`)
          }
        })
      }
    } else {
      this.setState({ activeTab: this.state.activeTab + 1 })
    }
  }

  insertPanes() {
    const scan_panes = [
        { label: "Basic Info",      content: ( <BasicInfoPane   scan={this.state.scan} campaign={this.props.cmpId} onNameChange={this.syncName} onCampaignChange={this.syncCampaign} onAgentChange={this.syncAgent} />)},
        { label: "Targets",         content: ( <TargetsPane   scan={this.state.scan} onTargetsChange={this.syncTargets} />)},
        { label: "Modules",         content: ( <ModulesPane   scan={this.state.scan} onModulesChange={this.syncModules} />)},
    ]
    scan_panes.map((pane) => this.panes.push(pane))
  }
}
