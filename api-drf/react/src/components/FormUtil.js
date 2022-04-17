import React, { Component } from 'react'
import {
    CButton,
    CCard,
    CCardBody,
    CCardFooter,
    CRow,
    CCol,
    CListGroup,
    CListGroupItem,
    CTabContent,
    CTabPane,
} from '@coreui/react'

export default class PagedForm extends Component {
  constructor(props) {
    super(props);
    this.state = {
      activeTab: 0,
      showAddHost: true,
      title: 'Form',
    }
    this.handleChange = this.handleChange.bind(this)
  }

  panes = []

  nextClick = () => { }

  handleChange(e) {
      console.log("handleChange")
    this.setState({ [e.target.name]: e.target.value })
  }

  handleSubmit(e) {
    e.preventDefault()
    return false
  }

  setActiveTab(i) {
    this.setState({activeTab: i})
  }

  isLastPane() {
    return this.state.activeTab === (this.panes.length - 1)
  }

  render() {
    return (
      <>
        <div className='d-flex mb-2 justify-content-between'>
          <h4>{this.state.title}</h4>
        </div>
        <form onSubmit={(e) => this.handleSubmit(e)}>
          <CCard>
            <CCardBody>
              <CRow>
                <CCol xs='6' md='4' lg='3' xl='2'>
                  <CListGroup id='list-tab' role='tablist'>
                    {this.panes && this.panes.map((pane, i) =>
                      <CListGroupItem style={{ cursor: "default" }} key={i} onClick={() => this.setActiveTab(i)} action active={this.state.activeTab === i} >{i+1}) {pane.label}</CListGroupItem>
                    )}
                  </CListGroup>
                </CCol>
                <CCol xs='6' md='8' lg='11' xl='10'>
                  <CTabContent>
                    {this.panes && this.panes.map((pane, i) =>
                      <CTabPane key={i} active={this.state.activeTab === i} >
                        <h5 className='mb-2'>{pane.label}</h5>
                        {pane.content}
                      </CTabPane>
                    )}
                  </CTabContent>
                </CCol>
              </CRow>
            </CCardBody>
            <CCardFooter align='right'>
              <CButton className='mr-2' onClick={() => this.setActiveTab(this.state.activeTab - 1)} color="secondary" disabled={(this.state.activeTab === 0)}>
                Previous
              </CButton>
              <CButton onClick={this.nextClick} color={this.isLastPane() ? "success" : "info"}>
                {this.isLastPane() ? "Save" : "Next"}
              </CButton>
            </CCardFooter>
          </CCard>
        </form>
      </>
    )
  }
}
