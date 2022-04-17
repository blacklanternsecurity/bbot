import React from 'react'
import { 
  CCard, 
  CCardBody,
  CDataTable,
  CRow,
  CCol,
} from '@coreui/react'
import Api from './ApiUtil'

class ScanList extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      loading: true,
      scans: [],
      fields: [
        { key: 'name',  label: 'Scan Name', _style: { width: '30%' } },
      ],
    }
  }

  componentDidMount() {
    Api.get("/scans/")
    .then(res => { 
      this.setState({
        scans: res.data,
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
          <h4>Scans</h4>
        </div>
        <CRow>
          <CCol xs="12" md="12" className="mb-4">
            <CCard>
              <CCardBody>
                <CDataTable
                  items={this.state.scans ? this.state.scans : []}
                  fields={this.state.fields}
                  itemsPerPage={10}
                  hover
                  sorter
                  outlined
                  loading={this.state.loading}
                  pagination
                /> 
              </CCardBody>
            </CCard>
          </CCol>
        </CRow>
      </>
    )
  }
}

export default ScanList
