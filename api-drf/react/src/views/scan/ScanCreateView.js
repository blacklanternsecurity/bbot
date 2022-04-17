import React from 'react'
import { useParams } from "react-router-dom";
import ScanCreateForm from '../../components/ScanCreateForm'

const ScanCreateView = () => {

  const component_props = useParams()
  return (
    <>
      <ScanCreateForm { ...component_props } />
    </>
  )
}

export default ScanCreateView
