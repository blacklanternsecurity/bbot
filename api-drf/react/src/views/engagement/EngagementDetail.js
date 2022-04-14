import React from 'react'
import EngagementDetail from '../../components/EngagementDetail'
import { useParams } from "react-router-dom";

const EngagementDetailView = () => {
  const props = useParams()
  return (
    <>
      <EngagementDetail engagementId={props.engagementId} />
    </>
  )
}

export default EngagementDetailView
