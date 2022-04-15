import React from 'react'
import CampaignDetail from '../../components/CampaignDetail'
import { useParams } from "react-router-dom";

const CampaignDetailView = () => {
  const props = useParams()
  return (
    <>
      <CampaignDetail campaignId={props.campaignId} />
    </>
  )
}

export default CampaignDetailView
