import React from 'react'
import { useParams } from "react-router-dom";

const DetailView = (props) => {
  const component_props = useParams()
  const DetailComponent       = React.lazy(() => import(`../components/${props.component}`))
  return (
    <>
      <DetailComponent {...component_props} />
    </>
  )
}

export default DetailView
