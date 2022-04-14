import React from 'react'

const ListView = (props) => {
  const ListComponent       = React.lazy(() => import(`../components/${props.component}`))
  return (
    <>
      <ListComponent />
    </>
  )
}

export default ListView
