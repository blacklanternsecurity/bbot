import React from 'react'
import { CFooter, CLink } from '@coreui/react'

const TheFooter = () => {
  return (
    <CFooter fixed={false}>
      <div>
        &copy; {(new Date().getFullYear())}&nbsp;
        <CLink href="https://www.blacklanternsecurity.com/" target="_blank">
          Black Lantern Security
        </CLink>
      </div>
    </CFooter>
  )
}

export default React.memo(TheFooter)
