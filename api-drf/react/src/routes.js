import React from 'react'

const Dashboard  = React.lazy(() => import('./views/dashboard/Dashboard'))
const ListView   = React.lazy(() => import('./views/ListView'))
const DetailView = React.lazy(() => import('./views/DetailView'))

const GenericViews = [
    { type: ListView,   path: "/engagements",        name: "Engagements",       component: "EngagementList" },
    { type: ListView,   path: "/plugins",            name: "Plugins",           component: "PluginList" },
    { type: DetailView, path: "/engagements/:engId", name: "Engagement Detail", component: "EngagementDetail" },
]

// https://github.com/ReactTraining/react-router/tree/master/packages/react-router-config
const routes = [
    { path: '/', exact: true, name: 'Home' },
    { path: '/dashboard',                 name: 'Dashboard',         component: Dashboard },
]

GenericViews.map(view => {
    routes.push({path: view.path, name: view.name, component: view.type, props: {component: view.component}, exact: true})
})

export default routes
