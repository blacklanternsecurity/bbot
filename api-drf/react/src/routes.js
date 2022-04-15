import React from 'react'

const Dashboard  = React.lazy(() => import('./views/dashboard/Dashboard'))
const ListView   = React.lazy(() => import('./views/ListView'))
const DetailView = React.lazy(() => import('./views/DetailView'))

const GenericViews = [
    { type: ListView,   path: "/campaigns",          name: "Campaigns",         component: "CampaignList" },
    { type: DetailView, path: "/campaigns/:cmpId",   name: "Campaign Detail",   component: "CampaignDetail" },
    { type: ListView,   path: "/plugins",            name: "Plugins",           component: "PluginList" },
    { type: DetailView, path: "/plugins/:plgId",     name: "Plugin Detail",     component: "PluginDetail" },
    { type: ListView,   path: "/agents",             name: "Agents",            component: "AgentList" },
    { type: DetailView, path: "/agents/:agtId",      name: "Agent Detail",      component: "AgentDetail" },
]

// https://github.com/ReactTraining/react-router/tree/master/packages/react-router-config
const routes = [
    { path: '/', exact: true, name: 'Home' },
    { path: '/dashboard', name: 'Dashboard', component: Dashboard },
]

GenericViews.map(view => {
    routes.push({path: view.path, name: view.name, component: view.type, props: {component: view.component}, strict: true, exact: true})
    return null
})

export default routes
