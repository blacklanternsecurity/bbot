import React from 'react'

const Dashboard       = React.lazy(() => import('./views/dashboard/Dashboard'))
const ScanCreateView  = React.lazy(() => import('./views/scan/ScanCreateView'))
const ListView        = React.lazy(() => import('./views/ListView'))
const DetailView      = React.lazy(() => import('./views/DetailView'))

const GenericViews = [
    { type: ListView,   path: "/campaigns",          name: "Campaigns",         component: "CampaignList" },
    { type: DetailView, path: "/campaigns/:cmpId",   name: "Campaign Detail",   component: "CampaignDetail" },
    { type: ListView,   path: "/modules",            name: "Modules",           component: "ModuleList" },
    { type: DetailView, path: "/modules/:plgId",     name: "Module Detail",     component: "ModuleDetail" },
    { type: ListView,   path: "/agents",             name: "Agents",            component: "AgentList" },
    { type: DetailView, path: "/agents/:agtId",      name: "Agent Detail",      component: "AgentDetail" },
    { type: ListView,   path: "/scans",              name: "Scans",             component: "ScanList" },
    { type: DetailView, path: "/scans/:scanId",      name: "Scan Detail",       component: "ScanDetail" },
]

// https://github.com/ReactTraining/react-router/tree/master/packages/react-router-config
const routes = [
    { path: '/', exact: true, name: 'Home' },
    { path: '/dashboard', name: 'Dashboard', component: Dashboard },
    { path: '/scans/new', name: 'New Scan',  component: ScanCreateView },
    { path: '/campaigns/:cmpId/create-scan', name: 'New Scan',  component: ScanCreateView },
]

GenericViews.map(view => {
    routes.push({path: view.path, name: view.name, component: view.type, props: {component: view.component}, strict: true, exact: true})
    return null
})

export default routes
