import Vue from 'vue'
import Router from "vue-router";
import BootstrapVue from 'bootstrap-vue';
import 'bootstrap/dist/css/bootstrap.css'
import 'bootstrap-vue/dist/bootstrap-vue.css'

import App from './App.vue'
import DevicesListComponent from './core/DevicesList/DevicesList';
import DeviceDetails from './core/DeviceDetails/DeviceDetails';

Vue.config.productionTip = false
Vue.use(Router);
Vue.use(BootstrapVue)

const routes = [
    { path: '/', name: 'DevicesList', component: DevicesListComponent },
    { path: '/device/:id/', name: 'DeviceDetails', component: DeviceDetails },
    // the below path can be used for specific application analysis endpoint
    //{ path: '/device/:device_id/application/:application_id/', name: 'ApplicationAnalysis', component: ApplicationAnalysisComponent },
    { path: '*', redirect: '/' },
]

const MainRouter = new Router({
    routes
})

new Vue({
    router: MainRouter,
    render: h => h(App),
}).$mount('#app')